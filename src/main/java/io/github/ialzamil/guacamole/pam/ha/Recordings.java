package io.github.ialzamil.guacamole.pam.ha;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.Reader;
import java.net.HttpURLConnection;
import java.net.URI;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.regex.Pattern;

import org.apache.guacamole.GuacamoleException;
import org.apache.guacamole.GuacamoleResourceNotFoundException;
import org.apache.guacamole.GuacamoleSecurityException;
import org.apache.guacamole.io.ReaderGuacamoleReader;
import org.apache.guacamole.language.TranslatableMessage;
import org.apache.guacamole.net.auth.AbstractActivityLog;
import org.apache.guacamole.net.auth.ActivityLog;
import org.apache.guacamole.net.auth.ActivityRecordSet;
import org.apache.guacamole.net.auth.ConnectionRecord;
import org.apache.guacamole.net.auth.DelegatingConnectionRecord;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Session recordings of every server, as Guacamole's history recording
 * storage extension shows those of its own: each server lists those in its
 * "recording-search-path" in pam_ha_recording, with its URL
 * ("pam-ha-url"), and serves them to the other servers, which add them to
 * the connection history they show where they have no copy of their own.
 * Servers fetch them from each other with the secret they share
 * ("pam-ha-secret"). A recording is shown while a server having it runs:
 * a shared recording storage avoids that.
 */
final class Recordings {

    private static final Logger logger = LoggerFactory.getLogger(Recordings.class);

    /**
     * The header servers give their shared secret in.
     */
    static final String SECRET_HEADER = "HA-Sync-Secret";

    /**
     * How often this server lists its recordings.
     */
    private static final int SCAN_SECONDS = 30;

    private static final String TIMING_SUFFIX = ".timing";

    private static final Pattern UUID_NAME = Pattern.compile(
            "[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}");

    /**
     * A recording as listed: its file, relative to the recording search
     * path ("UUID", or "UUID/name"), its type and size.
     */
    private static final class Entry {

        final String historyUuid;
        final String fileName;
        final ActivityLog.Type type;
        final long size;

        Entry(String historyUuid, String fileName, ActivityLog.Type type, long size) {
            this.historyUuid = historyUuid;
            this.fileName = fileName;
            this.type = type;
            this.size = size;
        }

    }

    private final SessionStore store;

    private final Config config;

    /**
     * This server's recordings as listed, by recording_id.
     */
    private final Map<String, Entry> listed = new ConcurrentHashMap<>();

    private boolean loaded;

    Recordings(SessionStore store, Config config) {
        this.store = store;
        this.config = config;
    }

    void start(ScheduledExecutorService executor) {
        executor.scheduleWithFixedDelay(this::scan, 5, SCAN_SECONDS, TimeUnit.SECONDS);
        logger.info("Recordings are shared with the other servers, from {} (this server: {}).",
                config.recordingSearchPath, config.url);
    }

    private String recordingId(String historyUuid, String fileName) {
        return Sql.sha256(config.url + "\n" + historyUuid + "\n" + fileName);
    }

    /**
     * Lists this server's recordings: those added or changed since last
     * time, and removes those gone.
     */
    private synchronized void scan() {

        if (!store.isStarted())
            return;

        Map<String, Entry> found = new HashMap<>();
        File[] files = config.recordingSearchPath.listFiles();
        if (files != null) {
            for (File file : files) {
                if (!UUID_NAME.matcher(file.getName()).matches())
                    continue;
                if (file.isDirectory()) {
                    File[] children = file.listFiles();
                    if (children != null)
                        for (File child : children)
                            add(found, file.getName(), file.getName() + "/" + child.getName(), child);
                }
                else
                    add(found, file.getName(), file.getName(), file);
            }
        }

        try (Connection connection = store.getDatabase().connect()) {

            if (!loaded) {
                try (PreparedStatement statement = connection.prepareStatement("SELECT recording_id, history_uuid,"
                        + " file_name, log_type, file_size FROM pam_ha_recording WHERE url = ?")) {
                    statement.setString(1, config.url);
                    try (ResultSet results = statement.executeQuery()) {
                        while (results.next())
                            listed.put(results.getString(1), new Entry(results.getString(2), results.getString(3),
                                    type(results.getString(4)), results.getLong(5)));
                    }
                }
                loaded = true;
            }

            for (Map.Entry<String, Entry> entry : found.entrySet()) {
                Entry known = listed.get(entry.getKey());
                Entry file = entry.getValue();
                if (known != null && known.size == file.size && known.type == file.type)
                    continue;
                Sql.update(connection, "DELETE FROM pam_ha_recording WHERE recording_id = ?", entry.getKey());
                Sql.update(connection, "INSERT INTO pam_ha_recording (recording_id, history_uuid, file_name,"
                        + " url, log_type, file_size) VALUES (?, ?, ?, ?, ?, ?)", entry.getKey(), file.historyUuid,
                        file.fileName, config.url, file.type.name(), file.size);
                listed.put(entry.getKey(), file);
            }

            for (String id : new ArrayList<>(listed.keySet())) {
                if (!found.containsKey(id)) {
                    Sql.update(connection, "DELETE FROM pam_ha_recording WHERE recording_id = ?", id);
                    listed.remove(id);
                }
            }

        }
        catch (SQLException e) {
            logger.warn("Unable to list this server's recordings for the other servers: {}", e.getMessage());
        }

    }

    /**
     * Adds a recording found. Its type is read again only if its size
     * changed, rather than opening every recording at every scan.
     */
    private void add(Map<String, Entry> found, String historyUuid, String fileName, File file) {
        if (!file.isFile() || !file.canRead())
            return;
        String id = recordingId(historyUuid, fileName);
        long size = file.length();
        Entry known = listed.get(id);
        found.put(id, new Entry(historyUuid, fileName, known != null && known.size == size ? known.type
                : type(file), size));
    }

    private static ActivityLog.Type type(String name) {
        try {
            return ActivityLog.Type.valueOf(name);
        }
        catch (IllegalArgumentException e) {
            return ActivityLog.Type.SERVER_LOG;
        }
    }

    /**
     * The type of a recording, as the history recording storage extension
     * finds it.
     */
    private static ActivityLog.Type type(File file) {
        try (Reader reader = new InputStreamReader(new FileInputStream(file), StandardCharsets.UTF_8)) {
            if (new ReaderGuacamoleReader(reader).readInstruction() != null)
                return ActivityLog.Type.GUACAMOLE_SESSION_RECORDING;
        }
        catch (GuacamoleException | IOException e) {
            // Not a session recording
        }
        if (new File(file.getAbsolutePath() + TIMING_SUFFIX).exists())
            return ActivityLog.Type.TYPESCRIPT;
        if (file.getName().endsWith(TIMING_SUFFIX))
            return ActivityLog.Type.TYPESCRIPT_TIMING;
        return ActivityLog.Type.SERVER_LOG;
    }

    /**
     * The recording file of this server at the given path relative to the
     * recording search path ("UUID" or "UUID/name"), as asked by another
     * server with the shared secret.
     *
     * @throws GuacamoleException
     *     If the secret is wrong, or there is no such recording.
     */
    File file(String secret, String path) throws GuacamoleException {

        if (!config.isSecret(secret))
            throw new GuacamoleSecurityException("Permission denied.");

        String[] parts = path.split("/", -1);
        boolean valid = (parts.length == 1 || parts.length == 2) && UUID_NAME.matcher(parts[0]).matches()
                && (parts.length == 1 || !(parts[1].isEmpty() || parts[1].equals(".") || parts[1].equals("..")
                        || parts[1].contains("\\")));
        if (!valid)
            throw new GuacamoleResourceNotFoundException("No such recording.");

        try {
            File root = config.recordingSearchPath.getCanonicalFile();
            File file = new File(root, path).getCanonicalFile();
            if (!file.toPath().startsWith(root.toPath()) || !file.isFile() || !file.canRead())
                throw new GuacamoleResourceNotFoundException("No such recording.");
            return file;
        }
        catch (IOException e) {
            throw new GuacamoleResourceNotFoundException("No such recording.", e);
        }

    }

    /**
     * Connection history with the recordings of other servers added to the
     * records with none here.
     */
    ActivityRecordSet<ConnectionRecord> decorate(ActivityRecordSet<ConnectionRecord> history) {
        return new RecordSet(history);
    }

    /**
     * The recordings of other servers running now, of the given records,
     * by history UUID and then file name, with the URLs of the servers
     * having each.
     */
    private Map<String, Map<String, Remote>> remote(Collection<String> historyUuids) {

        Map<String, Map<String, Remote>> remote = new HashMap<>();
        if (historyUuids.isEmpty() || !store.isStarted())
            return remote;

        try (Connection connection = store.getDatabase().connect()) {
            for (List<String> chunk : Sql.chunks(historyUuids)) {
                List<Object> parameters = new ArrayList<Object>(chunk);
                parameters.add(config.url);
                try (PreparedStatement statement = connection.prepareStatement("SELECT r.history_uuid, r.file_name,"
                        + " r.url, r.log_type, r.file_size FROM pam_ha_recording r WHERE r.history_uuid IN ("
                        + Sql.marks(chunk.size()) + ") AND r.url <> ? AND r.url IN (SELECT url FROM"
                        + " pam_ha_server WHERE last_seen > "
                        + store.getDatabase().getType().secondsAgo(SessionStore.STALE_SECONDS) + ")")) {
                    Sql.bind(statement, parameters.toArray());
                    try (ResultSet results = statement.executeQuery()) {
                        while (results.next()) {
                            Remote recording = remote.computeIfAbsent(results.getString(1),
                                    uuid -> new LinkedHashMap<>()).computeIfAbsent(results.getString(2),
                                    name -> new Remote(name));
                            recording.urls.add(results.getString(3));
                            recording.type = type(results.getString(4));
                            recording.size = results.getLong(5);
                        }
                    }
                }
            }
        }
        catch (SQLException e) {
            logger.warn("Unable to find recordings of other servers: {}", e.getMessage());
        }
        return remote;

    }

    /**
     * Whether a record needs recordings of other servers: it shows none,
     * and this server has none of its own.
     */
    private boolean needsRemote(ConnectionRecord record) {
        UUID uuid = record.getUUID();
        return uuid != null && record.getLogs().isEmpty()
                && !new File(config.recordingSearchPath, uuid.toString()).exists();
    }

    /**
     * A recording of other servers.
     */
    private final class Remote {

        final String fileName;
        final List<String> urls = new ArrayList<>();
        ActivityLog.Type type;
        long size;

        Remote(String fileName) {
            this.fileName = fileName;
        }

        ActivityLog log() {
            return new AbstractActivityLog(type, new TranslatableMessage("RECORDING_STORAGE.INFO_" + type.name())) {

                @Override
                public long getSize() {
                    return size;
                }

                @Override
                public InputStream getContent() throws GuacamoleException {
                    return fetch(Remote.this);
                }

            };
        }

    }

    /**
     * The content of a recording, from the first server having it that
     * answers.
     */
    private InputStream fetch(Remote recording) throws GuacamoleException {

        String path = recording.fileName.replace("/", "\u0000");
        try {
            path = URLEncoder.encode(path, "UTF-8").replace("+", "%20").replace("%00", "/");
        }
        catch (IOException e) {
            throw new GuacamoleResourceNotFoundException("No such recording.", e);
        }

        for (String url : recording.urls) {
            try {
                HttpURLConnection connection = (HttpURLConnection) URI.create(PeerResource.url(url,
                        "recordings/" + path)).toURL().openConnection();
                connection.setConnectTimeout(5000);
                connection.setReadTimeout(30000);
                // A redirect would give the secret to wherever it leads
                connection.setInstanceFollowRedirects(false);
                connection.setRequestProperty(SECRET_HEADER, config.secret);
                if (connection.getResponseCode() == HttpURLConnection.HTTP_OK)
                    return connection.getInputStream();
                logger.warn("Server {} does not give recording {}: HTTP {}.", url, recording.fileName,
                        connection.getResponseCode());
                connection.disconnect();
            }
            catch (IOException e) {
                logger.warn("Unable to fetch recording {} from server {}: {}", recording.fileName, url,
                        e.getMessage());
            }
        }
        throw new GuacamoleResourceNotFoundException("The recording is not available from any server.");

    }

    /**
     * A record, with recordings of other servers.
     */
    private final class Record extends DelegatingConnectionRecord {

        private final Map<String, Remote> remote;

        Record(ConnectionRecord record, Map<String, Remote> remote) {
            super(record);
            this.remote = remote;
        }

        @Override
        public Map<String, ActivityLog> getLogs() {
            Map<String, ActivityLog> logs = new HashMap<>(super.getLogs());
            for (Remote recording : remote.values()) {
                String key = UUID.nameUUIDFromBytes(("pam-ha:" + recording.fileName)
                        .getBytes(StandardCharsets.UTF_8)).toString();
                logs.put(key, recording.log());
            }
            return logs;
        }

    }

    private ConnectionRecord withRemote(ConnectionRecord record, Map<String, Map<String, Remote>> remote) {
        UUID uuid = record.getUUID();
        Map<String, Remote> recordings = uuid == null ? null : remote.get(uuid.toString());
        return recordings == null || recordings.isEmpty() ? record : new Record(record, recordings);
    }

    /**
     * Connection history, whose records show recordings of other servers.
     */
    private final class RecordSet implements ActivityRecordSet<ConnectionRecord> {

        private final ActivityRecordSet<ConnectionRecord> records;

        RecordSet(ActivityRecordSet<ConnectionRecord> records) {
            this.records = records;
        }

        @Override
        public Collection<ConnectionRecord> asCollection() throws GuacamoleException {
            Collection<ConnectionRecord> all = records.asCollection();
            List<String> needing = new ArrayList<>();
            for (ConnectionRecord record : all) {
                if (needsRemote(record))
                    needing.add(record.getUUID().toString());
            }
            Map<String, Map<String, Remote>> remote = remote(needing);
            List<ConnectionRecord> decorated = new ArrayList<>(all.size());
            for (ConnectionRecord record : all)
                decorated.add(withRemote(record, remote));
            return decorated;
        }

        @Override
        public ConnectionRecord get(String identifier) throws GuacamoleException {
            ConnectionRecord record = records.get(identifier);
            if (record == null || !needsRemote(record))
                return record;
            List<String> uuid = new ArrayList<>();
            uuid.add(record.getUUID().toString());
            return withRemote(record, remote(uuid));
        }

        @Override
        public ActivityRecordSet<ConnectionRecord> contains(String value) throws GuacamoleException {
            return new RecordSet(records.contains(value));
        }

        @Override
        public ActivityRecordSet<ConnectionRecord> limit(int limit) throws GuacamoleException {
            return new RecordSet(records.limit(limit));
        }

        @Override
        public ActivityRecordSet<ConnectionRecord> sort(SortableProperty property, boolean desc)
                throws GuacamoleException {
            return new RecordSet(records.sort(property, desc));
        }

    }

}
