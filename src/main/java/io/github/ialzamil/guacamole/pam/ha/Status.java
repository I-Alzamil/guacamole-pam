package io.github.ialzamil.guacamole.pam.ha;

import java.io.IOException;
import java.io.InputStream;
import java.net.HttpURLConnection;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.Date;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;

/**
 * What the status page shows administrators: the servers sharing a
 * database, as each last told it is running, with their sessions and
 * recordings, and what this server shares with them. On demand, whether
 * the URL of each server ("pam-ha-url") reaches that server, as other
 * servers fetch recordings from it.
 */
final class Status {

    /**
     * How long to wait for a server whose URL is checked.
     */
    private static final int PING_TIMEOUT_MS = 3000;

    /**
     * The most servers whose URL is checked at once.
     */
    private static final int MAX_PINGS = 8;

    /**
     * What checking the URL of a server found.
     */
    enum Reach {

        /** The URL reaches that server. */
        OK,

        /** The URL reaches another server, such as through a load balancer. */
        OTHER_SERVER,

        /** The server refused the secret this server gave: they differ. */
        WRONG_SECRET,

        /** Nothing answered at the URL, or not as this extension does. */
        UNREACHABLE,

        /** The server sets no URL. */
        NO_URL,

        /** This server sets no secret to give. */
        NO_SECRET

    }

    private final Cluster cluster;

    Status(Cluster cluster) {
        this.cluster = cluster;
    }

    /**
     * The status of the servers sharing the database of the given store.
     *
     * @param check
     *     Whether to check the URL of each server running, which waits for
     *     each up to {@link #PING_TIMEOUT_MS} milliseconds.
     */
    Map<String, Object> read(SessionStore store, boolean check) {

        Config config = cluster.getConfig();
        Map<String, Object> status = new LinkedHashMap<>();
        status.put("server", store.getServerId());
        status.put("dataSource", store.getDatabase().getType().getIdentifier());
        status.put("heartbeatSeconds", SessionStore.HEARTBEAT_SECONDS);
        status.put("staleSeconds", SessionStore.STALE_SECONDS);

        Map<String, Object> shared = new LinkedHashMap<>();
        shared.put("sessions", store.isStarted());
        shared.put("logins", cluster.getLogins() != null && cluster.getLogins().isShared());
        shared.put("bans", cluster.getBans() != null);
        shared.put("totp", cluster.getCodes() != null);
        shared.put("recordings", cluster.getRecordings() != null);
        shared.put("shareLinks", cluster.allowsAnonymousShares());
        status.put("shared", shared);

        Map<String, Object> settings = new LinkedHashMap<>();
        settings.put("url", config.url);
        settings.put("secret", config.secret != null);
        settings.put("guacdHostname", config.guacdHostname);
        settings.put("recordingStorage", config.recordings);
        settings.put("ban", config.ban);
        settings.put("totp", config.totp);
        status.put("settings", settings);

        List<Map<String, Object>> servers = new ArrayList<>();
        status.put("servers", servers);
        if (!store.isStarted()) {
            status.put("error", "The tables of this extension could not be set up: see the log of this server.");
            return status;
        }

        try {
            servers.addAll(servers(store));
        }
        catch (SQLException e) {
            status.put("error", "Unable to read the servers from the database: " + e.getMessage());
            return status;
        }

        if (check)
            checkReach(servers, config);
        return status;

    }

    /**
     * Sets whether each server running is reached at its URL, asking them
     * all at once rather than waiting for each in turn.
     */
    private static void checkReach(List<Map<String, Object>> servers, Config config) {

        List<Map<String, Object>> alive = new ArrayList<>();
        for (Map<String, Object> server : servers) {
            if (Boolean.TRUE.equals(server.get("alive")))
                alive.add(server);
        }
        if (alive.isEmpty())
            return;

        ExecutorService pings = Executors.newFixedThreadPool(Math.min(alive.size(), MAX_PINGS), runnable -> {
            Thread thread = new Thread(runnable, "pam-ha-ping");
            thread.setDaemon(true);
            return thread;
        });
        try {
            List<Future<Reach>> answers = new ArrayList<>();
            for (Map<String, Object> server : alive)
                answers.add(pings.submit(() -> reach((String) server.get("id"), (String) server.get("url"),
                        config)));
            for (int i = 0; i < alive.size(); i++) {
                Reach reach;
                try {
                    reach = answers.get(i).get();
                }
                catch (ExecutionException e) {
                    reach = Reach.UNREACHABLE;
                }
                catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    return;
                }
                alive.get(i).put("reach", reach);
            }
        }
        finally {
            pings.shutdownNow();
        }

    }

    /**
     * Every server in the database, those running first, with the number
     * of their sessions and recordings. Times are given by this server's
     * clock, from how long ago they were by the database's.
     */
    private List<Map<String, Object>> servers(SessionStore store) throws SQLException {

        Database database = store.getDatabase();
        DatabaseType type = database.getType();
        List<Map<String, Object>> servers = new ArrayList<>();

        try (Connection connection = database.connect()) {

            Map<String, Integer> sessions = counts(connection, "SELECT server_id, COUNT(*) FROM"
                    + " pam_ha_session GROUP BY server_id");
            Map<String, Integer> recordings = counts(connection, "SELECT url, COUNT(*) FROM"
                    + " pam_ha_recording GROUP BY url");

            try (PreparedStatement statement = connection.prepareStatement("SELECT server_id, url, hostname,"
                    + " version, started, last_seen, " + type.now() + " FROM pam_ha_server");
                 ResultSet results = statement.executeQuery()) {
                long here = System.currentTimeMillis();
                while (results.next()) {
                    Date now = type.timestamp(results, 7);
                    Date started = type.timestamp(results, 5);
                    Date lastSeen = type.timestamp(results, 6);
                    long seenMs = Math.max(0, now.getTime() - lastSeen.getTime());

                    Map<String, Object> server = new LinkedHashMap<>();
                    String id = results.getString(1);
                    String url = results.getString(2);
                    server.put("id", id);
                    server.put("self", id.equals(store.getServerId()));
                    server.put("url", url);
                    server.put("hostname", results.getString(3));
                    server.put("version", results.getString(4));
                    server.put("started", started == null ? null : here - (now.getTime() - started.getTime()));
                    server.put("lastSeenSeconds", seenMs / 1000);
                    server.put("alive", seenMs < SessionStore.STALE_SECONDS * 1000L);
                    server.put("sessions", sessions.getOrDefault(id, 0));
                    server.put("recordings", url == null ? 0 : recordings.getOrDefault(url, 0));
                    servers.add(server);
                }
            }

        }

        servers.sort((a, b) -> {
            int alive = Boolean.compare((Boolean) b.get("alive"), (Boolean) a.get("alive"));
            if (alive != 0)
                return alive;
            String nameA = a.get("hostname") != null ? (String) a.get("hostname") : (String) a.get("id");
            String nameB = b.get("hostname") != null ? (String) b.get("hostname") : (String) b.get("id");
            return nameA.compareTo(nameB);
        });
        return servers;

    }

    private static Map<String, Integer> counts(Connection connection, String sql) throws SQLException {
        Map<String, Integer> counts = new HashMap<>();
        try (PreparedStatement statement = connection.prepareStatement(sql);
             ResultSet results = statement.executeQuery()) {
            while (results.next()) {
                if (results.getString(1) != null)
                    counts.put(results.getString(1), results.getInt(2));
            }
        }
        return counts;
    }

    /**
     * Whether the given URL reaches the server of the given identifier,
     * asking it who it is with the secret.
     */
    static Reach reach(String serverId, String url, Config config) {

        if (url == null)
            return Reach.NO_URL;
        if (config.secret == null)
            return Reach.NO_SECRET;

        HttpURLConnection connection = null;
        try {
            connection = (HttpURLConnection) URI.create(PeerResource.url(url, "ping")).toURL().openConnection();
            connection.setConnectTimeout(PING_TIMEOUT_MS);
            connection.setReadTimeout(PING_TIMEOUT_MS);
            // A redirect would give the secret to wherever it leads
            connection.setInstanceFollowRedirects(false);
            connection.setRequestProperty(Recordings.SECRET_HEADER, config.secret);
            int code = connection.getResponseCode();
            if (code == HttpURLConnection.HTTP_FORBIDDEN)
                return Reach.WRONG_SECRET;
            if (code != HttpURLConnection.HTTP_OK)
                return Reach.UNREACHABLE;
            try (InputStream input = connection.getInputStream()) {
                byte[] answer = input.readNBytes(64);
                return new String(answer, StandardCharsets.UTF_8).trim().equals(serverId) ? Reach.OK
                        : Reach.OTHER_SERVER;
            }
        }
        catch (IOException | IllegalArgumentException e) {
            return Reach.UNREACHABLE;
        }
        finally {
            if (connection != null)
                connection.disconnect();
        }

    }

}
