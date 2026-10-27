package io.github.ialzamil.guacamole.pam.ha;

import java.security.SecureRandom;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Timestamp;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

import org.apache.guacamole.GuacamoleException;
import org.apache.guacamole.GuacamoleServerException;
import org.apache.guacamole.net.GuacamoleTunnel;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * The sessions open on every Guacamole server sharing a database, kept in
 * that database: each server records the sessions it opens, and tells it is
 * still running every {@link #HEARTBEAT_SECONDS} seconds. The sessions of a
 * server not heard from for {@link #STALE_SECONDS} seconds, which stopped or
 * lost the database, are not counted, and are removed by the others.
 *
 * Before a session opens, its limits are checked against the sessions of
 * every server while holding the single row of pam_ha_lock, and the
 * session is recorded before the row is released: servers check one at a
 * time, so two can never both let the last user in.
 *
 * Once open, a session is recorded with where it runs, so the other servers
 * list it, can join it, and can ask this one to end it: each server looks
 * for sessions to end every {@link #END_POLL_MS} milliseconds. Share links
 * of sessions are kept here too, so any server opens them.
 *
 * This server's own sessions are also kept here, so the database is set
 * right at each heartbeat: a session whose removal failed is removed then,
 * and sessions removed by other servers while this one was not heard from
 * (a long pause) are recorded again.
 */
final class SessionStore {

    /**
     * Longest wait for the lock of session limits.
     */
    private static final int LOCK_TIMEOUT_SECONDS = 10;

    private static final Logger logger = LoggerFactory.getLogger(SessionStore.class);

    /**
     * How often this server tells it is running, and sets the database
     * right about its sessions.
     */
    static final int HEARTBEAT_SECONDS = 10;

    /**
     * How long a server may go unheard before its sessions stop counting.
     */
    static final int STALE_SECONDS = 45;

    /**
     * How often this server looks for sessions other servers asked it to
     * end.
     */
    static final long END_POLL_MS = 2000;

    /**
     * How long counts shown, such as "in use by N users", and the sessions
     * of other servers listed, may be reused: listing connections asks for
     * each of them.
     */
    private static final long COUNTS_MAX_AGE_MS = 2000;

    /**
     * How long to wait before trying again to set up the tables, when that
     * failed.
     */
    private static final long RETRY_MS = 60000;

    private static final String COLUMNS = "s.session_id, s.server_id, s.tunnel_id, s.connection_id,"
            + " s.connection_group_id, s.sharing_profile_id, s.joined, s.username, s.remote_host, s.started,"
            + " s.guacd_hostname, s.guacd_port, s.guacd_ssl, s.guacd_connection_id";

    private static final SecureRandom random = new SecureRandom();

    /**
     * What a session of this server records once open.
     */
    static final class Details {

        final String tunnelId;
        final String connectionId;
        final String remoteHost;
        final SessionRow.Guacd guacd;

        Details(String tunnelId, String connectionId, String remoteHost, SessionRow.Guacd guacd) {
            this.tunnelId = tunnelId;
            this.connectionId = connectionId;
            this.remoteHost = remoteHost;
            this.guacd = guacd;
        }

    }

    /**
     * A session of this server.
     */
    private static final class Session {

        private final Target target;
        private final String username;
        private final boolean joined;
        private final String sharingProfileId;

        /**
         * Whether Guacamole lists it among its own active connections, or
         * only this extension does: sessions it opened joining those of
         * other servers.
         */
        private final boolean listed;

        /**
         * The session it joins, if it joins one, ended once that one ends.
         */
        private final String joinedSessionId;

        private final Date started = new Date();

        private volatile Details details;

        private volatile GuacamoleTunnel tunnel;

        /**
         * Whether it was asked to end, maybe before its tunnel was
         * attached.
         */
        private volatile boolean ending;

        /**
         * Whether it is in the database, so the heartbeat may record it
         * again if it went missing.
         */
        private volatile boolean recorded;

        Session(Target target, String username, boolean joined, String sharingProfileId, boolean listed,
                String joinedSessionId) {
            this.target = target;
            this.username = username;
            this.joined = joined;
            this.sharingProfileId = sharingProfileId;
            this.listed = listed;
            this.joinedSessionId = joinedSessionId;
        }

    }

    /**
     * A share link, and the session it joins.
     */
    static final class Share {

        final String keyHash;
        final String sharingProfileId;
        final SessionRow session;

        Share(String keyHash, String sharingProfileId, SessionRow session) {
            this.keyHash = keyHash;
            this.sharingProfileId = sharingProfileId;
            this.session = session;
        }

    }

    private final Database database;

    private final Limits.Defaults defaults;

    private final String serverId;

    private final String url;

    /**
     * This server's host name, and the version of this extension it runs,
     * shown on the status page of every server.
     */
    private final String hostname;

    private final String version;

    private final Map<String, Session> sessions = new ConcurrentHashMap<>();

    /**
     * Held while this server's sessions are recorded, removed or set right,
     * so the heartbeat never sees one half done.
     */
    private final Object recording = new Object();

    /**
     * Held while the counts, or the sessions of other servers, are read
     * again.
     */
    private final Object counting = new Object();

    private final Object listing = new Object();

    private ScheduledExecutorService heartbeat;

    private boolean started;

    private long nextAttempt;

    /**
     * Counts of the sessions of every server, by target, as last read, and
     * when; null until read, or once a session opened or closed here.
     */
    private volatile Map<Target, Integer> counts;

    private volatile long countsRead;

    /**
     * The open sessions of other servers, as last read, and when.
     */
    private volatile List<SessionRow> others;

    private volatile long othersRead;

    private volatile long lastReadFailureLogged;

    SessionStore(Database database, Limits.Defaults defaults, String serverId, String url, String hostname,
            String version) {
        this.database = database;
        this.defaults = defaults;
        this.serverId = serverId;
        this.url = url;
        this.hostname = hostname;
        this.version = version;
    }

    Database getDatabase() {
        return database;
    }

    Limits.Defaults getDefaults() {
        return defaults;
    }

    String getServerId() {
        return serverId;
    }

    /**
     * Sets up the tables if needed and starts the heartbeat, once. Returns
     * whether sessions are shared; if not, the reason was logged, and this
     * is tried again a minute later.
     */
    synchronized boolean start() {

        if (started)
            return true;
        if (System.currentTimeMillis() < nextAttempt)
            return false;

        try {
            database.createSchema();
            synchronized (recording) {
                try (Connection connection = database.connect()) {
                    touchServer(connection);
                }
            }
        }
        catch (SQLException e) {
            nextAttempt = System.currentTimeMillis() + RETRY_MS;
            logger.error("Sessions of the {} data source are not shared between servers: {} Their tables can be"
                    + " created with the schema script of the extension. Trying again in a minute.",
                    database.getType().getIdentifier(), e.getMessage());
            logger.debug("Unable to set up the shared sessions.", e);
            return false;
        }

        heartbeat = Executors.newSingleThreadScheduledExecutor(task -> {
            Thread thread = new Thread(task, "pam-ha-" + database.getType().getIdentifier());
            thread.setDaemon(true);
            return thread;
        });
        heartbeat.scheduleWithFixedDelay(this::beat, HEARTBEAT_SECONDS, HEARTBEAT_SECONDS, TimeUnit.SECONDS);
        heartbeat.scheduleWithFixedDelay(this::endRequested, END_POLL_MS, END_POLL_MS, TimeUnit.MILLISECONDS);

        started = true;
        logger.info("Sessions of the {} data source are shared with the other servers using its database"
                + " (this server: {}).", database.getType().getIdentifier(), serverId);
        return true;

    }

    synchronized boolean isStarted() {
        return started;
    }

    /**
     * Stops the heartbeat and removes this server and its sessions, which
     * end with it.
     */
    synchronized void shutdown() {

        if (!started)
            return;

        heartbeat.shutdownNow();
        started = false;

        synchronized (recording) {
            sessions.clear();
            try (Connection connection = database.connect()) {
                Sql.update(connection, "DELETE FROM pam_ha_session WHERE server_id = ?", serverId);
                Sql.update(connection, "DELETE FROM pam_ha_server WHERE server_id = ?", serverId);
            }
            catch (SQLException e) {
                logger.warn("Unable to remove the sessions of this server: {} The other servers ignore them"
                        + " within {} seconds.", e.getMessage(), STALE_SECONDS);
            }
        }

    }

    /**
     * Records a session about to open, refusing it if it would go over its
     * limits. Returns its identifier, for {@link #attach} and
     * {@link #close}.
     *
     * @throws GuacamoleException
     *     If the session would go over a limit (refused as Guacamole
     *     refuses it), or could not be recorded.
     */
    String open(Target target, String username, Limits limits) throws GuacamoleException {
        return open(new Session(target, username, false, null, true, null), limits);
    }

    /**
     * Records a session about to join another: never refused, as Guacamole
     * counts and limits no such session. It ends once the session joined
     * ends, as Guacamole ends those joining its own.
     *
     * @param listed
     *     Whether Guacamole itself lists it as an active connection, and
     *     ends it, or only this extension does.
     */
    String openJoin(SessionRow joined, String username, String sharingProfileId, boolean listed)
            throws GuacamoleException {
        return open(new Session(new Target(Target.Kind.CONNECTION, joined.connectionId), username, true,
                sharingProfileId, listed, joined.sessionId), null);
    }

    private String open(Session session, Limits limits) throws GuacamoleException {

        String id = UUID.randomUUID().toString();

        synchronized (recording) {

            sessions.put(id, session);
            try (Connection connection = database.connect()) {

                connection.setAutoCommit(false);
                connection.setTransactionIsolation(Connection.TRANSACTION_READ_COMMITTED);
                try {
                    if (limits != null && limits.any()) {
                        lock(connection);
                        touchServer(connection);
                        check(connection, session.target, session.username, limits);
                    }
                    else
                        touchServer(connection);
                    insert(connection, id, session);
                    connection.commit();
                    session.recorded = true;
                }
                catch (SQLException | GuacamoleException | RuntimeException e) {
                    // Its failure never hides why, such as a limit reached
                    try {
                        connection.rollback();
                    }
                    catch (SQLException rollback) {
                        e.addSuppressed(rollback);
                    }
                    throw e;
                }

            }
            catch (SQLException e) {
                sessions.remove(id);
                throw new GuacamoleServerException("Unable to record the session in the database.", e);
            }
            catch (GuacamoleException | RuntimeException e) {
                sessions.remove(id);
                throw e;
            }

        }

        counts = null;
        return id;

    }

    /**
     * Records where a session that just opened runs, so other servers list
     * it, join it and can end it, and keeps its tunnel, to end it when
     * asked. If the database cannot be reached, the next heartbeat records
     * it.
     */
    void attach(String id, GuacamoleTunnel tunnel, Details details) {

        synchronized (recording) {

            Session session = sessions.get(id);
            if (session == null)
                return;
            session.tunnel = tunnel;
            session.details = details;

            try (Connection connection = database.connect()) {
                SessionRow.Guacd guacd = details.guacd;
                Sql.update(connection, "UPDATE pam_ha_session SET tunnel_id = ?, connection_id = ?,"
                        + " remote_host = ?, guacd_hostname = ?, guacd_port = ?, guacd_ssl = ?,"
                        + " guacd_connection_id = ? WHERE session_id = ?",
                        details.tunnelId, details.connectionId, details.remoteHost,
                        guacd == null ? null : guacd.hostname, guacd == null ? Sql.NULL_INTEGER : guacd.port,
                        guacd == null ? Sql.NULL_INTEGER : (Object) guacd.ssl,
                        guacd == null ? null : guacd.connectionId, id);
            }
            catch (SQLException e) {
                session.recorded = false;
                logger.warn("Unable to record where a session runs: {} It is recorded at the next heartbeat.",
                        e.getMessage());
            }

        }

        counts = null;

        // Asked to end while it was opening
        Session session = sessions.get(id);
        if (session != null && session.ending)
            closeTunnel(session);

    }

    /**
     * Removes a session that ended, and its share links. If the database
     * cannot be reached, the next heartbeat removes it.
     */
    void close(String id) {

        synchronized (recording) {
            if (sessions.remove(id) == null)
                return;
            try (Connection connection = database.connect()) {
                Sql.update(connection, "DELETE FROM pam_ha_session WHERE session_id = ?", id);
                Sql.update(connection, "DELETE FROM pam_ha_share WHERE session_id = ?", id);
            }
            catch (SQLException e) {
                logger.warn("Unable to remove a session that ended: {} It is removed at the next heartbeat.",
                        e.getMessage());
            }
        }

        counts = null;
        others = null;

    }

    /**
     * Ends the session with the given identifier: at once if it is one of
     * this server, otherwise by asking the server it runs on, which ends it
     * within {@link #END_POLL_MS} milliseconds.
     */
    void end(String id) throws GuacamoleException {

        Session session = sessions.get(id);
        if (session != null) {
            // Still opening: ended as soon as its tunnel is attached
            session.ending = true;
            closeTunnel(session);
            return;
        }

        try (Connection connection = database.connect()) {
            Sql.update(connection, "UPDATE pam_ha_session SET end_requested = 1 WHERE session_id = ?", id);
        }
        catch (SQLException e) {
            throw new GuacamoleServerException("Unable to ask the server of the session to end it.", e);
        }

    }

    /**
     * Sessions open of the given target on every server, as read at most
     * {@link #COUNTS_MAX_AGE_MS} ago; zero if the database cannot be read.
     * Sessions joining others are not counted.
     */
    int count(Target target) {
        Integer count = counts().get(target);
        return count == null ? 0 : count;
    }

    /**
     * The counts, read again if too old: once, while other threads asking
     * meanwhile wait for them, as listing connections asks for each.
     */
    private Map<Target, Integer> counts() {
        synchronized (counting) {
            return readCounts();
        }
    }

    private Map<Target, Integer> readCounts() {

        Map<Target, Integer> current = counts;
        if (current != null && System.currentTimeMillis() - countsRead < COUNTS_MAX_AGE_MS)
            return current;

        Map<Target, Integer> read = new HashMap<>();
        try (Connection connection = database.connect();
             PreparedStatement statement = connection.prepareStatement(
                 "SELECT s.connection_id, s.connection_group_id, COUNT(*) FROM pam_ha_session s"
               + " WHERE s.joined = 0 AND " + live() + " GROUP BY s.connection_id, s.connection_group_id");
             ResultSet results = statement.executeQuery()) {

            while (results.next()) {
                String connectionId = results.getString(1);
                String group = results.getString(2);
                if (connectionId != null)
                    read.merge(new Target(Target.Kind.CONNECTION, connectionId), results.getInt(3), (a, b) -> a + b);
                if (group != null)
                    read.merge(new Target(Target.Kind.CONNECTION_GROUP, group), results.getInt(3), (a, b) -> a + b);
            }

        }
        catch (SQLException e) {
            readFailed("count the sessions of every server", e);
            return current != null ? current : Collections.<Target, Integer>emptyMap();
        }

        counts = read;
        countsRead = System.currentTimeMillis();
        return read;

    }

    /**
     * The open sessions of the other servers, as read at most
     * {@link #COUNTS_MAX_AGE_MS} ago; none if the database cannot be read.
     */
    List<SessionRow> others() {
        synchronized (listing) {

            List<SessionRow> current = others;
            if (current != null && System.currentTimeMillis() - othersRead < COUNTS_MAX_AGE_MS)
                return current;

            List<SessionRow> read = new ArrayList<>();
            try (Connection connection = database.connect();
                 PreparedStatement statement = connection.prepareStatement("SELECT " + COLUMNS
                     + " FROM pam_ha_session s WHERE s.server_id <> ? AND s.tunnel_id IS NOT NULL AND "
                     + live())) {
                statement.setString(1, serverId);
                try (ResultSet results = statement.executeQuery()) {
                    while (results.next())
                        read.add(row(results));
                }
            }
            catch (SQLException e) {
                readFailed("list the sessions of the other servers", e);
                return current != null ? current : Collections.<SessionRow>emptyList();
            }

            others = read;
            othersRead = System.currentTimeMillis();
            return read;

        }
    }

    /**
     * This server's open sessions that only this extension lists: those
     * joining sessions of other servers.
     */
    List<SessionRow> unlisted() {
        List<SessionRow> rows = new ArrayList<>();
        for (Map.Entry<String, Session> entry : sessions.entrySet()) {
            Session session = entry.getValue();
            Details details = session.details;
            if (!session.listed && details != null)
                rows.add(row(entry.getKey(), session, details));
        }
        return rows;
    }

    /**
     * The identifier of this server's session with the given tunnel, or
     * null.
     */
    String sessionOfTunnel(String tunnelId) {
        for (Map.Entry<String, Session> entry : sessions.entrySet()) {
            Details details = entry.getValue().details;
            if (details != null && details.tunnelId.equals(tunnelId))
                return entry.getKey();
        }
        return null;
    }

    /**
     * The session with the given identifier, of any server, if open; null
     * otherwise.
     */
    SessionRow find(String id) throws GuacamoleException {

        Session session = sessions.get(id);
        if (session != null) {
            Details details = session.details;
            return details == null ? null : row(id, session, details);
        }

        try (Connection connection = database.connect();
             PreparedStatement statement = connection.prepareStatement("SELECT " + COLUMNS
                 + " FROM pam_ha_session s WHERE s.session_id = ? AND " + live())) {
            statement.setString(1, id);
            try (ResultSet results = statement.executeQuery()) {
                return results.next() ? row(results) : null;
            }
        }
        catch (SQLException e) {
            throw new GuacamoleServerException("Unable to read the session from the database.", e);
        }

    }

    /**
     * Records a share link of a session, as created by Guacamole or by
     * {@link #share}, so every server opens it.
     */
    void registerShare(String sessionId, String key, String sharingProfileId) throws GuacamoleException {
        try (Connection connection = database.connect()) {
            Sql.update(connection, "INSERT INTO pam_ha_share (share_key, session_id, sharing_profile_id,"
                    + " created) VALUES (?, ?, ?, " + now() + ")", Sql.sha256(key), sessionId, sharingProfileId);
        }
        catch (SQLException e) {
            throw new GuacamoleServerException("Unable to record the share link in the database.", e);
        }
    }

    /**
     * Creates and records a share link of a session, returning its key.
     */
    String share(String sessionId, String sharingProfileId) throws GuacamoleException {
        byte[] bytes = new byte[32];
        random.nextBytes(bytes);
        String key = Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
        registerShare(sessionId, key, sharingProfileId);
        return key;
    }

    /**
     * The share link with the given SHA-256 of its key, if its session is
     * still open; null otherwise.
     */
    Share findShare(String keyHash) throws GuacamoleException {

        String sessionId;
        String sharingProfileId;
        try (Connection connection = database.connect();
             PreparedStatement statement = connection.prepareStatement("SELECT session_id, sharing_profile_id"
                 + " FROM pam_ha_share WHERE share_key = ?")) {
            statement.setString(1, keyHash);
            try (ResultSet results = statement.executeQuery()) {
                if (!results.next())
                    return null;
                sessionId = results.getString(1);
                sharingProfileId = results.getString(2);
            }
        }
        catch (SQLException e) {
            throw new GuacamoleServerException("Unable to read the share link from the database.", e);
        }

        SessionRow session = find(sessionId);
        return session == null ? null : new Share(keyHash, sharingProfileId, session);

    }

    /**
     * Tells this server is running, sets the database right about its
     * sessions, and removes the sessions of servers no longer heard from,
     * and the share links of sessions gone.
     */
    private void beat() {
        try {
            synchronized (recording) {
                try (Connection connection = database.connect()) {
                    touchServer(connection);
                    setRight(connection);
                }
            }
            try (Connection connection = database.connect()) {
                // Servers first, then every session of a server gone: one
                // going stale between the two leaves none behind
                Sql.update(connection, "DELETE FROM pam_ha_server WHERE last_seen < " + ago());
                Sql.update(connection, "DELETE FROM pam_ha_session WHERE server_id NOT IN (SELECT server_id"
                        + " FROM pam_ha_server)");
                Sql.update(connection, "DELETE FROM pam_ha_share WHERE session_id NOT IN (SELECT"
                        + " session_id FROM pam_ha_session)");
            }
        }
        catch (SQLException | RuntimeException e) {
            logger.warn("Unable to tell the other servers this one is running: {} Its sessions stop counting"
                    + " after {} seconds without it.", e.getMessage(), STALE_SECONDS);
        }
    }

    /**
     * Ends the sessions of this server other servers asked to end, and
     * those this extension opened joining a session that ended.
     */
    private void endRequested() {

        List<String> requested = new ArrayList<>();
        Map<String, Session> joining = new HashMap<>();
        for (Map.Entry<String, Session> entry : sessions.entrySet()) {
            Session session = entry.getValue();
            if (!session.listed && session.joinedSessionId != null && session.tunnel != null)
                joining.put(entry.getKey(), session);
        }
        Set<String> joinedOpen = new HashSet<>();

        try (Connection connection = database.connect()) {

            try (PreparedStatement statement = connection.prepareStatement("SELECT session_id FROM"
                    + " pam_ha_session WHERE server_id = ? AND end_requested = 1")) {
                statement.setString(1, serverId);
                try (ResultSet results = statement.executeQuery()) {
                    while (results.next())
                        requested.add(results.getString(1));
                }
            }

            Set<String> joined = new HashSet<>();
            for (Session session : joining.values())
                joined.add(session.joinedSessionId);
            for (List<String> chunk : Sql.chunks(joined)) {
                try (PreparedStatement statement = connection.prepareStatement("SELECT s.session_id FROM"
                        + " pam_ha_session s WHERE s.session_id IN (" + Sql.marks(chunk.size()) + ") AND "
                        + live())) {
                    Sql.bind(statement, chunk.toArray());
                    try (ResultSet results = statement.executeQuery()) {
                        while (results.next())
                            joinedOpen.add(results.getString(1));
                    }
                }
            }

        }
        catch (SQLException | RuntimeException e) {
            logger.debug("Unable to look for sessions to end.", e);
            return;
        }

        for (String id : requested) {
            Session session = sessions.get(id);
            if (session != null) {
                logger.info("Ending session {} of user \"{}\", as asked from another server.", id,
                        session.username);
                closeTunnel(session);
            }
        }

        for (Map.Entry<String, Session> entry : joining.entrySet()) {
            Session session = entry.getValue();
            if (!joinedOpen.contains(session.joinedSessionId) && sessions.containsKey(entry.getKey())) {
                logger.info("Ending session {} of user \"{}\": the session it joined ended.", entry.getKey(),
                        session.username);
                closeTunnel(session);
            }
        }

    }

    private void closeTunnel(Session session) {
        GuacamoleTunnel tunnel = session.tunnel;
        if (tunnel == null)
            return;
        try {
            tunnel.close();
        }
        catch (GuacamoleException | RuntimeException e) {
            logger.warn("Unable to end a session: {}", e.getMessage());
            logger.debug("Unable to close the tunnel of a session.", e);
        }
    }

    /**
     * Removes this server's sessions that ended here, and records again
     * those open here that went missing, or whose details are not recorded.
     */
    private void setRight(Connection connection) throws SQLException {

        Set<String> stored = new HashSet<>();
        try (PreparedStatement statement = connection.prepareStatement(
                "SELECT session_id FROM pam_ha_session WHERE server_id = ?")) {
            statement.setString(1, serverId);
            try (ResultSet results = statement.executeQuery()) {
                while (results.next())
                    stored.add(results.getString(1));
            }
        }

        for (String id : stored) {
            if (!sessions.containsKey(id))
                Sql.update(connection, "DELETE FROM pam_ha_session WHERE session_id = ?", id);
        }

        for (Map.Entry<String, Session> entry : sessions.entrySet()) {
            Session session = entry.getValue();
            if (session.recorded && stored.contains(entry.getKey()))
                continue;
            if (!session.recorded && session.details == null)
                continue;
            if (stored.contains(entry.getKey()))
                Sql.update(connection, "DELETE FROM pam_ha_session WHERE session_id = ?", entry.getKey());
            insert(connection, entry.getKey(), session);
            session.recorded = true;
        }

    }

    /**
     * Waits for, and holds until the transaction ends, the row every server
     * holds while checking limits. Updating it locks it in every database.
     */
    private static void lock(Connection connection) throws SQLException {
        // Waited for at most LOCK_TIMEOUT_SECONDS: a server stuck holding
        // it, such as one cut off mid-transaction, must not hold every
        // other server's sessions, and their heartbeats, with it
        int updated;
        try (PreparedStatement statement = connection.prepareStatement(
                "UPDATE pam_ha_lock SET lock_id = 1 WHERE lock_id = 1")) {
            statement.setQueryTimeout(LOCK_TIMEOUT_SECONDS);
            updated = statement.executeUpdate();
        }
        if (updated == 0)
            throw new SQLException("The row of pam_ha_lock is missing: run the schema script of the"
                    + " extension again.");
    }

    /**
     * Refuses the session if it would go over its limits, given the
     * sessions of every server.
     */
    private void check(Connection connection, Target target, String username, Limits limits)
            throws SQLException, GuacamoleException {

        String column = "s." + target.getKind().getColumn();
        try (PreparedStatement statement = connection.prepareStatement(
                "SELECT COUNT(*),"
              + " COALESCE(SUM(CASE WHEN " + column + " = ? THEN 1 ELSE 0 END), 0),"
              + " COALESCE(SUM(CASE WHEN " + column + " = ? AND s.username = ? THEN 1 ELSE 0 END), 0)"
              + " FROM pam_ha_session s WHERE s.joined = 0 AND " + live())) {
            statement.setString(1, target.getIdentifier());
            statement.setString(2, target.getIdentifier());
            statement.setString(3, username);
            try (ResultSet results = statement.executeQuery()) {
                results.next();
                limits.check(results.getInt(1), results.getInt(2), results.getInt(3));
            }
        }

    }

    private void insert(Connection connection, String id, Session session) throws SQLException {

        boolean group = session.target.getKind() == Target.Kind.CONNECTION_GROUP;
        Details details = session.details;
        SessionRow.Guacd guacd = details == null ? null : details.guacd;
        String connectionId = details != null ? details.connectionId : group ? null
                : session.target.getIdentifier();

        Sql.update(connection, "INSERT INTO pam_ha_session (session_id, server_id, tunnel_id,"
                + " connection_id, connection_group_id, sharing_profile_id, joined, username, remote_host,"
                + " started, guacd_hostname, guacd_port, guacd_ssl, guacd_connection_id) VALUES (?, ?, ?, ?, ?,"
                + " ?, ?, ?, ?, " + now() + ", ?, ?, ?, ?)",
                id, serverId, details == null ? null : details.tunnelId, connectionId,
                group ? session.target.getIdentifier() : null, session.sharingProfileId, session.joined,
                session.username, details == null ? null : details.remoteHost,
                guacd == null ? null : guacd.hostname, guacd == null ? Sql.NULL_INTEGER : guacd.port,
                guacd == null ? Sql.NULL_INTEGER : (Object) guacd.ssl, guacd == null ? null : guacd.connectionId);

    }

    /**
     * Tells this server is running. It started when first recorded, or
     * recorded again after a long pause, when the others removed it.
     */
    private void touchServer(Connection connection) throws SQLException {
        if (Sql.update(connection, "UPDATE pam_ha_server SET last_seen = " + now() + ", url = ?,"
                + " hostname = ?, version = ? WHERE server_id = ?", url, hostname, version, serverId) == 0)
            Sql.update(connection, "INSERT INTO pam_ha_server (server_id, last_seen, url, hostname, version,"
                    + " started) VALUES (?, " + now() + ", ?, ?, ?, " + now() + ")", serverId, url, hostname,
                    version);
    }

    private SessionRow row(ResultSet results) throws SQLException {
        String guacdHostname = results.getString(11);
        String guacdConnectionId = results.getString(14);
        SessionRow.Guacd guacd = guacdHostname == null || guacdConnectionId == null ? null
                : new SessionRow.Guacd(guacdHostname, results.getInt(12), results.getInt(13) != 0,
                        guacdConnectionId);
        return new SessionRow(results.getString(1), results.getString(2), results.getString(3),
                results.getString(4), results.getString(5), results.getString(6), results.getInt(7) != 0,
                results.getString(8), results.getString(9), database.getType().timestamp(results, 10), guacd);
    }

    private SessionRow row(String id, Session session, Details details) {
        boolean group = session.target.getKind() == Target.Kind.CONNECTION_GROUP;
        return new SessionRow(id, serverId, details.tunnelId, details.connectionId,
                group ? session.target.getIdentifier() : null, session.sharingProfileId, session.joined,
                session.username, details.remoteHost, session.started, details.guacd);
    }

    /**
     * SQL condition on a session "s": its server was heard from lately.
     */
    private String live() {
        return "s.server_id IN (SELECT server_id FROM pam_ha_server WHERE last_seen > " + ago() + ")";
    }

    private String now() {
        return database.getType().now();
    }

    private String ago() {
        return database.getType().secondsAgo(STALE_SECONDS);
    }

    private void readFailed(String what, SQLException e) {
        long now = System.currentTimeMillis();
        if (now - lastReadFailureLogged > RETRY_MS) {
            lastReadFailureLogged = now;
            logger.warn("Unable to {}: {}", what, e.getMessage());
        }
    }

    /**
     * The current time, for Guacamole's own tables, whose timestamps are
     * written by Java as Guacamole writes them.
     */
    static Timestamp timestamp() {
        return new Timestamp(System.currentTimeMillis());
    }

}
