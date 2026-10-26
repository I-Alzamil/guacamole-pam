package io.github.ialzamil.guacamole.pam.rotation;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;

import org.apache.guacamole.GuacamoleException;
import org.apache.guacamole.GuacamoleServerException;
import org.apache.guacamole.net.GuacamoleTunnel;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import io.github.ialzamil.guacamole.pam.Values;
import io.github.ialzamil.guacamole.pam.db.PamDatabase;
import io.github.ialzamil.guacamole.pam.db.SqlDialect;

/**
 * Open sessions of managed connections, on every Guacamole server sharing
 * the database. Each server keeps the tunnels of its own sessions, which only
 * it can close, and records them in "pam_session" so all servers can tell
 * whether a connection is in use. A server refreshes the heartbeat of its
 * rows every minute; rows of a server that stopped without removing them are
 * ignored once stale, then removed.
 */
class SessionRegistry {

    private static final Logger logger = LoggerFactory.getLogger(SessionRegistry.class);

    /**
     * Age after which a row is no longer trusted: three missed heartbeats.
     */
    static final int STALE_SECONDS = 180;

    private final PamDatabase database;

    private final SqlDialect dialect;

    /**
     * The condition that a row is not stale.
     */
    private final String fresh;

    /**
     * Identifies this server's rows (see {@link ServerRegistry}).
     */
    private final String server;

    /**
     * A session open on this server.
     */
    static final class Session {

        private final String id = UUID.randomUUID().toString();
        private final String identifier;
        private final String username;
        private final GuacamoleTunnel tunnel;
        private final SessionAccess access;

        /**
         * When it started, by the database's clock where it was recorded, so
         * it compares with the end of checkouts.
         */
        private volatile long started = System.currentTimeMillis();

        private volatile boolean recorded = false;

        private Session(String identifier, String username, GuacamoleTunnel tunnel, SessionAccess access) {
            this.identifier = identifier;
            this.username = username;
            this.tunnel = tunnel;
            this.access = access;
        }

        String getIdentifier() {
            return identifier;
        }

        String getUsername() {
            return username;
        }

        GuacamoleTunnel getTunnel() {
            return tunnel;
        }

        SessionAccess getAccess() {
            return access;
        }

        long getStarted() {
            return started;
        }

    }

    private final ConcurrentMap<GuacamoleTunnel, Session> local = new ConcurrentHashMap<>();

    SessionRegistry(PamDatabase database, String server) {
        this.database = database;
        this.dialect = database.getDialect();
        this.server = server;
        this.fresh = " heartbeat > " + dialect.plusSeconds(dialect.now(), Integer.toString(-STALE_SECONDS));
    }

    void started(String identifier, String username, GuacamoleTunnel tunnel, SessionAccess access) {

        Session session = new Session(identifier, username, tunnel, access);
        local.put(tunnel, session);

        if (Values.parseId(identifier) == null)
            return;

        try (Connection connection = database.getConnection()) {
            record(connection, session);
        }
        catch (GuacamoleException | SQLException e) {
            // The next heartbeat records it
            logger.warn("Unable to record the session of \"{}\" on connection {}: {}", username, identifier,
                    e.getMessage());
        }

    }

    /**
     * Records a session, or refreshes its heartbeat. Its start is kept from
     * when it was first recorded, even if its row was removed since.
     */
    private void record(Connection connection, Session session) throws SQLException {

        Map<String, String> values = new LinkedHashMap<>();
        values.put("session_id", "?");
        values.put("connection_id", "?");
        values.put("username", "?");
        values.put("server", "?");

        try (PreparedStatement statement = connection.prepareStatement(dialect.upsert("pam_session",
                Collections.singletonList("session_id"), values, "heartbeat = " + dialect.now()))) {
            statement.setString(1, session.id);
            statement.setInt(2, Values.parseId(session.identifier));
            statement.setString(3, session.username);
            statement.setString(4, server);
            statement.executeUpdate();
        }

        if (session.recorded)
            return;

        try (PreparedStatement statement = connection.prepareStatement(
                "SELECT started FROM pam_session WHERE session_id = ?")) {
            statement.setString(1, session.id);
            try (ResultSet results = statement.executeQuery()) {
                if (results.next()) {
                    session.started = SqlDialect.getTimestamp(results, 1).getTime();
                    session.recorded = true;
                }
            }
        }

    }

    /**
     * Forgets a session, returning whether this server still has another
     * session of the same connection.
     */
    boolean ended(GuacamoleTunnel tunnel) {

        Session session = local.remove(tunnel);
        if (session == null)
            return false;

        if (Values.parseId(session.identifier) != null) {
            try (Connection connection = database.getConnection();
                 PreparedStatement statement = connection.prepareStatement(
                     "DELETE FROM pam_session WHERE session_id = ?")) {
                statement.setString(1, session.id);
                statement.executeUpdate();
            }
            catch (GuacamoleException | SQLException e) {
                // Ignored once stale
                logger.warn("Unable to remove the ended session of \"{}\" on connection {}: {}",
                        session.username, session.identifier, e.getMessage());
            }
        }

        return getLocal(session.identifier).size() > 0;

    }

    /**
     * Sessions of the connection open on this server.
     */
    List<Session> getLocal(String identifier) {
        List<Session> sessions = new ArrayList<>();
        for (Session session : local.values()) {
            if (session.identifier.equals(identifier))
                sessions.add(session);
        }
        return sessions;
    }

    boolean hasLocal() {
        return !local.isEmpty();
    }

    /**
     * Every session open on this server.
     */
    List<Session> getAllLocal() {
        return new ArrayList<>(local.values());
    }

    /**
     * Open sessions of the connection on every server.
     */
    int count(int connectionId) throws GuacamoleException {
        Integer count = countAll().get(connectionId);
        return count == null ? 0 : count;
    }

    /**
     * Open sessions per connection id on every server, leaving out
     * connections with none.
     */
    Map<Integer, Integer> countAll() throws GuacamoleException {

        Map<Integer, Integer> counts = new HashMap<>();

        try (Connection connection = database.getConnection();
             PreparedStatement statement = connection.prepareStatement(
                 "SELECT connection_id, count(*) FROM pam_session WHERE" + fresh + " GROUP BY connection_id");
             ResultSet results = statement.executeQuery()) {
            while (results.next())
                counts.put(results.getInt(1), results.getInt(2));
        }
        catch (SQLException e) {
            throw new GuacamoleServerException("Unable to count open sessions.", e);
        }

        return counts;

    }

    /**
     * Refreshes this server's rows, recording any it is missing, and removes
     * stale rows of servers that stopped. Returns the ids of connections
     * whose sessions were removed, as their after-use rotation was never
     * triggered.
     */
    Set<Integer> heartbeat() throws GuacamoleException {

        Set<Integer> abandoned = new HashSet<>();

        try (Connection connection = database.getConnection()) {

            // Rows this server failed to remove are not refreshed, and go
            // stale like those of a stopped server. Each is recorded on its
            // own: one of a connection just deleted, whose session closes
            // shortly, cannot be, and must not keep the others from being
            for (Session session : local.values()) {
                if (Values.parseId(session.identifier) == null)
                    continue;
                try {
                    record(connection, session);
                }
                catch (SQLException e) {
                    logger.debug("Unable to record the session of \"{}\" on connection {}: {}", session.username,
                            session.identifier, e.getMessage());
                }
            }

            List<String[]> stale = new ArrayList<>();
            try (PreparedStatement statement = connection.prepareStatement(
                    "SELECT session_id, connection_id, username, server FROM pam_session WHERE NOT" + fresh);
                 ResultSet results = statement.executeQuery()) {
                while (results.next())
                    stale.add(new String[] { results.getString(1), results.getString(2), results.getString(3),
                            results.getString(4) });
            }

            // Each removed once, here or by another server, unless
            // refreshed meanwhile
            try (PreparedStatement statement = connection.prepareStatement(
                    "DELETE FROM pam_session WHERE session_id = ? AND NOT" + fresh)) {
                for (String[] row : stale) {
                    statement.setString(1, row[0]);
                    if (statement.executeUpdate() == 0)
                        continue;
                    abandoned.add(Integer.valueOf(row[1]));
                    logger.info("Removed the stale session of \"{}\" on connection {}, recorded by server"
                            + " \"{}\", which stopped refreshing it.", row[2], row[1], row[3]);
                }
            }

        }
        catch (SQLException e) {
            throw new GuacamoleServerException("Unable to refresh the open sessions.", e);
        }

        return abandoned;

    }

}
