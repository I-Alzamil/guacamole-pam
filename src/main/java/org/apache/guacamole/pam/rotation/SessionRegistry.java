package org.apache.guacamole.pam.rotation;

import java.net.InetAddress;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;

import org.apache.guacamole.GuacamoleException;
import org.apache.guacamole.GuacamoleServerException;
import org.apache.guacamole.net.GuacamoleTunnel;
import org.apache.guacamole.pam.db.PamDatabase;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Open sessions of managed connections, on every Guacamole server sharing
 * the database. Each server keeps the tunnels of its own sessions, which only
 * it can close, and records them in "pam_session" so all servers can tell
 * whether a connection is in use. A server refreshes the heartbeat of its
 * rows every minute; rows of a server that stopped without removing them are
 * ignored once stale, then removed.
 *
 * Where "pam_session" is missing (tables created by hand for an earlier
 * version), only this server's sessions are known, as before.
 */
class SessionRegistry {

    private static final Logger logger = LoggerFactory.getLogger(SessionRegistry.class);

    /**
     * Age after which a row is no longer trusted: three missed heartbeats.
     */
    static final int STALE_SECONDS = 180;

    private static final String FRESH = " heartbeat > CURRENT_TIMESTAMP - make_interval(secs => " + STALE_SECONDS + ")";

    private final PamDatabase database;

    /**
     * Identifies this server's rows: its host name, made unique per start.
     */
    private final String server = hostName() + "/" + UUID.randomUUID().toString().substring(0, 8);

    /**
     * A session open on this server.
     */
    static final class Session {

        private final String id = UUID.randomUUID().toString();
        private final String identifier;
        private final String username;
        private final GuacamoleTunnel tunnel;

        /**
         * When it started, by the database's clock where it was recorded, so
         * it compares with the end of checkouts.
         */
        private volatile long started = System.currentTimeMillis();

        private volatile boolean recorded = false;

        private Session(String identifier, String username, GuacamoleTunnel tunnel) {
            this.identifier = identifier;
            this.username = username;
            this.tunnel = tunnel;
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

        long getStarted() {
            return started;
        }

    }

    private final ConcurrentMap<GuacamoleTunnel, Session> local = new ConcurrentHashMap<>();

    SessionRegistry(PamDatabase database) {
        this.database = database;
    }

    private static String hostName() {
        try {
            return InetAddress.getLocalHost().getHostName();
        }
        catch (Exception e) {
            return "guacamole";
        }
    }

    /**
     * Connection id as stored in the database, or null for connections
     * outside it.
     */
    private static Integer toId(String identifier) {
        return RotationService.parseInt(identifier);
    }

    void started(String identifier, String username, GuacamoleTunnel tunnel) {

        Session session = new Session(identifier, username, tunnel);
        local.put(tunnel, session);

        if (toId(identifier) == null || !database.hasSessionTable())
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
        try (PreparedStatement statement = connection.prepareStatement(
                "INSERT INTO pam_session (session_id, connection_id, username, server)"
              + " VALUES (?, ?, ?, ?)"
              + " ON CONFLICT (session_id) DO UPDATE SET heartbeat = CURRENT_TIMESTAMP"
              + " RETURNING started")) {
            statement.setString(1, session.id);
            statement.setInt(2, toId(session.identifier));
            statement.setString(3, session.username);
            statement.setString(4, server);
            try (ResultSet results = statement.executeQuery()) {
                if (results.next() && !session.recorded) {
                    session.started = results.getTimestamp(1).getTime();
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

        if (toId(session.identifier) != null && database.hasSessionTable()) {
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

        if (!database.hasSessionTable()) {
            for (Session session : local.values()) {
                Integer id = toId(session.identifier);
                if (id != null)
                    counts.merge(id, 1, Integer::sum);
            }
            return counts;
        }

        try (Connection connection = database.getConnection();
             PreparedStatement statement = connection.prepareStatement(
                 "SELECT connection_id, count(*) FROM pam_session WHERE" + FRESH + " GROUP BY connection_id");
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
        if (!database.hasSessionTable())
            return abandoned;

        try (Connection connection = database.getConnection()) {

            // Rows this server failed to remove are not refreshed, and go
            // stale like those of a stopped server
            for (Session session : local.values()) {
                if (toId(session.identifier) != null)
                    record(connection, session);
            }

            try (PreparedStatement statement = connection.prepareStatement(
                    "DELETE FROM pam_session WHERE NOT" + FRESH + " RETURNING connection_id, username, server");
                 ResultSet results = statement.executeQuery()) {
                while (results.next()) {
                    abandoned.add(results.getInt(1));
                    logger.info("Removed the stale session of \"{}\" on connection {}, recorded by server"
                            + " \"{}\", which stopped refreshing it.", results.getString(2), results.getInt(1),
                            results.getString(3));
                }
            }

        }
        catch (SQLException e) {
            throw new GuacamoleServerException("Unable to refresh the open sessions.", e);
        }

        return abandoned;

    }

}
