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
import io.github.ialzamil.guacamole.pam.coordination.Coordination;
import io.github.ialzamil.guacamole.pam.db.PamDatabase;
import io.github.ialzamil.guacamole.pam.db.SqlDialect;

/**
 * Open sessions of managed connections on this Guacamole server, whose
 * tunnels only it can close. Each is recorded in "pam_session" too, so a
 * server taking over from one that stopped finds those it left open, and
 * with the HA module so every server can tell whether a connection is in
 * use (see {@link Coordination}).
 */
class SessionRegistry implements Coordination.Sessions {

    private static final Logger logger = LoggerFactory.getLogger(SessionRegistry.class);

    private final PamDatabase database;

    private final SqlDialect dialect;

    /**
     * Identifies this server's rows: its host name, made unique per start.
     */
    private final String server = truncate(Values.hostName(), MAX_HOST_NAME) + "/"
            + UUID.randomUUID().toString().substring(0, 8);

    /**
     * Longest host name kept in the server's identifier, which
     * "pam_session.server" holds in 128 characters.
     */
    private static final int MAX_HOST_NAME = 100;

    private static String truncate(String value, int max) {
        return value.length() > max ? value.substring(0, max) : value;
    }

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

        /**
         * Whether it was first recorded later than it started, by a
         * heartbeat: its start is then its own, not that of its row.
         */
        private volatile boolean recordedLate = false;

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

    /**
     * How many sessions one statement refreshes at most, well within the
     * parameters every database allows.
     */
    private static final int MAX_IN = 100;

    SessionRegistry(PamDatabase database) {
        this.database = database;
        this.dialect = database.getDialect();
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
            // Recorded again by the next heartbeat, with the HA module
            session.recordedLate = true;
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
                    // Recorded late, its row started after the session did,
                    // maybe after its checkout ended
                    if (!session.recordedLate)
                        session.started = SqlDialect.getTimestamp(results, 1).getTime();
                    session.recorded = true;
                }
            }
        }

    }

    /**
     * Forgets a session that ended, returning it, or null if unknown. Its
     * row stays until {@link #removeRow}.
     */
    Session ended(GuacamoleTunnel tunnel) {
        return local.remove(tunnel);
    }

    /**
     * Removes the row of a session that ended.
     */
    void removeRow(Session session) {

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

    @Override
    public Map<Integer, Integer> countLocal() {
        Map<Integer, Integer> counts = new HashMap<>();
        for (Session session : local.values()) {
            Integer id = Values.parseId(session.identifier);
            if (id != null)
                counts.merge(id, 1, (a, b) -> a + b);
        }
        return counts;
    }

    @Override
    public void refresh() throws GuacamoleException {
        try (Connection connection = database.getConnection()) {

            // Only those of open sessions: rows this server failed to remove
            // are not refreshed, and go stale like those of a stopped server
            List<Session> open = new ArrayList<>();
            for (Session session : local.values()) {
                if (Values.parseId(session.identifier) != null)
                    open.add(session);
            }

            int refreshed = 0;
            for (int i = 0; i < open.size(); i += MAX_IN) {
                List<Session> part = open.subList(i, Math.min(open.size(), i + MAX_IN));
                try (PreparedStatement statement = connection.prepareStatement("UPDATE pam_session SET heartbeat = "
                        + dialect.now() + " WHERE session_id IN " + SqlDialect.parameters(part.size()))) {
                    for (int j = 0; j < part.size(); j++)
                        statement.setString(j + 1, part.get(j).id);
                    refreshed += statement.executeUpdate();
                }
            }
            if (refreshed == open.size())
                return;

            // Some were removed by other servers while this one was not
            // heard from: each recorded again on its own, as one of a
            // connection just deleted, whose session closes shortly, cannot
            // be, and must not keep the others from being
            for (Session session : open) {
                try {
                    record(connection, session);
                }
                catch (SQLException e) {
                    logger.debug("Unable to record the session of \"{}\" on connection {}: {}", session.username,
                            session.identifier, e.getMessage());
                }
            }

        }
        catch (SQLException e) {
            throw new GuacamoleServerException("Unable to refresh the open sessions.", e);
        }
    }

    @Override
    public Set<Integer> removeOthers() throws GuacamoleException {
        return remove("server <> ?", server, "which stopped");
    }

    @Override
    public Set<Integer> removeStale(int seconds) throws GuacamoleException {
        return remove("NOT" + fresh(seconds), null, "which stopped refreshing it");
    }

    @Override
    public Map<Integer, Integer> countRecorded(int seconds) throws GuacamoleException {

        Map<Integer, Integer> counts = new HashMap<>();

        try (Connection connection = database.getConnection();
             PreparedStatement statement = connection.prepareStatement("SELECT connection_id, count(*)"
                     + " FROM pam_session WHERE" + fresh(seconds) + " GROUP BY connection_id");
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
     * The condition that a row was refreshed within the given seconds.
     */
    private String fresh(int seconds) {
        return " heartbeat > " + dialect.plusSeconds(dialect.now(), Integer.toString(-seconds));
    }

    /**
     * Removes the rows matching the given condition, of at most one
     * parameter, logging each as recorded by a server that did as said.
     * Returns the ids of their connections.
     */
    private Set<Integer> remove(String condition, String parameter, String what) throws GuacamoleException {

        Set<Integer> removed = new HashSet<>();

        try (Connection connection = database.getConnection()) {

            List<String[]> rows = new ArrayList<>();
            try (PreparedStatement statement = connection.prepareStatement(
                    "SELECT session_id, connection_id, username, server FROM pam_session WHERE " + condition)) {
                if (parameter != null)
                    statement.setString(1, parameter);
                try (ResultSet results = statement.executeQuery()) {
                    while (results.next())
                        rows.add(new String[] { results.getString(1), results.getString(2), results.getString(3),
                                results.getString(4) });
                }
            }

            // Each removed once, here or by another server, unless
            // refreshed meanwhile
            try (PreparedStatement statement = connection.prepareStatement(
                    "DELETE FROM pam_session WHERE session_id = ? AND " + condition)) {
                for (String[] row : rows) {
                    statement.setString(1, row[0]);
                    if (parameter != null)
                        statement.setString(2, parameter);
                    if (statement.executeUpdate() == 0)
                        continue;
                    removed.add(Integer.valueOf(row[1]));
                    logger.info("Removed the session of \"{}\" on connection {}, recorded by server \"{}\", {}.",
                            row[2], row[1], row[3], what);
                }
            }

        }
        catch (SQLException e) {
            throw new GuacamoleServerException("Unable to remove the sessions of stopped servers.", e);
        }

        return removed;

    }

}
