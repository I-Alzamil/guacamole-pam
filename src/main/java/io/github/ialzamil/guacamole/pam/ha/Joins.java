package io.github.ialzamil.guacamole.pam.ha;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.HashMap;
import java.util.Map;

import org.apache.guacamole.GuacamoleException;
import org.apache.guacamole.GuacamoleResourceNotFoundException;
import org.apache.guacamole.GuacamoleServerException;
import org.apache.guacamole.net.GuacamoleSocket;
import org.apache.guacamole.net.GuacamoleTunnel;
import org.apache.guacamole.net.InetGuacamoleSocket;
import org.apache.guacamole.net.SSLGuacamoleSocket;
import org.apache.guacamole.net.SimpleGuacamoleTunnel;
import org.apache.guacamole.protocol.ConfiguredGuacamoleSocket;
import org.apache.guacamole.protocol.GuacamoleClientInformation;
import org.apache.guacamole.protocol.GuacamoleConfiguration;
import org.apache.guacamole.token.TokenFilter;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Sessions joining a session of another server: they connect to the guacd
 * that session runs on and join its connection there, with the parameters
 * of a sharing profile, or none to share it fully, as Guacamole's own
 * sharing joins sessions. They are recorded in Guacamole's connection
 * history, as Guacamole records those it opens.
 */
final class Joins {

    private static final Logger logger = LoggerFactory.getLogger(Joins.class);

    private Joins() {
    }

    /**
     * Opens a session joining the given one.
     *
     * @param username
     *     Who joins, empty for someone using a share link.
     *
     * @param remoteHost
     *     Where from.
     */
    static GuacamoleTunnel open(SessionStore store, SessionRow joined, String sharingProfileId, String username,
            String remoteHost, GuacamoleClientInformation info, Map<String, String> tokens)
            throws GuacamoleException {

        if (!joined.joinable())
            throw new GuacamoleResourceNotFoundException("No existing connection to be joined.");

        Database database = store.getDatabase();
        GuacamoleConfiguration config = new GuacamoleConfiguration();
        config.setConnectionID(joined.guacd.connectionId);
        config.setParameters(parameters(database, sharingProfileId));
        TokenFilter filter = new TokenFilter();
        filter.setTokens(tokens);
        filter.filterValues(config.getParameters());

        String sessionId = store.openJoin(joined, username, sharingProfileId, false);
        try {

            GuacamoleSocket socket = joined.guacd.ssl
                    ? new SSLGuacamoleSocket(joined.guacd.hostname, joined.guacd.port)
                    : new InetGuacamoleSocket(joined.guacd.hostname, joined.guacd.port);
            GuacamoleTunnel tunnel = new SimpleGuacamoleTunnel(new ConfiguredGuacamoleSocket(socket, config,
                    info));

            Long historyId = startHistory(database, joined.connectionId, sharingProfileId, username, remoteHost);
            SessionTunnel session = new SessionTunnel(tunnel, () -> {
                store.close(sessionId);
                endHistory(database, historyId);
            });
            store.attach(sessionId, session, new SessionStore.Details(tunnel.getUUID().toString(),
                    joined.connectionId, remoteHost, joined.guacd));
            return session;

        }
        catch (GuacamoleException | RuntimeException e) {
            store.close(sessionId);
            throw e;
        }

    }

    /**
     * The parameters of a sharing profile, or none.
     */
    private static Map<String, String> parameters(Database database, String sharingProfileId)
            throws GuacamoleException {

        Map<String, String> parameters = new HashMap<>();
        Integer id = Sql.id(sharingProfileId);
        if (id == null)
            return parameters;

        try (Connection connection = database.connect();
             PreparedStatement statement = connection.prepareStatement("SELECT parameter_name, parameter_value"
                 + " FROM guacamole_sharing_profile_parameter WHERE sharing_profile_id = ?")) {
            statement.setInt(1, id);
            try (ResultSet results = statement.executeQuery()) {
                while (results.next())
                    parameters.put(results.getString(1), results.getString(2));
            }
        }
        catch (SQLException e) {
            throw new GuacamoleServerException("Unable to read the sharing profile.", e);
        }
        return parameters;

    }

    /**
     * Records a joining session in Guacamole's connection history, returning
     * its record's identifier; null if it could not be recorded, which is
     * logged.
     */
    private static Long startHistory(Database database, String connectionId, String sharingProfileId,
            String username, String remoteHost) {

        Integer connection = Sql.id(connectionId);
        Integer sharingProfile = Sql.id(sharingProfileId);
        if (connection == null)
            return null;

        try (Connection db = database.connect()) {

            String connectionName = string(db, "SELECT connection_name FROM guacamole_connection"
                    + " WHERE connection_id = ?", connection);
            String sharingProfileName = sharingProfile == null ? null : string(db, "SELECT"
                    + " sharing_profile_name FROM guacamole_sharing_profile WHERE sharing_profile_id = ?",
                    sharingProfile);
            Integer userId = null;
            try (PreparedStatement statement = db.prepareStatement("SELECT u.user_id FROM guacamole_user u"
                    + " JOIN guacamole_entity e ON u.entity_id = e.entity_id WHERE e.name = ? AND e.type = 'USER'")) {
                statement.setString(1, username);
                try (ResultSet results = statement.executeQuery()) {
                    if (results.next())
                        userId = results.getInt(1);
                }
            }

            try (PreparedStatement statement = db.prepareStatement("INSERT INTO guacamole_connection_history"
                    + " (user_id, username, remote_host, connection_id, connection_name, sharing_profile_id,"
                    + " sharing_profile_name, start_date) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                    Statement.RETURN_GENERATED_KEYS)) {
                Sql.bind(statement, userId != null ? (Object) userId : Sql.NULL_INTEGER, username, remoteHost,
                        connection, connectionName, sharingProfile != null ? (Object) sharingProfile
                        : Sql.NULL_INTEGER, sharingProfileName, SessionStore.timestamp());
                statement.executeUpdate();
                try (ResultSet keys = statement.getGeneratedKeys()) {
                    return keys.next() ? keys.getLong(1) : null;
                }
            }

        }
        catch (SQLException e) {
            logger.warn("Unable to record a session joining another in the connection history: {}",
                    e.getMessage());
            logger.debug("Unable to record a joining session.", e);
            return null;
        }

    }

    private static void endHistory(Database database, Long historyId) {
        if (historyId == null)
            return;
        try (Connection db = database.connect()) {
            Sql.update(db, "UPDATE guacamole_connection_history SET end_date = ? WHERE history_id = ?",
                    SessionStore.timestamp(), historyId);
        }
        catch (SQLException e) {
            logger.warn("Unable to record the end of a joining session in the connection history: {}",
                    e.getMessage());
        }
    }

    private static String string(Connection db, String sql, int id) throws SQLException {
        try (PreparedStatement statement = db.prepareStatement(sql)) {
            statement.setInt(1, id);
            try (ResultSet results = statement.executeQuery()) {
                return results.next() ? results.getString(1) : null;
            }
        }
    }

}
