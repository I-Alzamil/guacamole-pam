package org.apache.guacamole.pam.db;

import java.sql.Array;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Timestamp;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import org.apache.guacamole.GuacamoleException;
import org.apache.guacamole.GuacamoleServerException;
import org.apache.guacamole.pam.PamAttributes;

/**
 * Reads managed connections from the Guacamole JDBC tables, and records
 * rotation outcomes in "pam_rotation_state". Writing the rotated password
 * straight to "guacamole_connection_parameter" lets rotations run without a
 * user session, such as for periodic rotation.
 */
public class ConnectionRepository {

    private static final String PASSWORD_PARAMETER = "password";

    private final PamDatabase database;

    public ConnectionRepository(PamDatabase database) {
        this.database = database;
    }

    /**
     * A connection with its parameters, attributes and rotation state.
     */
    public static final class Target {

        private final int id;
        private final String name;
        private final String protocol;
        private final Map<String, String> parameters = new HashMap<>();
        private final Map<String, String> attributes = new HashMap<>();
        private State state = new State();

        Target(int id, String name, String protocol) {
            this.id = id;
            this.name = name;
            this.protocol = protocol;
        }

        public int getId() {
            return id;
        }

        public String getName() {
            return name;
        }

        public String getProtocol() {
            return protocol;
        }

        public Map<String, String> getParameters() {
            return parameters;
        }

        public Map<String, String> getAttributes() {
            return attributes;
        }

        /**
         * Returns the attribute value, or null if unset or blank.
         */
        public String getAttribute(String name) {
            String value = attributes.get(name);
            return value == null || value.trim().isEmpty() ? null : value.trim();
        }

        public State getState() {
            return state;
        }

    }

    /**
     * Outcome of the latest rotation attempt of a connection.
     */
    public static final class State {

        private Timestamp lastAttempt;
        private Timestamp lastSuccess;
        private String status;
        private String message;
        private String hostKey;
        private boolean pendingPassword;

        public Timestamp getLastAttempt() {
            return lastAttempt;
        }

        public Timestamp getLastSuccess() {
            return lastSuccess;
        }

        public String getStatus() {
            return status;
        }

        public String getMessage() {
            return message;
        }

        public String getHostKey() {
            return hostKey;
        }

        public boolean hasPendingPassword() {
            return pendingPassword;
        }

    }

    /**
     * Loads a connection with all its parameters and attributes, or returns
     * null if it does not exist.
     */
    public Target load(int connectionId) throws GuacamoleException {

        try (Connection connection = database.getConnection()) {

            Target target;
            try (PreparedStatement statement = connection.prepareStatement(
                    "SELECT connection_id, connection_name, protocol FROM guacamole_connection"
                  + " WHERE connection_id = ?")) {
                statement.setInt(1, connectionId);
                try (ResultSet results = statement.executeQuery()) {
                    if (!results.next())
                        return null;
                    target = new Target(results.getInt(1), results.getString(2), results.getString(3));
                }
            }

            readPairs(connection, "SELECT parameter_name, parameter_value FROM guacamole_connection_parameter"
                    + " WHERE connection_id = ?", connectionId, target.parameters);
            readPairs(connection, "SELECT attribute_name, attribute_value FROM guacamole_connection_attribute"
                    + " WHERE connection_id = ?", connectionId, target.attributes);

            Map<Integer, State> states = readStates(connection);
            if (states.containsKey(connectionId))
                target.state = states.get(connectionId);

            return target;

        }
        catch (SQLException e) {
            throw new GuacamoleServerException("Unable to read connection " + connectionId + ".", e);
        }

    }

    /**
     * Returns every connection with a platform, with its PAM attributes and
     * state but without its parameters.
     */
    public List<Target> listManaged() throws GuacamoleException {

        Map<Integer, Target> targets = new LinkedHashMap<>();

        try (Connection connection = database.getConnection()) {

            try (PreparedStatement statement = connection.prepareStatement(
                    "SELECT c.connection_id, c.connection_name, c.protocol, a.attribute_name, a.attribute_value"
                  + " FROM guacamole_connection c"
                  + " JOIN guacamole_connection_attribute a ON a.connection_id = c.connection_id"
                  + " WHERE a.attribute_name LIKE 'pam-%'"
                  + " AND c.connection_id IN (SELECT connection_id FROM guacamole_connection_attribute"
                  + "   WHERE attribute_name = ? AND attribute_value <> '')"
                  + " ORDER BY lower(c.connection_name), c.connection_id")) {

                statement.setString(1, PamAttributes.PLATFORM);

                try (ResultSet results = statement.executeQuery()) {
                    while (results.next()) {
                        int id = results.getInt(1);
                        Target target = targets.get(id);
                        if (target == null) {
                            target = new Target(id, results.getString(2), results.getString(3));
                            targets.put(id, target);
                        }
                        target.attributes.put(results.getString(4), results.getString(5));
                    }
                }

            }

            Map<Integer, State> states = readStates(connection);
            for (Target target : targets.values()) {
                if (states.containsKey(target.id))
                    target.state = states.get(target.id);
            }

        }
        catch (SQLException e) {
            throw new GuacamoleServerException("Unable to list managed connections.", e);
        }

        return new ArrayList<>(targets.values());

    }

    /**
     * Returns every connection that may need an access request: Account
     * connections, and connections requiring a request or approvals. Only
     * the named, non-secret parameters and the PAM attributes are loaded.
     */
    public List<Target> listRequestCandidates(String accountProtocol, List<String> parameterNames)
            throws GuacamoleException {

        Map<Integer, Target> targets = new LinkedHashMap<>();

        try (Connection connection = database.getConnection()) {

            try (PreparedStatement statement = connection.prepareStatement(
                    "SELECT connection_id, connection_name, protocol FROM guacamole_connection"
                  + " WHERE protocol = ? OR connection_id NOT IN (SELECT connection_id FROM guacamole_connection_attribute"
                  + "   WHERE attribute_name = ? AND attribute_value = 'true')"
                  + " OR connection_id IN (SELECT connection_id FROM guacamole_connection_attribute"
                  + "   WHERE attribute_name = ? AND attribute_value NOT IN ('', '0'))"
                  + " ORDER BY lower(connection_name), connection_id")) {
                statement.setString(1, accountProtocol);
                statement.setString(2, PamAttributes.REQUEST_EXEMPT);
                statement.setString(3, PamAttributes.APPROVALS_REQUIRED);
                try (ResultSet results = statement.executeQuery()) {
                    while (results.next())
                        targets.put(results.getInt(1), new Target(results.getInt(1), results.getString(2), results.getString(3)));
                }
            }

            Array ids = connection.createArrayOf("integer", targets.keySet().toArray());

            try (PreparedStatement statement = connection.prepareStatement(
                    "SELECT connection_id, parameter_name, parameter_value FROM guacamole_connection_parameter"
                  + " WHERE connection_id = ANY (?) AND parameter_name = ANY (?)")) {
                statement.setArray(1, ids);
                statement.setArray(2, connection.createArrayOf("varchar", parameterNames.toArray()));
                try (ResultSet results = statement.executeQuery()) {
                    while (results.next())
                        targets.get(results.getInt(1)).parameters.put(results.getString(2), results.getString(3));
                }
            }

            try (PreparedStatement statement = connection.prepareStatement(
                    "SELECT connection_id, attribute_name, attribute_value FROM guacamole_connection_attribute"
                  + " WHERE connection_id = ANY (?) AND attribute_name LIKE 'pam-%'")) {
                statement.setArray(1, ids);
                try (ResultSet results = statement.executeQuery()) {
                    while (results.next())
                        targets.get(results.getInt(1)).attributes.put(results.getString(2), results.getString(3));
                }
            }

        }
        catch (SQLException e) {
            throw new GuacamoleServerException("Unable to list request connections.", e);
        }

        return new ArrayList<>(targets.values());

    }

    /**
     * Marks a rotation as started, storing the password about to be set so
     * it survives a crash mid-rotation.
     */
    public void recordStart(int connectionId, String pendingPassword) throws GuacamoleException {

        try (Connection connection = database.getConnection();
             PreparedStatement statement = connection.prepareStatement(
                 "INSERT INTO pam_rotation_state (connection_id, last_attempt, last_status, last_message, pending_password)"
               + " VALUES (?, CURRENT_TIMESTAMP, 'RUNNING', NULL, ?)"
               + " ON CONFLICT (connection_id) DO UPDATE SET last_attempt = EXCLUDED.last_attempt,"
               + " last_status = EXCLUDED.last_status, last_message = NULL,"
               + " pending_password = EXCLUDED.pending_password")) {

            statement.setInt(1, connectionId);
            statement.setString(2, pendingPassword);
            statement.executeUpdate();

        }
        catch (SQLException e) {
            throw new GuacamoleServerException("Unable to record rotation start.", e);
        }

    }

    /**
     * Stores the new password of the connection and records the success, in
     * one transaction.
     */
    public void recordSuccess(int connectionId, String newPassword, String message, String hostKey)
            throws GuacamoleException {

        try (Connection connection = database.getConnection()) {

            connection.setAutoCommit(false);
            try {

                try (PreparedStatement statement = connection.prepareStatement(
                        "INSERT INTO guacamole_connection_parameter (connection_id, parameter_name, parameter_value)"
                      + " VALUES (?, ?, ?) ON CONFLICT (connection_id, parameter_name)"
                      + " DO UPDATE SET parameter_value = EXCLUDED.parameter_value")) {
                    statement.setInt(1, connectionId);
                    statement.setString(2, PASSWORD_PARAMETER);
                    statement.setString(3, newPassword);
                    statement.executeUpdate();
                }

                try (PreparedStatement statement = connection.prepareStatement(
                        "UPDATE pam_rotation_state SET last_success = CURRENT_TIMESTAMP, last_status = 'SUCCESS',"
                      + " last_message = ?, host_key = coalesce(?, host_key), pending_password = NULL"
                      + " WHERE connection_id = ?")) {
                    statement.setString(1, message);
                    statement.setString(2, hostKey);
                    statement.setInt(3, connectionId);
                    statement.executeUpdate();
                }

                connection.commit();

            }
            catch (SQLException e) {
                connection.rollback();
                throw e;
            }

        }
        catch (SQLException e) {
            throw new GuacamoleServerException("Unable to store the rotated password.", e);
        }

    }

    /**
     * Records a failed or unconfirmed rotation. The pending password is kept
     * only when the target may already be using it.
     */
    public void recordFailure(int connectionId, String status, String message, String hostKey,
            boolean keepPendingPassword) throws GuacamoleException {

        try (Connection connection = database.getConnection();
             PreparedStatement statement = connection.prepareStatement(
                 "INSERT INTO pam_rotation_state (connection_id, last_attempt, last_status, last_message, host_key)"
               + " VALUES (?, CURRENT_TIMESTAMP, ?, ?, ?)"
               + " ON CONFLICT (connection_id) DO UPDATE SET last_attempt = EXCLUDED.last_attempt,"
               + " last_status = EXCLUDED.last_status, last_message = EXCLUDED.last_message,"
               + " host_key = coalesce(EXCLUDED.host_key, pam_rotation_state.host_key),"
               + " pending_password = CASE WHEN ? THEN pam_rotation_state.pending_password ELSE NULL END")) {

            statement.setInt(1, connectionId);
            statement.setString(2, status);
            statement.setString(3, message);
            statement.setString(4, hostKey);
            statement.setBoolean(5, keepPendingPassword);
            statement.executeUpdate();

        }
        catch (SQLException e) {
            throw new GuacamoleServerException("Unable to record rotation failure.", e);
        }

    }

    /**
     * Returns the password kept from an unconfirmed rotation, or null.
     */
    public String getPendingPassword(int connectionId) throws GuacamoleException {

        try (Connection connection = database.getConnection();
             PreparedStatement statement = connection.prepareStatement(
                 "SELECT pending_password FROM pam_rotation_state WHERE connection_id = ?")) {

            statement.setInt(1, connectionId);
            try (ResultSet results = statement.executeQuery()) {
                return results.next() ? results.getString(1) : null;
            }

        }
        catch (SQLException e) {
            throw new GuacamoleServerException("Unable to read rotation state.", e);
        }

    }

    private static void readPairs(Connection connection, String sql, int connectionId,
            Map<String, String> into) throws SQLException {
        try (PreparedStatement statement = connection.prepareStatement(sql)) {
            statement.setInt(1, connectionId);
            try (ResultSet results = statement.executeQuery()) {
                while (results.next())
                    into.put(results.getString(1), results.getString(2));
            }
        }
    }

    private static Map<Integer, State> readStates(Connection connection) throws SQLException {

        Map<Integer, State> states = new HashMap<>();

        try (PreparedStatement statement = connection.prepareStatement(
                "SELECT connection_id, last_attempt, last_success, last_status, last_message, host_key,"
              + " pending_password IS NOT NULL FROM pam_rotation_state");
             ResultSet results = statement.executeQuery()) {

            while (results.next()) {
                State state = new State();
                state.lastAttempt = results.getTimestamp(2);
                state.lastSuccess = results.getTimestamp(3);
                state.status = results.getString(4);
                state.message = results.getString(5);
                state.hostKey = results.getString(6);
                state.pendingPassword = results.getBoolean(7);
                states.put(results.getInt(1), state);
            }

        }

        return states;

    }

}
