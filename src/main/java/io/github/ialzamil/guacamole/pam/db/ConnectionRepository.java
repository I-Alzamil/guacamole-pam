package io.github.ialzamil.guacamole.pam.db;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Timestamp;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import org.apache.guacamole.GuacamoleException;
import org.apache.guacamole.GuacamoleServerException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import io.github.ialzamil.guacamole.pam.PamAttributes;
import io.github.ialzamil.guacamole.pam.crypto.MigrationReport;
import io.github.ialzamil.guacamole.pam.crypto.Secrets;

/**
 * Reads managed connections from the Guacamole JDBC tables, and records
 * rotation outcomes in "pam_rotation_state". Writing the rotated password
 * straight to "guacamole_connection_parameter" lets rotations run without a
 * user session, such as for periodic rotation.
 *
 * If a key is set (see {@link Secrets}), passwords kept from unconfirmed
 * rotations are encrypted, and the passwords, keys and passphrases of every
 * connection, Accounts included, are kept apart (see
 * {@link ConnectionSecrets}). Values returned here are always plaintext.
 */
public class ConnectionRepository {

    private static final Logger logger = LoggerFactory.getLogger(ConnectionRepository.class);

    static final String PASSWORD_PARAMETER = "password";

    private final PamDatabase database;

    private final SqlDialect dialect;

    private final Secrets secrets;

    private final ConnectionSecrets connectionSecrets;

    public ConnectionRepository(PamDatabase database, Secrets secrets, ConnectionSecrets connectionSecrets) {
        this.database = database;
        this.dialect = database.getDialect();
        this.secrets = secrets;
        this.connectionSecrets = connectionSecrets;
    }

    /**
     * Sets a parameter of a connection, within the caller's transaction.
     */
    static void setParameter(SqlDialect dialect, Connection connection, int connectionId, String parameter,
            String value) throws SQLException {
        Map<String, String> values = new LinkedHashMap<>();
        values.put("connection_id", "?");
        values.put("parameter_name", "?");
        values.put("parameter_value", "?");
        try (PreparedStatement statement = connection.prepareStatement(dialect.upsert(
                "guacamole_connection_parameter", Arrays.asList("connection_id", "parameter_name"), values,
                "parameter_value = EXCLUDED.parameter_value"))) {
            statement.setInt(1, connectionId);
            statement.setString(2, parameter);
            statement.setString(3, value);
            statement.executeUpdate();
        }
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

        /**
         * Why a sensitive parameter could not be read, leaving it out, or
         * null.
         */
        private String secretError;

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

        /**
         * The connection's password, as plaintext, or null if it has none.
         *
         * @throws GuacamoleServerException
         *     If a sensitive parameter could not be read (not decrypted).
         */
        public String getPassword() throws GuacamoleServerException {
            if (secretError != null)
                throw new GuacamoleServerException("The secrets of \"" + name + "\" cannot be read: "
                        + secretError);
            return parameters.get(PASSWORD_PARAMETER);
        }

        /**
         * Why a sensitive parameter could not be read, leaving it out of the
         * parameters, or null.
         */
        public String getSecretError() {
            return secretError;
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
            // Most callers need no password, so one that cannot be read is
            // left out, and reported by Target.getPassword()
            for (String name : ConnectionSecrets.SENSITIVE) {
                if (!target.parameters.containsKey(name))
                    continue;
                try {
                    target.parameters.put(name, connectionSecrets.resolve(connection, connectionId, name,
                            target.parameters.get(name)));
                }
                catch (GuacamoleException e) {
                    target.parameters.remove(name);
                    target.secretError = e.getMessage();
                }
            }
            readPairs(connection, "SELECT attribute_name, attribute_value FROM guacamole_connection_attribute"
                    + " WHERE connection_id = ?", connectionId, target.attributes);

            Map<Integer, State> states = readStates(connection, connectionId);
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

            Map<Integer, State> states = readStates(connection, null);
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

        // Connections are read by this condition, rather than by listing
        // their ids, which could be more than a statement may hold
        String candidates = "SELECT connection_id FROM guacamole_connection"
                + " WHERE protocol = ? OR connection_id NOT IN (SELECT connection_id FROM guacamole_connection_attribute"
                + "   WHERE attribute_name = ? AND attribute_value = 'true')"
                + " OR connection_id IN (SELECT connection_id FROM guacamole_connection_attribute"
                + "   WHERE attribute_name = ? AND attribute_value NOT IN ('', '0'))";

        try (Connection connection = database.getConnection()) {

            try (PreparedStatement statement = connection.prepareStatement(
                    "SELECT connection_id, connection_name, protocol FROM guacamole_connection"
                  + " WHERE connection_id IN (" + candidates + ")"
                  + " ORDER BY lower(connection_name), connection_id")) {
                setCandidateParameters(statement, 1, accountProtocol);
                try (ResultSet results = statement.executeQuery()) {
                    while (results.next())
                        targets.put(results.getInt(1), new Target(results.getInt(1), results.getString(2), results.getString(3)));
                }
            }

            if (!parameterNames.isEmpty()) {
                try (PreparedStatement statement = connection.prepareStatement(
                        "SELECT connection_id, parameter_name, parameter_value FROM guacamole_connection_parameter"
                      + " WHERE connection_id IN (" + candidates + ")"
                      + " AND parameter_name IN " + SqlDialect.parameters(parameterNames.size()))) {
                    int index = setCandidateParameters(statement, 1, accountProtocol);
                    for (String name : parameterNames)
                        statement.setString(index++, name);
                    try (ResultSet results = statement.executeQuery()) {
                        while (results.next())
                            addTo(targets, results);
                    }
                }
            }

            try (PreparedStatement statement = connection.prepareStatement(
                    "SELECT connection_id, attribute_name, attribute_value FROM guacamole_connection_attribute"
                  + " WHERE connection_id IN (" + candidates + ") AND attribute_name LIKE 'pam-%'")) {
                setCandidateParameters(statement, 1, accountProtocol);
                try (ResultSet results = statement.executeQuery()) {
                    while (results.next()) {
                        Target target = targets.get(results.getInt(1));
                        // Added since the connections were listed
                        if (target != null)
                            target.attributes.put(results.getString(2), results.getString(3));
                    }
                }
            }

        }
        catch (SQLException e) {
            throw new GuacamoleServerException("Unable to list request connections.", e);
        }

        return new ArrayList<>(targets.values());

    }

    /**
     * Sets the parameters of the condition selecting request candidates,
     * from the given index, returning the index of the next parameter.
     */
    private static int setCandidateParameters(PreparedStatement statement, int index, String accountProtocol)
            throws SQLException {
        statement.setString(index++, accountProtocol);
        statement.setString(index++, PamAttributes.REQUEST_EXEMPT);
        statement.setString(index++, PamAttributes.APPROVALS_REQUIRED);
        return index;
    }

    /**
     * Adds a parameter read as (connection id, name, value) to its target,
     * unless the connection was added since the targets were listed.
     */
    private static void addTo(Map<Integer, Target> targets, ResultSet results) throws SQLException {
        Target target = targets.get(results.getInt(1));
        if (target != null)
            target.parameters.put(results.getString(2), results.getString(3));
    }

    /**
     * Marks a rotation as started, storing the password about to be set so
     * it survives a crash mid-rotation.
     */
    public void recordStart(int connectionId, String pendingPassword) throws GuacamoleException {

        Map<String, String> values = new LinkedHashMap<>();
        values.put("connection_id", "?");
        values.put("last_attempt", dialect.now());
        values.put("last_status", "'RUNNING'");
        values.put("pending_password", "?");

        try (Connection connection = database.getConnection();
             PreparedStatement statement = connection.prepareStatement(dialect.upsert("pam_rotation_state",
                 Collections.singletonList("connection_id"), values,
                 "last_attempt = EXCLUDED.last_attempt, last_status = EXCLUDED.last_status, last_message = NULL,"
               + " pending_password = EXCLUDED.pending_password"))) {

            statement.setInt(1, connectionId);
            statement.setString(2, secrets.protect(Secrets.PENDING_PASSWORD, pendingPassword));
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

                String parameter;
                if (connectionSecrets.keepsSecrets()) {
                    connectionSecrets.keep(connection, connectionId, PASSWORD_PARAMETER, newPassword);
                    parameter = ConnectionSecrets.token(PASSWORD_PARAMETER, connectionId);
                }
                else {
                    connectionSecrets.forget(connection, connectionId, PASSWORD_PARAMETER);
                    parameter = newPassword;
                }

                setParameter(dialect, connection, connectionId, PASSWORD_PARAMETER, parameter);

                try (PreparedStatement statement = connection.prepareStatement(
                        "UPDATE pam_rotation_state SET last_success = " + dialect.now() + ", last_status = 'SUCCESS',"
                      // The key passed the host key check, so it is trusted
                      + " last_message = ?, host_key = coalesce(?, host_key), pending_password = NULL"
                      + " WHERE connection_id = ?")) {
                    statement.setString(1, message);
                    statement.setString(2, hostKey);
                    statement.setInt(3, connectionId);
                    statement.executeUpdate();
                }

                connection.commit();

            }
            catch (SQLException | GuacamoleException e) {
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

        Map<String, String> values = new LinkedHashMap<>();
        values.put("connection_id", "?");
        values.put("last_attempt", dialect.now());
        values.put("last_status", "?");
        values.put("last_message", "?");
        values.put("host_key", "?");

        try (Connection connection = database.getConnection();
             PreparedStatement statement = connection.prepareStatement(dialect.upsert("pam_rotation_state",
                 Collections.singletonList("connection_id"), values,
                 "last_attempt = EXCLUDED.last_attempt,"
               + " last_status = EXCLUDED.last_status, last_message = EXCLUDED.last_message,"
               // The first key seen is trusted from then on (SSH); a failure
               // never replaces it, so a host presenting another key cannot
               // become trusted by failing
               + " host_key = coalesce(pam_rotation_state.host_key, EXCLUDED.host_key),"
               + " pending_password = CASE WHEN ? = 1 THEN pam_rotation_state.pending_password ELSE NULL END"))) {

            statement.setInt(1, connectionId);
            statement.setString(2, status);
            statement.setString(3, message);
            statement.setString(4, hostKey);
            statement.setInt(5, keepPendingPassword ? 1 : 0);
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
                return results.next() ? secrets.reveal(Secrets.PENDING_PASSWORD, results.getString(1)) : null;
            }

        }
        catch (SQLException e) {
            throw new GuacamoleServerException("Unable to read rotation state.", e);
        }

    }

    /**
     * Stores every pending password in the form {@link Secrets} requires
     * now; connections' own secrets are migrated by
     * {@link ConnectionSecrets#migrate}. Values changed meanwhile are left as
     * they are; values that cannot be decrypted here are skipped, and
     * reported.
     */
    public void migrateSecrets(MigrationReport report) throws GuacamoleException {

        try (Connection connection = database.getConnection();
             PreparedStatement pending = connection.prepareStatement(
                 "SELECT connection_id, pending_password FROM pam_rotation_state WHERE pending_password IS NOT NULL");
             PreparedStatement updatePending = connection.prepareStatement(
                 "UPDATE pam_rotation_state SET pending_password = ? WHERE connection_id = ? AND pending_password = ?")) {

            try (ResultSet results = pending.executeQuery()) {
                while (results.next()) {
                    int id = results.getInt(1);
                    String stored = results.getString(2);
                    if (!secrets.canReveal(stored)) {
                        report.unreadable(stored);
                        continue;
                    }
                    if (!secrets.needsMigration(stored))
                        continue;
                    String wanted = migrated(id, "pending password",
                            () -> secrets.protect(Secrets.PENDING_PASSWORD, stored));
                    if (wanted != null) {
                        updatePending.setString(1, wanted);
                        updatePending.setInt(2, id);
                        updatePending.setString(3, stored);
                        report.changed(updatePending.executeUpdate());
                    }
                }
            }

        }
        catch (SQLException e) {
            throw new GuacamoleServerException("Unable to migrate connection secrets.", e);
        }

    }

    @FunctionalInterface
    private interface Conversion {
        String apply() throws GuacamoleException, SQLException;
    }

    /**
     * The value a stored secret must become, or null if it cannot be
     * decrypted although its key is configured (altered), which is logged.
     */
    private static String migrated(int id, String what, Conversion conversion) throws SQLException {
        try {
            return conversion.apply();
        }
        catch (GuacamoleException e) {
            logger.warn("The {} of connection {} was left as it is: {}", what, id, e.getMessage());
            return null;
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

    /**
     * Rotation states by connection id: of the given connection only, or of
     * all if null.
     */
    private static Map<Integer, State> readStates(Connection connection, Integer connectionId)
            throws SQLException {

        Map<Integer, State> states = new HashMap<>();

        try (PreparedStatement statement = connection.prepareStatement(
                "SELECT connection_id, last_attempt, last_success, last_status, last_message, host_key,"
              + " CASE WHEN pending_password IS NULL THEN 0 ELSE 1 END FROM pam_rotation_state"
              + (connectionId == null ? "" : " WHERE connection_id = ?"))) {

            if (connectionId != null)
                statement.setInt(1, connectionId);

            try (ResultSet results = statement.executeQuery()) {
                while (results.next()) {
                    State state = new State();
                    state.lastAttempt = SqlDialect.getTimestamp(results, 2);
                    state.lastSuccess = SqlDialect.getTimestamp(results, 3);
                    state.status = results.getString(4);
                    state.message = results.getString(5);
                    state.hostKey = results.getString(6);
                    state.pendingPassword = results.getBoolean(7);
                    states.put(results.getInt(1), state);
                }
            }

        }

        return states;

    }

}
