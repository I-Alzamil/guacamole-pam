package org.apache.guacamole.pam.db;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.apache.guacamole.GuacamoleClientException;
import org.apache.guacamole.GuacamoleException;
import org.apache.guacamole.GuacamoleServerException;
import org.apache.guacamole.pam.AccountProtocol;
import org.apache.guacamole.pam.crypto.MigrationReport;
import org.apache.guacamole.pam.crypto.SecretCipher;
import org.apache.guacamole.pam.crypto.Secrets;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Sensitive parameters of connections ({@link #SENSITIVE}: passwords, private
 * keys and passphrases), kept encrypted in "pam_connection_secret" while a
 * key is set. The parameter then holds a token naming its parameter and
 * connection, such as "${PAM_PASSWORD_17}", which the extension replaces with
 * the value when the connection opens, as Guacamole's vault extensions do.
 * Editors of the connection only see the token. Each value is encrypted for
 * its parameter and connection alone, so it cannot be moved elsewhere and
 * used there. Naming the connection lets a balancing group, through which
 * Guacamole opens a connection it chooses itself, be given the values of all
 * its connections.
 *
 * Values containing a Guacamole token, such as "${GUAC_PASSWORD}", stay in
 * the parameter, as Guacamole must replace them. Accounts keep their password
 * here too, although it never reaches guacd: only this extension reads it.
 * Without a key, while decrypting, or before the table exists, values stay
 * in their parameter, as in Guacamole itself; an Account's password is then
 * encrypted there if a key is set (see {@link ConnectionRepository}).
 */
public class ConnectionSecrets {

    private static final Logger logger = LoggerFactory.getLogger(ConnectionSecrets.class);

    /**
     * Guacamole's password fields, and its private keys.
     */
    public static final Set<String> SENSITIVE = Collections.unmodifiableSet(new LinkedHashSet<>(Arrays.asList(
            "password", "passphrase", "private-key", "gateway-password",
            "sftp-password", "sftp-passphrase", "sftp-private-key", "client-key")));

    private static final String TOKEN_PREFIX = "${PAM_";

    private static final String GUACAMOLE_TOKEN = "${";

    private final PamDatabase database;

    private final Secrets secrets;

    public ConnectionSecrets(PamDatabase database, Secrets secrets) {
        this.database = database;
        this.secrets = secrets;
    }

    /**
     * Name of the token standing for a parameter of a connection, such as
     * "PAM_SFTP_PRIVATE_KEY_17".
     */
    public static String tokenName(String parameter, int connectionId) {
        return "PAM_" + parameter.toUpperCase().replace('-', '_') + "_" + connectionId;
    }

    public static String token(String parameter, int connectionId) {
        return "${" + tokenName(parameter, connectionId) + "}";
    }

    private static String purpose(int connectionId, String parameter) {
        return Secrets.CONNECTION_SECRET + ":" + connectionId + ":" + parameter;
    }

    /**
     * Whether a connection with this protocol keeps its sensitive values
     * here. Known once the database was first used.
     */
    public boolean keepsSecrets(String protocol) {
        return secrets.isEncrypting() && database.hasSecretTable();
    }

    /**
     * How the parameters of a connection being saved through Guacamole (the
     * editor, or the API) are stored: the changes to make to them before
     * saving, then, once saved, {@link #complete}.
     */
    public final class Saving {

        /**
         * New values of parameters, null to leave a parameter out.
         */
        private final Map<String, String> changes = new HashMap<>();

        /**
         * Values to keep here, written with their token once the
         * connection's identifier is known.
         */
        private final Map<String, String> kept = new HashMap<>();

        private final Set<String> forgotten = new HashSet<>();

        public Map<String, String> getChanges() {
            return changes;
        }

        public void complete(int connectionId) throws GuacamoleException {

            if (!database.hasSecretTable())
                return;

            try (Connection connection = database.getConnection()) {

                connection.setAutoCommit(false);
                try {
                    for (Map.Entry<String, String> value : kept.entrySet()) {
                        keep(connection, connectionId, value.getKey(), value.getValue());
                        setParameter(connection, connectionId, value.getKey(), token(value.getKey(), connectionId));
                    }
                    for (String parameter : forgotten)
                        forget(connection, connectionId, parameter);
                    connection.commit();
                }
                catch (SQLException | GuacamoleException e) {
                    connection.rollback();
                    throw e;
                }

            }
            catch (SQLException e) {
                throw new GuacamoleServerException("Unable to store the connection's secrets.", e);
            }

        }

    }

    /**
     * Decides how to store the parameters of a connection saved through
     * Guacamole.
     *
     * @param connectionId
     *     The connection's identifier, or null for a new connection.
     *
     * @throws GuacamoleClientException
     *     If a token of this extension is anywhere but in the parameter of
     *     this connection it stands for, a sensitive value is one this
     *     extension encrypted (other than an Account's password stored in
     *     its parameter), or a token stands for a value not kept here.
     */
    public Saving prepare(Integer connectionId, String protocol, Map<String, String> parameters)
            throws GuacamoleException {

        Saving saving = new Saving();
        boolean keeps = keepsSecrets(protocol);
        boolean account = AccountProtocol.NAME.equals(protocol);

        for (Map.Entry<String, String> parameter : parameters.entrySet()) {

            String name = parameter.getKey();
            String value = parameter.getValue();
            boolean sensitive = SENSITIVE.contains(name);

            if (value == null || value.isEmpty()) {
                if (sensitive)
                    saving.forgotten.add(name);
                continue;
            }

            boolean own = sensitive && connectionId != null && value.equals(token(name, connectionId));
            if (!own && value.contains(TOKEN_PREFIX))
                throw new GuacamoleClientException("Tokens such as " + (connectionId == null ? "${PAM_PASSWORD_17}"
                        : token(name, connectionId)) + " can only be used in the field and connection they belong"
                        + " to. Type the value instead.");

            if (!sensitive)
                continue;

            // Guacamole must replace the token, so it stays in the parameter
            if (!own && value.contains(GUACAMOLE_TOKEN)) {
                saving.forgotten.add(name);
                continue;
            }

            boolean accountPassword = account && name.equals(ConnectionRepository.PASSWORD_PARAMETER);

            // Not kept here, an Account's password is encrypted in its parameter
            if (accountPassword && !keeps) {
                saving.changes.put(name, secrets.protect(Secrets.CONNECTION_PASSWORD,
                        own ? require(connectionId, name) : value));
                saving.forgotten.add(name);
                continue;
            }

            // An Account's password still encrypted in its parameter, which
            // the editor sends back until it is moved here
            if (accountPassword && !own && SecretCipher.isEncrypted(value))
                value = secrets.reveal(Secrets.CONNECTION_PASSWORD, value);
            else if (!own && SecretCipher.isEncrypted(value))
                throw new GuacamoleClientException("Encrypted values cannot be copied into a connection. Type the"
                        + " value instead.");

            if (keeps) {
                if (own)
                    require(connectionId, name);
                else {
                    // Left out until the token naming the connection can be written
                    saving.changes.put(name, connectionId == null ? null : token(name, connectionId));
                    saving.kept.put(name, value);
                }
            }
            else {
                if (own)
                    saving.changes.put(name, require(connectionId, name));
                saving.forgotten.add(name);
            }

        }

        return saving;

    }

    /**
     * Tokens and values for opening a connection: those of its parameters
     * that are tokens of this extension.
     *
     * @throws GuacamoleException
     *     If a value is missing, or cannot be decrypted here.
     */
    public Map<String, String> getTokens(int connectionId) throws GuacamoleException {

        List<String> names = new ArrayList<>();

        try (Connection connection = database.getConnection();
             PreparedStatement statement = connection.prepareStatement(
                 "SELECT parameter_name, parameter_value FROM guacamole_connection_parameter"
               + " WHERE connection_id = ? AND parameter_value LIKE '${PAM%'")) {

            statement.setInt(1, connectionId);
            try (ResultSet results = statement.executeQuery()) {
                while (results.next()) {
                    if (results.getString(2).equals(token(results.getString(1), connectionId)))
                        names.add(results.getString(1));
                }
            }

        }
        catch (SQLException e) {
            throw new GuacamoleServerException("Unable to read the connection's parameters.", e);
        }

        Map<String, String> tokens = new HashMap<>();
        for (String name : names)
            tokens.put(tokenName(name, connectionId), require(connectionId, name));
        return tokens;

    }

    /**
     * The value of a stored parameter: kept here if it is its token, an
     * Account's password in its parameter decrypted, or as it is.
     */
    String resolve(int connectionId, String parameter, String value) throws GuacamoleException {
        if (SENSITIVE.contains(parameter) && token(parameter, connectionId).equals(value))
            return require(connectionId, parameter);
        if (ConnectionRepository.PASSWORD_PARAMETER.equals(parameter))
            return secrets.reveal(Secrets.CONNECTION_PASSWORD, value);
        return value;
    }

    /**
     * The value kept for a parameter of the connection, which must be there.
     */
    private String require(int connectionId, String parameter) throws GuacamoleException {
        String value = database.hasSecretTable() ? read(connectionId, parameter) : null;
        if (value == null)
            throw new GuacamoleServerException("The " + parameter + " of connection " + connectionId + " is "
                    + token(parameter, connectionId) + ", but the extension keeps no value for it. Set it again.");
        return value;
    }

    private String read(int connectionId, String parameter) throws GuacamoleException {
        try (Connection connection = database.getConnection()) {
            String stored = readRaw(connection, connectionId, parameter);
            return stored == null ? null : secrets.reveal(purpose(connectionId, parameter), stored);
        }
        catch (SQLException e) {
            throw new GuacamoleServerException("Unable to read the connection's secrets.", e);
        }
    }

    private static String readRaw(Connection connection, int connectionId, String parameter) throws SQLException {
        try (PreparedStatement statement = connection.prepareStatement(
                "SELECT value FROM pam_connection_secret WHERE connection_id = ? AND parameter_name = ?")) {
            statement.setInt(1, connectionId);
            statement.setString(2, parameter);
            try (ResultSet results = statement.executeQuery()) {
                return results.next() ? results.getString(1) : null;
            }
        }
    }

    /**
     * Keeps a value, encrypted, within the caller's transaction.
     */
    void keep(Connection connection, int connectionId, String parameter, String value)
            throws SQLException, GuacamoleException {
        try (PreparedStatement statement = connection.prepareStatement(
                "INSERT INTO pam_connection_secret (connection_id, parameter_name, value) VALUES (?, ?, ?)"
              + " ON CONFLICT (connection_id, parameter_name) DO UPDATE SET value = EXCLUDED.value")) {
            statement.setInt(1, connectionId);
            statement.setString(2, parameter);
            statement.setString(3, secrets.protect(purpose(connectionId, parameter), value));
            statement.executeUpdate();
        }
    }

    void forget(Connection connection, int connectionId, String parameter) throws SQLException {
        if (!database.hasSecretTable())
            return;
        try (PreparedStatement statement = connection.prepareStatement(
                "DELETE FROM pam_connection_secret WHERE connection_id = ? AND parameter_name = ?")) {
            statement.setInt(1, connectionId);
            statement.setString(2, parameter);
            statement.executeUpdate();
        }
    }

    private static void setParameter(Connection connection, int connectionId, String parameter, String value)
            throws SQLException {
        try (PreparedStatement statement = connection.prepareStatement(
                "INSERT INTO guacamole_connection_parameter (connection_id, parameter_name, parameter_value)"
              + " VALUES (?, ?, ?) ON CONFLICT (connection_id, parameter_name)"
              + " DO UPDATE SET parameter_value = EXCLUDED.parameter_value")) {
            statement.setInt(1, connectionId);
            statement.setString(2, parameter);
            statement.setString(3, value);
            statement.executeUpdate();
        }
    }

    /**
     * Moves sensitive values to where {@link #keepsSecrets} says they belong:
     * here, or back into their parameter (while decrypting, or without a
     * key). Then encrypts again what an earlier key encrypted,
     * and forgets values no parameter refers to. Values changed meanwhile
     * are left as they are.
     */
    public void migrate(MigrationReport report) throws GuacamoleException {

        if (!database.hasSecretTable())
            return;

        try (Connection connection = database.getConnection()) {

            List<Misplaced> misplaced = new ArrayList<>();
            try (PreparedStatement statement = connection.prepareStatement(
                    "SELECT p.connection_id, c.protocol, p.parameter_name, p.parameter_value"
                  + " FROM guacamole_connection_parameter p JOIN guacamole_connection c"
                  + "   ON c.connection_id = p.connection_id"
                  + " WHERE p.parameter_name = ANY (?) AND p.parameter_value <> ''")) {
                statement.setArray(1, connection.createArrayOf("varchar", SENSITIVE.toArray()));
                try (ResultSet results = statement.executeQuery()) {
                    while (results.next()) {
                        int id = results.getInt(1);
                        String name = results.getString(3);
                        String value = results.getString(4);
                        boolean own = value.equals(token(name, id));
                        boolean keeps = keepsSecrets(results.getString(2));
                        // Encrypted in its parameter, only an Account's password
                        // is moved: another value was pasted there, and stays put
                        boolean movable = !SecretCipher.isEncrypted(value)
                                || (AccountProtocol.NAME.equals(results.getString(2))
                                    && name.equals(ConnectionRepository.PASSWORD_PARAMETER));
                        // Guacamole tokens stay put
                        if (keeps && !own && !value.contains(GUACAMOLE_TOKEN) && movable)
                            misplaced.add(new Misplaced(id, name, value, true));
                        else if (!keeps && own)
                            misplaced.add(new Misplaced(id, name, value, false));
                    }
                }
            }

            for (Misplaced value : misplaced)
                move(connection, value, report);

            reencrypt(connection, report);

        }
        catch (SQLException e) {
            throw new GuacamoleServerException("Unable to migrate the secrets of connections.", e);
        }

    }

    private static final class Misplaced {

        private final int connectionId;
        private final String parameter;
        private final String value;
        private final boolean belongsHere;

        Misplaced(int connectionId, String parameter, String value, boolean belongsHere) {
            this.connectionId = connectionId;
            this.parameter = parameter;
            this.value = value;
            this.belongsHere = belongsHere;
        }

    }

    /**
     * Moves one value here, or back into its parameter, in one transaction
     * that changes nothing if the parameter changed.
     */
    private void move(Connection connection, Misplaced misplaced, MigrationReport report)
            throws SQLException, GuacamoleException {

        int id = misplaced.connectionId;
        String plaintext = misplaced.value;

        // An Account's password, encrypted in its parameter
        if (misplaced.belongsHere && SecretCipher.isEncrypted(plaintext)) {
            if (!secrets.canReveal(plaintext)) {
                report.unreadable(plaintext);
                return;
            }
            try {
                plaintext = secrets.reveal(Secrets.CONNECTION_PASSWORD, plaintext);
            }
            catch (GuacamoleException e) {
                logger.warn("The password of connection {} was left as it is: {}", id, e.getMessage());
                return;
            }
        }

        if (!misplaced.belongsHere) {
            String stored = readRaw(connection, id, misplaced.parameter);
            if (stored == null)
                return;
            if (!secrets.canReveal(stored)) {
                report.unreadable(stored);
                return;
            }
            plaintext = secrets.reveal(purpose(id, misplaced.parameter), stored);
        }

        connection.setAutoCommit(false);
        try {

            if (misplaced.belongsHere)
                keep(connection, id, misplaced.parameter, plaintext);
            else
                forget(connection, id, misplaced.parameter);

            try (PreparedStatement statement = connection.prepareStatement(
                    "UPDATE guacamole_connection_parameter SET parameter_value = ?"
                  + " WHERE connection_id = ? AND parameter_name = ? AND parameter_value = ?")) {
                statement.setString(1, misplaced.belongsHere ? token(misplaced.parameter, id) : plaintext);
                statement.setInt(2, id);
                statement.setString(3, misplaced.parameter);
                statement.setString(4, misplaced.value);
                if (statement.executeUpdate() == 0) {
                    connection.rollback();
                    return;
                }
            }

            connection.commit();
            report.changed(1);

        }
        catch (SQLException | GuacamoleException e) {
            connection.rollback();
            throw e;
        }
        finally {
            connection.setAutoCommit(true);
        }

    }

    private void reencrypt(Connection connection, MigrationReport report) throws SQLException, GuacamoleException {

        List<Misplaced> kept = new ArrayList<>();
        try (PreparedStatement statement = connection.prepareStatement(
                "SELECT s.connection_id, s.parameter_name, s.value, p.parameter_value FROM pam_connection_secret s"
              + " LEFT JOIN guacamole_connection_parameter p"
              + "   ON p.connection_id = s.connection_id AND p.parameter_name = s.parameter_name");
             PreparedStatement forget = connection.prepareStatement(
                 "DELETE FROM pam_connection_secret WHERE connection_id = ? AND parameter_name = ? AND value = ?")) {

            try (ResultSet results = statement.executeQuery()) {
                while (results.next()) {
                    int id = results.getInt(1);
                    String name = results.getString(2);
                    if (token(name, id).equals(results.getString(4)))
                        kept.add(new Misplaced(id, name, results.getString(3), true));
                    else {
                        // No parameter refers to it any more
                        forget.setInt(1, id);
                        forget.setString(2, name);
                        forget.setString(3, results.getString(3));
                        report.changed(forget.executeUpdate());
                    }
                }
            }

        }

        try (PreparedStatement update = connection.prepareStatement(
                "UPDATE pam_connection_secret SET value = ?"
              + " WHERE connection_id = ? AND parameter_name = ? AND value = ?")) {
            for (Misplaced value : kept) {
                if (!secrets.canReveal(value.value)) {
                    report.unreadable(value.value);
                    continue;
                }
                if (!secrets.needsMigration(value.value))
                    continue;
                update.setString(1, secrets.protect(purpose(value.connectionId, value.parameter), value.value));
                update.setInt(2, value.connectionId);
                update.setString(3, value.parameter);
                update.setString(4, value.value);
                report.changed(update.executeUpdate());
            }
        }

    }

}
