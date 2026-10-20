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
import org.apache.guacamole.pam.crypto.MigrationReport;
import org.apache.guacamole.pam.crypto.SecretCipher;
import org.apache.guacamole.pam.crypto.Secrets;
import org.apache.guacamole.protocol.GuacamoleConfiguration;

/**
 * Sensitive parameters of connections ({@link #SENSITIVE}: passwords, private
 * keys and passphrases), kept encrypted in "pam_connection_secret" while a
 * key is set. The parameter then holds a token naming its parameter and
 * connection, such as "${PAM_PASSWORD_17}", which the extension replaces with
 * the value when the connection opens, as Guacamole's vault extensions do.
 * Editors of the connection see {@link #MASK} in its place, which saving
 * unchanged keeps the value, as the token itself does. Each value is encrypted for
 * its parameter and connection alone, so it cannot be moved elsewhere and
 * used there. Naming the connection lets a balancing group, through which
 * Guacamole opens a connection it chooses itself, be given the values of all
 * its connections.
 *
 * Values containing a Guacamole token, such as "${GUAC_PASSWORD}", stay in
 * the parameter, as Guacamole must replace them. Accounts keep their password
 * here too, although it never reaches guacd: only this extension reads it.
 * Without a key, or while decrypting, values stay in their parameter, as in
 * Guacamole itself.
 */
public class ConnectionSecrets {

    /**
     * Guacamole's password fields, and its private keys.
     */
    public static final Set<String> SENSITIVE = Collections.unmodifiableSet(new LinkedHashSet<>(Arrays.asList(
            "password", "passphrase", "private-key", "gateway-password",
            "sftp-password", "sftp-passphrase", "sftp-private-key", "client-key")));

    private static final String TOKEN_PREFIX = "${PAM_";

    /**
     * What editors see in place of a value kept here, masked as any
     * password: it looks set, and tells nothing of where the value is. It
     * only ever stands for the value of its own field and connection. The
     * platform editor shows stored platform passwords the same way
     * (STORED_SECRET of guacSettingsPamPlatforms.js).
     */
    public static final String MASK = "********";

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

    /**
     * The configuration of a connection as its editors see it: its tokens
     * are {@link #MASK}. Parameters are only read, and masked, when asked
     * for: the database's configurations query them only then, so listing
     * connections, which reads their protocol, stays one query.
     */
    public static GuacamoleConfiguration masked(GuacamoleConfiguration configuration, int connectionId) {
        return new MaskedConfiguration(configuration, connectionId);
    }

    /**
     * See {@link #masked}. Changes go to the configuration it masks.
     */
    private static final class MaskedConfiguration extends GuacamoleConfiguration {

        private static final long serialVersionUID = 1L;

        private final GuacamoleConfiguration configuration;

        private final int connectionId;

        /**
         * The parameters, masked, once read.
         */
        private Map<String, String> parameters;

        MaskedConfiguration(GuacamoleConfiguration configuration, int connectionId) {
            this.configuration = configuration;
            this.connectionId = connectionId;
        }

        @Override
        public String getConnectionID() {
            return configuration.getConnectionID();
        }

        @Override
        public void setConnectionID(String connectionID) {
            configuration.setConnectionID(connectionID);
        }

        @Override
        public String getProtocol() {
            return configuration.getProtocol();
        }

        @Override
        public void setProtocol(String protocol) {
            configuration.setProtocol(protocol);
        }

        @Override
        public Map<String, String> getParameters() {
            if (parameters == null) {
                Map<String, String> read = new HashMap<>(configuration.getParameters());
                for (String parameter : SENSITIVE) {
                    if (token(parameter, connectionId).equals(read.get(parameter)))
                        read.put(parameter, MASK);
                }
                parameters = Collections.unmodifiableMap(read);
            }
            return parameters;
        }

        @Override
        public String getParameter(String name) {
            return getParameters().get(name);
        }

        @Override
        public Set<String> getParameterNames() {
            return getParameters().keySet();
        }

        @Override
        public void setParameter(String name, String value) {
            configuration.setParameter(name, value);
            parameters = null;
        }

        @Override
        public void unsetParameter(String name) {
            configuration.unsetParameter(name);
            parameters = null;
        }

        @Override
        public void setParameters(Map<String, String> parameters) {
            configuration.setParameters(parameters);
            this.parameters = null;
        }

    }

    private static String purpose(int connectionId, String parameter) {
        return Secrets.CONNECTION_SECRET + ":" + connectionId + ":" + parameter;
    }

    /**
     * Whether sensitive values are kept here: while a key is set.
     */
    public boolean keepsSecrets() {
        return secrets.isEncrypting();
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

            if (kept.isEmpty() && forgotten.isEmpty())
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
     *     extension encrypted, or a token stands for a value not kept here.
     */
    public Saving prepare(Integer connectionId, String protocol, Map<String, String> parameters)
            throws GuacamoleException {

        Saving saving = new Saving();
        boolean keeps = keepsSecrets();

        // Only read where a value is this connection's own token, which an
        // existing connection alone has
        int id = connectionId == null ? -1 : connectionId;

        for (Map.Entry<String, String> parameter : parameters.entrySet()) {

            String name = parameter.getKey();
            String value = parameter.getValue();
            boolean sensitive = SENSITIVE.contains(name);

            if (value == null || value.isEmpty()) {
                if (sensitive)
                    saving.forgotten.add(name);
                continue;
            }

            // The mask an editor saw keeps the value, as the token would
            if (sensitive && MASK.equals(value)) {
                if (connectionId == null || !holdsToken(connectionId, name))
                    throw new GuacamoleClientException("The " + name + " is " + MASK + ", which only stands for a"
                            + " value already stored in the same field of the same connection, so it cannot be"
                            + " copied. Type the " + name + " instead.");
                value = token(name, connectionId);
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

            if (!own && SecretCipher.isEncrypted(value))
                throw new GuacamoleClientException("Encrypted values cannot be copied into a connection. Type the"
                        + " value instead.");

            if (keeps) {
                if (own) {
                    // Written back, as the editor sent the mask in its place
                    require(id, name);
                    saving.changes.put(name, token(name, id));
                }
                else {
                    // Left out until the token naming the connection can be written
                    saving.changes.put(name, connectionId == null ? null : token(name, connectionId));
                    saving.kept.put(name, value);
                }
            }
            else {
                if (own)
                    saving.changes.put(name, require(id, name));
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
     * The value of a stored parameter, read through the caller's database
     * connection: kept here if it is its token, or as it is.
     */
    String resolve(Connection connection, int connectionId, String parameter, String value)
            throws GuacamoleException {
        if (SENSITIVE.contains(parameter) && token(parameter, connectionId).equals(value))
            return require(connection, connectionId, parameter);
        return value;
    }

    /**
     * The value kept for a parameter of the connection, which must be there.
     */
    private String require(int connectionId, String parameter) throws GuacamoleException {
        try (Connection connection = database.getConnection()) {
            return require(connection, connectionId, parameter);
        }
        catch (SQLException e) {
            throw new GuacamoleServerException("Unable to read the connection's secrets.", e);
        }
    }

    private String require(Connection connection, int connectionId, String parameter) throws GuacamoleException {

        String stored;
        try {
            stored = readRaw(connection, connectionId, parameter);
        }
        catch (SQLException e) {
            throw new GuacamoleServerException("Unable to read the connection's secrets.", e);
        }

        if (stored == null)
            throw new GuacamoleServerException("The " + parameter + " of connection " + connectionId + " is "
                    + token(parameter, connectionId) + ", but the extension keeps no value for it. Set it again.");
        return secrets.reveal(purpose(connectionId, parameter), stored);

    }

    /**
     * Whether the stored parameter of a connection is its token.
     */
    private boolean holdsToken(int connectionId, String parameter) throws GuacamoleException {

        try (Connection connection = database.getConnection();
             PreparedStatement statement = connection.prepareStatement(
                 "SELECT parameter_value FROM guacamole_connection_parameter"
               + " WHERE connection_id = ? AND parameter_name = ?")) {

            statement.setInt(1, connectionId);
            statement.setString(2, parameter);
            try (ResultSet results = statement.executeQuery()) {
                return results.next() && token(parameter, connectionId).equals(results.getString(1));
            }

        }
        catch (SQLException e) {
            throw new GuacamoleServerException("Unable to read the connection's parameters.", e);
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

        boolean keeps = keepsSecrets();

        try (Connection connection = database.getConnection()) {

            List<Misplaced> misplaced = new ArrayList<>();
            try (PreparedStatement statement = connection.prepareStatement(
                    "SELECT connection_id, parameter_name, parameter_value FROM guacamole_connection_parameter"
                  + " WHERE parameter_name = ANY (?) AND parameter_value <> ''")) {
                statement.setArray(1, connection.createArrayOf("varchar", SENSITIVE.toArray()));
                try (ResultSet results = statement.executeQuery()) {
                    while (results.next()) {
                        int id = results.getInt(1);
                        String name = results.getString(2);
                        String value = results.getString(3);
                        boolean own = value.equals(token(name, id));
                        // Guacamole tokens stay put, and so does an encrypted
                        // value written there by hand: it is no plaintext
                        if (keeps && !own && !value.contains(GUACAMOLE_TOKEN) && !SecretCipher.isEncrypted(value))
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
