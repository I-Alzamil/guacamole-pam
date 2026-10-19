package org.apache.guacamole.pam.db;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.HashMap;
import java.util.Map;

import org.apache.guacamole.GuacamoleClientException;
import org.apache.guacamole.GuacamoleException;
import org.apache.guacamole.GuacamoleServerException;
import org.apache.guacamole.pam.AccountProtocol;
import org.apache.guacamole.pam.PamAttributes;
import org.apache.guacamole.pam.crypto.MigrationReport;
import org.apache.guacamole.pam.crypto.SecretCipher;
import org.apache.guacamole.pam.crypto.Secrets;

/**
 * Passwords of managed connections (with a platform, other than Accounts),
 * kept encrypted in "pam_connection_password" while a key is set. Their
 * "password" parameter is then the token {@link #TOKEN}, which the
 * extension replaces with the password when the connection opens, as
 * Guacamole's vault extensions do. Editors of the connection only see the
 * token. Each password is encrypted for its connection alone, so it cannot
 * be moved to another connection and used there.
 *
 * Without a key, while decrypting, or before the table exists, passwords
 * stay in the parameter, as in Guacamole itself.
 */
public class PasswordStore {

    public static final String TOKEN_NAME = "PAM_PASSWORD";

    public static final String TOKEN = "${" + TOKEN_NAME + "}";

    static final String PASSWORD_PARAMETER = "password";

    private final PamDatabase database;

    private final Secrets secrets;

    public PasswordStore(PamDatabase database, Secrets secrets) {
        this.database = database;
        this.secrets = secrets;
    }

    private static String purpose(int connectionId) {
        return Secrets.MANAGED_PASSWORD + ":" + connectionId;
    }

    /**
     * Whether the password of such a connection is kept here, rather than
     * in its parameter. Known once the database was first used.
     */
    public boolean keepsPassword(String protocol, boolean managed) {
        return managed && !AccountProtocol.NAME.equals(protocol) && secrets.isEncrypting()
                && database.hasPasswordTable();
    }

    /**
     * How a password being saved through Guacamole (the editor, or the
     * API) is stored: the value of its parameter, then, once the connection
     * is saved and has an identifier, {@link #complete}.
     */
    public final class Saving {

        private final String parameter;

        /**
         * The password to keep here, or null to keep what is kept.
         */
        private final String kept;

        /**
         * Whether to forget the password kept here.
         */
        private final boolean forget;

        private Saving(String parameter, String kept, boolean forget) {
            this.parameter = parameter;
            this.kept = kept;
            this.forget = forget;
        }

        public String getParameter() {
            return parameter;
        }

        public void complete(int connectionId) throws GuacamoleException {
            if (kept == null && !forget)
                return;
            try (Connection connection = database.getConnection()) {
                if (kept != null)
                    keep(connection, connectionId, kept);
                else
                    forget(connection, connectionId);
            }
            catch (SQLException e) {
                throw new GuacamoleServerException("Unable to store the connection's password.", e);
            }
        }

    }

    /**
     * Decides how to store a password saved through Guacamole.
     *
     * @param connectionId
     *     The connection's identifier, or null for a new connection.
     *
     * @throws GuacamoleClientException
     *     If the password is a value this extension encrypted, other than an
     *     Account's (encrypted values are not copied between connections), or
     *     the token while the connection has no password kept here.
     */
    public Saving prepare(Integer connectionId, String protocol, boolean managed, String password)
            throws GuacamoleException {

        boolean account = AccountProtocol.NAME.equals(protocol);
        boolean available = database.hasPasswordTable();

        if (password == null || password.isEmpty())
            return new Saving(password, null, available);

        // The token always means this connection's own kept password
        String plaintext;
        boolean unchanged = TOKEN.equals(password);
        if (unchanged) {
            plaintext = connectionId == null || !available ? null : read(connectionId);
            if (plaintext == null)
                throw new GuacamoleClientException(TOKEN + " stands for the password the extension keeps for a"
                        + " connection, and this connection has none. Type the password instead.");
        }
        else if (SecretCipher.isEncrypted(password)) {
            if (!account)
                throw new GuacamoleClientException("Encrypted passwords cannot be copied into a connection."
                        + " Type the password instead.");
            plaintext = secrets.reveal(Secrets.CONNECTION_PASSWORD, password);
        }
        else
            plaintext = password;

        // An Account's encrypted password is kept as it is when unchanged
        if (account)
            return new Saving(secrets.protect(Secrets.CONNECTION_PASSWORD, unchanged ? plaintext : password),
                    null, available);

        if (keepsPassword(protocol, managed))
            return new Saving(TOKEN, unchanged ? null : plaintext, false);

        return new Saving(plaintext, null, available);

    }

    /**
     * The password to open a connection with, if its parameter is the
     * token, or null if the parameter needs nothing.
     *
     * @throws GuacamoleException
     *     If the password is missing, or cannot be decrypted here.
     */
    public String getForConnect(int connectionId) throws GuacamoleException {

        try (Connection connection = database.getConnection();
             PreparedStatement statement = connection.prepareStatement(
                 "SELECT parameter_value FROM guacamole_connection_parameter"
               + " WHERE connection_id = ? AND parameter_name = ?")) {

            statement.setInt(1, connectionId);
            statement.setString(2, PASSWORD_PARAMETER);
            try (ResultSet results = statement.executeQuery()) {
                if (!results.next() || !TOKEN.equals(results.getString(1)))
                    return null;
            }

        }
        catch (SQLException e) {
            throw new GuacamoleServerException("Unable to read the connection's password.", e);
        }

        return require(connectionId);

    }

    /**
     * The plaintext of a stored "password" parameter.
     */
    String resolve(int connectionId, String parameter) throws GuacamoleException {
        return TOKEN.equals(parameter) ? require(connectionId)
                : secrets.reveal(Secrets.CONNECTION_PASSWORD, parameter);
    }

    /**
     * The password kept for the connection, which must be there.
     */
    private String require(int connectionId) throws GuacamoleException {
        String password = database.hasPasswordTable() ? read(connectionId) : null;
        if (password == null)
            throw new GuacamoleServerException("The password of connection " + connectionId + " is " + TOKEN
                    + ", but the extension keeps no password for it. Set the password again.");
        return password;
    }

    /**
     * The password kept for the connection, or null.
     */
    private String read(int connectionId) throws GuacamoleException {

        try (Connection connection = database.getConnection();
             PreparedStatement statement = connection.prepareStatement(
                 "SELECT password FROM pam_connection_password WHERE connection_id = ?")) {

            statement.setInt(1, connectionId);
            try (ResultSet results = statement.executeQuery()) {
                return results.next() ? secrets.reveal(purpose(connectionId), results.getString(1)) : null;
            }

        }
        catch (SQLException e) {
            throw new GuacamoleServerException("Unable to read the connection's password.", e);
        }

    }

    /**
     * Keeps the connection's password, encrypted, within the caller's
     * transaction.
     */
    void keep(Connection connection, int connectionId, String password) throws SQLException, GuacamoleException {
        try (PreparedStatement statement = connection.prepareStatement(
                "INSERT INTO pam_connection_password (connection_id, password) VALUES (?, ?)"
              + " ON CONFLICT (connection_id) DO UPDATE SET password = EXCLUDED.password")) {
            statement.setInt(1, connectionId);
            statement.setString(2, secrets.protect(purpose(connectionId), password));
            statement.executeUpdate();
        }
    }

    void forget(Connection connection, int connectionId) throws SQLException {
        if (!database.hasPasswordTable())
            return;
        try (PreparedStatement statement = connection.prepareStatement(
                "DELETE FROM pam_connection_password WHERE connection_id = ?")) {
            statement.setInt(1, connectionId);
            statement.executeUpdate();
        }
    }

    /**
     * Moves passwords to where {@link #keepsPassword} says they belong: into
     * this store, or back into their parameter (while decrypting, without a
     * key, or once a connection is no longer managed). Then encrypts again
     * what an earlier key encrypted, and forgets passwords no parameter
     * refers to. Values changed meanwhile are left as they are.
     */
    public void migrate(MigrationReport report) throws GuacamoleException {

        if (!database.hasPasswordTable())
            return;

        try (Connection connection = database.getConnection()) {

            // Passwords not where they belong: in a parameter while they
            // belong here, or the token while they do not
            Map<Integer, Misplaced> misplaced = new HashMap<>();
            try (PreparedStatement statement = connection.prepareStatement(
                    "SELECT c.connection_id, c.protocol, p.parameter_value,"
                  + " EXISTS (SELECT 1 FROM guacamole_connection_attribute a WHERE a.connection_id = c.connection_id"
                  + "   AND a.attribute_name = ? AND a.attribute_value <> '')"
                  + " FROM guacamole_connection c JOIN guacamole_connection_parameter p"
                  + "   ON p.connection_id = c.connection_id AND p.parameter_name = ?"
                  + " WHERE p.parameter_value <> ''")) {
                statement.setString(1, PamAttributes.PLATFORM);
                statement.setString(2, PASSWORD_PARAMETER);
                try (ResultSet results = statement.executeQuery()) {
                    while (results.next()) {
                        boolean belongsHere = keepsPassword(results.getString(2), results.getBoolean(4));
                        if (belongsHere != TOKEN.equals(results.getString(3)))
                            misplaced.put(results.getInt(1), new Misplaced(results.getString(3), belongsHere));
                    }
                }
            }

            for (Map.Entry<Integer, Misplaced> entry : misplaced.entrySet())
                move(connection, entry.getKey(), entry.getValue().parameter, entry.getValue().belongsHere, report);

            reencrypt(connection, report);

        }
        catch (SQLException e) {
            throw new GuacamoleServerException("Unable to migrate the passwords of managed connections.", e);
        }

    }

    private static final class Misplaced {

        private final String parameter;

        private final boolean belongsHere;

        Misplaced(String parameter, boolean belongsHere) {
            this.parameter = parameter;
            this.belongsHere = belongsHere;
        }

    }

    /**
     * Moves one password into this store, or back into its parameter, in
     * one transaction that changes nothing if the parameter changed.
     */
    private void move(Connection connection, int connectionId, String parameter, boolean intoStore,
            MigrationReport report) throws SQLException, GuacamoleException {

        String stored = intoStore ? parameter : readRaw(connection, connectionId);
        if (stored == null)
            return;
        if (!secrets.canReveal(stored)) {
            report.unreadable(stored);
            return;
        }

        connection.setAutoCommit(false);
        try {

            String plaintext = intoStore ? secrets.reveal(Secrets.CONNECTION_PASSWORD, parameter)
                    : secrets.reveal(purpose(connectionId), stored);

            if (intoStore)
                keep(connection, connectionId, plaintext);
            else
                forget(connection, connectionId);

            try (PreparedStatement statement = connection.prepareStatement(
                    "UPDATE guacamole_connection_parameter SET parameter_value = ?"
                  + " WHERE connection_id = ? AND parameter_name = ? AND parameter_value = ?")) {
                statement.setString(1, intoStore ? TOKEN : plaintext);
                statement.setInt(2, connectionId);
                statement.setString(3, PASSWORD_PARAMETER);
                statement.setString(4, parameter);
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

    private String readRaw(Connection connection, int connectionId) throws SQLException {
        try (PreparedStatement statement = connection.prepareStatement(
                "SELECT password FROM pam_connection_password WHERE connection_id = ?")) {
            statement.setInt(1, connectionId);
            try (ResultSet results = statement.executeQuery()) {
                return results.next() ? results.getString(1) : null;
            }
        }
    }

    private void reencrypt(Connection connection, MigrationReport report) throws SQLException, GuacamoleException {

        Map<Integer, String> kept = new HashMap<>();
        try (PreparedStatement statement = connection.prepareStatement(
                "SELECT k.connection_id, k.password, p.parameter_value = ? FROM pam_connection_password k"
              + " LEFT JOIN guacamole_connection_parameter p"
              + "   ON p.connection_id = k.connection_id AND p.parameter_name = ?");
             PreparedStatement forget = connection.prepareStatement(
                 "DELETE FROM pam_connection_password WHERE connection_id = ? AND password = ?")) {

            statement.setString(1, TOKEN);
            statement.setString(2, PASSWORD_PARAMETER);
            try (ResultSet results = statement.executeQuery()) {
                while (results.next()) {
                    if (results.getBoolean(3))
                        kept.put(results.getInt(1), results.getString(2));
                    else {
                        // No parameter refers to it any more
                        forget.setInt(1, results.getInt(1));
                        forget.setString(2, results.getString(2));
                        report.changed(forget.executeUpdate());
                    }
                }
            }

        }

        try (PreparedStatement update = connection.prepareStatement(
                "UPDATE pam_connection_password SET password = ? WHERE connection_id = ? AND password = ?")) {
            for (Map.Entry<Integer, String> entry : kept.entrySet()) {
                if (!secrets.canReveal(entry.getValue())) {
                    report.unreadable(entry.getValue());
                    continue;
                }
                if (!secrets.needsMigration(entry.getValue()))
                    continue;
                update.setString(1, secrets.protect(purpose(entry.getKey()), entry.getValue()));
                update.setInt(2, entry.getKey());
                update.setString(3, entry.getValue());
                report.changed(update.executeUpdate());
            }
        }

    }

}
