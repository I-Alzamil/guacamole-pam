package org.apache.guacamole.pam.database;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.sql.Connection;
import java.sql.Driver;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.Base64;
import java.util.Properties;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.crypto.Mac;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

import org.apache.guacamole.pam.database.DatabaseTarget.Kind;
import org.apache.guacamole.pam.management.PlatformTestResult;
import org.apache.guacamole.pam.rotation.ChangeOutcome;

/**
 * Changes and checks passwords of database accounts, over the JDBC driver
 * of each database installed with Guacamole (in GUACAMOLE_HOME/lib), as an
 * administrator account or as the account itself:
 *
 * - PostgreSQL: ALTER ROLE ... PASSWORD, given a SCRAM-SHA-256 verifier
 *   computed here, so the password itself never reaches the server or its
 *   logs. An administrator needs CREATEROLE and, since PostgreSQL 16, the
 *   ADMIN option on the role (or to be a superuser).
 * - MySQL: ALTER USER ... IDENTIFIED BY, which MySQL masks in its logs; as
 *   the account itself, with REPLACE and the current password, required
 *   wherever "password_require_current" is on. An administrator needs
 *   CREATE USER.
 * - MariaDB: keeping each account's authentication method, which MariaDB
 *   would otherwise replace: for mysql_native_password accounts, their hash,
 *   so the password stays out of its logs, which would show it in the
 *   clear; for others (ed25519...), the password. With SET PASSWORD as the
 *   account itself (ALTER USER needs CREATE USER even for one's own
 *   account), ALTER USER as an administrator, who needs CREATE USER and,
 *   to read accounts' methods, SELECT on mysql.global_priv.
 * - SQL Server: ALTER LOGIN ... WITH PASSWORD, with OLD_PASSWORD as the
 *   login itself. An administrator needs ALTER ANY LOGIN, and CONTROL SERVER
 *   for sysadmin logins.
 */
public class DatabaseClient {

    private static final String POSTGRESQL_DRIVER = "org.postgresql.Driver";
    private static final String MARIADB_DRIVER = "org.mariadb.jdbc.Driver";
    private static final String MYSQL_DRIVER = "com.mysql.cj.jdbc.Driver";
    private static final String SQLSERVER_DRIVER = "com.microsoft.sqlserver.jdbc.SQLServerDriver";

    /**
     * How long to wait for a connection, in seconds.
     */
    private static final int CONNECT_TIMEOUT_SECONDS = 10;

    /**
     * How long to wait for each answer, in seconds.
     */
    private static final int SOCKET_TIMEOUT_SECONDS = 30;

    /**
     * Iterations of the SCRAM-SHA-256 verifiers set on PostgreSQL, as
     * PostgreSQL itself uses by default.
     */
    private static final int SCRAM_ITERATIONS = 4096;

    /**
     * Account the test without an administrator signs in as, expecting to be
     * refused.
     */
    private static final String TEST_USERNAME = "guacamole-pam-test";

    private static final SecureRandom RANDOM = new SecureRandom();

    /**
     * Sets the account's new password, as the administrator account if the
     * platform has one, otherwise as the account itself. Never throws.
     */
    public ChangeOutcome changePassword(DatabaseTarget target, String newPassword) {

        boolean admin = target.getAdminUsername() != null;
        if (!admin && target.getPassword() == null)
            return new ChangeOutcome(false, false, "The account has no current password and the platform no"
                    + " administrator account.", null, null);

        Connection connection;
        try {
            connection = admin ? connect(target, target.getAdminUsername(), target.getAdminPassword())
                    : connect(target, target.getUsername(), target.getPassword());
        }
        catch (SQLException e) {
            return new ChangeOutcome(false, false, isAuthenticationFailure(e)
                    ? (admin ? "The " + target.describe() + " refused the administrator account's password."
                             : "The " + target.describe() + " refused the account's current password.")
                    : describe(target, e), null, null);
        }
        catch (DriverMissing e) {
            return new ChangeOutcome(false, false, e.getMessage(), null, null);
        }

        try {
            boolean mariadb = target.getKind() == Kind.MYSQL && isMariaDb(connection);
            setPassword(connection, target, mariadb, admin, newPassword);
            return new ChangeOutcome(true, true, null, null, null);
        }
        catch (SQLException e) {
            // Refused by the server, which changed nothing, unless the
            // connection was lost meanwhile
            boolean lost = e.getSQLState() != null && e.getSQLState().startsWith("08");
            return new ChangeOutcome(false, lost, describeRefusal(target, admin, e), null, null);
        }
        finally {
            close(connection);
        }

    }

    /**
     * Returns whether the server accepts the given password of the account,
     * by signing in with it.
     *
     * @throws Exception
     *     If the server cannot be reached or trusted, or the driver is
     *     missing.
     */
    public boolean acceptsPassword(DatabaseTarget target, String password) throws Exception {
        try {
            close(connect(target, target.getUsername(), password == null ? "" : password));
            return true;
        }
        catch (SQLException e) {
            if (isAuthenticationFailure(e))
                return false;
            throw new Exception(describe(target, e), e);
        }
    }

    /**
     * Checks that the server can be reached and trusted, and that the
     * administrator account, if any, signs in and may change passwords,
     * without changing any. Without an administrator account, signs in as
     * an account that does not exist, which the server must refuse (and
     * may log). Never throws.
     */
    public PlatformTestResult test(DatabaseTarget target) {

        PlatformTestResult result = new PlatformTestResult();
        String over = !target.isEncrypted() ? "without encryption"
                : target.isVerified() ? "over TLS, its certificate checked" : "over TLS, its certificate not checked";

        if (target.getAdminUsername() == null) {
            try {
                close(connect(target, TEST_USERNAME, randomPassword()));
                result.failed("The " + target.describe() + " let an unknown account sign in (\"" + TEST_USERNAME
                        + "\", with a random password): its accounts would not be checked.");
            }
            catch (SQLException e) {
                if (isAuthenticationFailure(e))
                    result.passed("The " + target.describe() + " answers " + over + ", and refuses unknown"
                            + " accounts.");
                else
                    result.failed(describe(target, e));
            }
            catch (DriverMissing e) {
                result.failed(e.getMessage());
            }
            if (result.isSuccess())
                result.info("No administrator account: each account changes its own password.");
            return result;
        }

        Connection connection;
        try {
            connection = connect(target, target.getAdminUsername(), target.getAdminPassword());
        }
        catch (SQLException e) {
            result.failed(isAuthenticationFailure(e)
                    ? "The " + target.describe() + " refused the administrator account \"" + target.getAdminUsername()
                        + "\": " + firstLine(e)
                    : describe(target, e));
            return result;
        }
        catch (DriverMissing e) {
            return result.failed(e.getMessage());
        }

        try {
            String version = connection.getMetaData().getDatabaseProductVersion();
            result.passed("The administrator account \"" + target.getAdminUsername() + "\" signed in to the "
                    + target.describe() + " (" + version + "), " + over + ".");
            checkPrivileges(connection, target, result);
        }
        catch (SQLException e) {
            result.failed("Unable to check what the administrator account may do: " + firstLine(e));
        }
        finally {
            close(connection);
        }
        return result;

    }

    /**
     * Adds whether the administrator account may change other accounts'
     * passwords.
     */
    private static void checkPrivileges(Connection connection, DatabaseTarget target, PlatformTestResult result)
            throws SQLException {

        switch (target.getKind()) {

            case POSTGRESQL:
                try (Statement statement = connection.createStatement();
                     ResultSet results = statement.executeQuery(
                         "SELECT rolsuper, rolcreaterole FROM pg_roles WHERE rolname = current_user")) {
                    results.next();
                    if (results.getBoolean(1))
                        result.passed("It is a superuser, so it may change any role's password.");
                    else if (results.getBoolean(2))
                        result.passed("It has CREATEROLE. Since PostgreSQL 16, it also needs the ADMIN option on"
                                + " each role it changes (GRANT role TO it WITH ADMIN OPTION).");
                    else
                        result.failed("It has neither CREATEROLE nor superuser, so it may not change other roles'"
                                + " passwords.");
                }
                return;

            case MYSQL:
                boolean allowed = false;
                try (Statement statement = connection.createStatement();
                     ResultSet results = statement.executeQuery("SHOW GRANTS")) {
                    while (results.next()) {
                        String grant = results.getString(1).toUpperCase();
                        allowed |= grant.contains("CREATE USER") || grant.startsWith("GRANT ALL PRIVILEGES ON *.*");
                    }
                }
                if (!allowed) {
                    result.failed("It lacks CREATE USER, so it may not change other accounts' passwords.");
                    return;
                }
                result.passed("It has CREATE USER, so it may change other accounts' passwords.");
                if (isMariaDb(connection)) {
                    try (Statement statement = connection.createStatement();
                         ResultSet results = statement.executeQuery("SELECT 1 FROM mysql.global_priv LIMIT 1")) {
                        result.passed("It may read accounts' authentication methods, which MariaDB needs kept.");
                    }
                    catch (SQLException e) {
                        result.failed("It may not read mysql.global_priv, which it needs to keep accounts'"
                                + " authentication methods: grant it SELECT on mysql.global_priv.");
                    }
                }
                return;

            case SQLSERVER:
                try (Statement statement = connection.createStatement();
                     ResultSet results = statement.executeQuery("SELECT HAS_PERMS_BY_NAME(NULL, NULL, 'ALTER ANY"
                         + " LOGIN'), HAS_PERMS_BY_NAME(NULL, NULL, 'CONTROL SERVER')")) {
                    results.next();
                    if (results.getInt(2) == 1)
                        result.passed("It has CONTROL SERVER, so it may change any login's password.");
                    else if (results.getInt(1) == 1)
                        result.passed("It has ALTER ANY LOGIN, so it may change logins' passwords, except those of"
                                + " sysadmin logins, which need CONTROL SERVER.");
                    else
                        result.failed("It lacks ALTER ANY LOGIN, so it may not change other logins' passwords.");
                }
                return;

            default:
                return;

        }

    }

    /**
     * Runs the statement setting the password.
     */
    private static void setPassword(Connection connection, DatabaseTarget target, boolean mariadb, boolean admin,
            String newPassword) throws SQLException {

        String name = target.getUsername();

        switch (target.getKind()) {

            case POSTGRESQL:
                // Neither a verifier nor a quoted name can end the statement
                try (Statement statement = connection.createStatement()) {
                    statement.execute("ALTER ROLE " + (admin ? quotePostgreSqlName(name) : "CURRENT_USER")
                            + " PASSWORD '" + scramVerifier(newPassword) + "'");
                }
                return;

            case MYSQL:
                if (mariadb) {
                    setMariaDbPassword(connection, target, admin, newPassword);
                    return;
                }
                // Parameters filled in by the driver, quoted as literals.
                // MySQL keeps the account's authentication method.
                try (PreparedStatement statement = connection.prepareStatement(admin
                        ? "ALTER USER ?@? IDENTIFIED BY ?" : "ALTER USER USER() IDENTIFIED BY ? REPLACE ?")) {
                    if (admin) {
                        statement.setString(1, name);
                        statement.setString(2, target.getAccountHost());
                        statement.setString(3, newPassword);
                    }
                    else {
                        statement.setString(1, newPassword);
                        statement.setString(2, target.getPassword());
                    }
                    statement.execute();
                }
                return;

            case SQLSERVER:
                try (Statement statement = connection.createStatement()) {
                    statement.execute("ALTER LOGIN " + quoteSqlServerName(name) + " WITH PASSWORD = "
                            + quoteSqlServerString(newPassword)
                            + (admin ? "" : " OLD_PASSWORD = " + quoteSqlServerString(target.getPassword())));
                }
                return;

            default:
                throw new SQLException("Unknown database type.");

        }

    }

    /**
     * MariaDB authentication method keeping passwords out of its logs, by
     * being given their hash.
     */
    private static final String NATIVE_PASSWORD = "mysql_native_password";

    /**
     * Sets a MariaDB account's password keeping its authentication method,
     * which MariaDB would otherwise replace with mysql_native_password:
     * accounts using it are given the hash of the new password; accounts
     * using another, such as ed25519, the password itself, as only the
     * server computes their hashes.
     *
     * @throws SQLException
     *     If the method cannot be read, or the password cannot be set.
     */
    private static void setMariaDbPassword(Connection connection, DatabaseTarget target, boolean admin,
            String newPassword) throws SQLException {

        String plugin = admin ? readMariaDbPlugin(connection, target) : readOwnMariaDbPlugin(connection);
        boolean hashed = plugin.isEmpty() || NATIVE_PASSWORD.equals(plugin);

        // The new password could not be checked: change nothing
        if (!hashed && isMySqlConnectorJ(connection))
            throw new SQLException(connectorJAdvice(plugin), "HY000", MARIADB_PLUGIN_UNSUPPORTED);

        String sql;
        if (admin)
            sql = hashed ? "ALTER USER ?@? IDENTIFIED BY PASSWORD ?"
                         : "ALTER USER ?@? IDENTIFIED VIA " + plugin + " USING PASSWORD(?)";
        else
            sql = hashed ? "SET PASSWORD = ?" : "SET PASSWORD = PASSWORD(?)";

        try (PreparedStatement statement = connection.prepareStatement(sql)) {
            int index = 1;
            if (admin) {
                statement.setString(index++, target.getUsername());
                statement.setString(index++, target.getAccountHost());
            }
            statement.setString(index, hashed ? nativePasswordHash(newPassword) : newPassword);
            statement.execute();
        }

    }

    /**
     * Reads the authentication method of the target's account, as the
     * administrator account, which needs SELECT on mysql.global_priv.
     */
    private static String readMariaDbPlugin(Connection connection, DatabaseTarget target) throws SQLException {
        try (PreparedStatement statement = connection.prepareStatement(
                "SELECT JSON_VALUE(Priv, '$.plugin') FROM mysql.global_priv WHERE User = ? AND Host = ?")) {
            statement.setString(1, target.getUsername());
            statement.setString(2, target.getAccountHost());
            try (ResultSet results = statement.executeQuery()) {
                if (!results.next())
                    throw new SQLException("Account '" + target.getUsername() + "'@'" + target.getAccountHost()
                            + "' not found.", "42000", 1396);
                return validPlugin(results.getString(1));
            }
        }
        catch (SQLException e) {
            if (e.getErrorCode() == 1142 || e.getErrorCode() == 1044)
                throw new SQLException("Unable to read the account's authentication method, needed to keep it: "
                        + firstLine(e), e.getSQLState(), MARIADB_PLUGIN_UNREADABLE, e);
            throw e;
        }
    }

    /**
     * Reads the authentication method of the account connected as.
     */
    private static String readOwnMariaDbPlugin(Connection connection) throws SQLException {
        try (Statement statement = connection.createStatement();
             ResultSet results = statement.executeQuery("SHOW CREATE USER CURRENT_USER")) {
            results.next();
            Matcher via = Pattern.compile("IDENTIFIED VIA (\\w+)").matcher(results.getString(1));
            return via.find() ? validPlugin(via.group(1)) : NATIVE_PASSWORD;
        }
    }

    /**
     * An authentication method's name, refused unless it is a plain name,
     * as it is written into the statement.
     */
    private static String validPlugin(String plugin) throws SQLException {
        String name = plugin == null ? "" : plugin;
        if (!name.matches("\\w*"))
            throw new SQLException("Unknown authentication method \"" + name + "\".");
        return name;
    }

    /**
     * Error code of the administrator account not reading a MariaDB
     * account's authentication method.
     */
    private static final int MARIADB_PLUGIN_UNREADABLE = -1142;

    /**
     * Error code of a MariaDB account's authentication method that MySQL's
     * driver cannot sign in with.
     */
    private static final int MARIADB_PLUGIN_UNSUPPORTED = -1251;

    private static boolean isMySqlConnectorJ(Connection connection) throws SQLException {
        return connection.getMetaData().getDriverName().contains("MySQL Connector");
    }

    private static String connectorJAdvice(String plugin) {
        return "The account uses MariaDB's " + plugin + " authentication, which MySQL Connector/J cannot sign in"
                + " with, so its new password could not be checked: put MariaDB Connector/J"
                + " (mariadb-java-client-*.jar) in GUACAMOLE_HOME/lib, then restart Guacamole.";
    }

    /**
     * Opens a connection to the server, as the given account.
     *
     * @throws DriverMissing
     *     If no driver of the server's database is installed.
     */
    private Connection connect(DatabaseTarget target, String username, String password)
            throws SQLException, DriverMissing {

        Properties properties = new Properties();
        properties.setProperty("user", username);
        properties.setProperty("password", password);

        File trust = null;
        try {

            String url;
            Driver driver;
            switch (target.getKind()) {

                case POSTGRESQL:
                    driver = load(POSTGRESQL_DRIVER, "PostgreSQL", "the PostgreSQL JDBC driver (postgresql-*.jar)");
                    url = "jdbc:postgresql://" + host(target) + ":" + target.getPort() + "/"
                            + (target.getDatabase() == null ? "postgres" : target.getDatabase());
                    properties.setProperty("connectTimeout", Integer.toString(CONNECT_TIMEOUT_SECONDS));
                    properties.setProperty("loginTimeout", Integer.toString(CONNECT_TIMEOUT_SECONDS));
                    properties.setProperty("socketTimeout", Integer.toString(SOCKET_TIMEOUT_SECONDS));
                    properties.setProperty("ApplicationName", "guacamole-pam");
                    properties.setProperty("gssEncMode", "disable");
                    if (!target.isEncrypted())
                        properties.setProperty("sslmode", "disable");
                    else if (!target.isVerified()) {
                        properties.setProperty("sslmode", "require");
                        properties.setProperty("sslfactory", "org.postgresql.ssl.NonValidatingFactory");
                    }
                    else {
                        properties.setProperty("sslmode", "verify-full");
                        if (target.getAuthorities().isEmpty())
                            properties.setProperty("sslfactory", "org.postgresql.ssl.DefaultJavaSSLFactory");
                        else {
                            trust = writePem(target);
                            properties.setProperty("sslrootcert", trust.getPath());
                        }
                    }
                    break;

                case MYSQL:
                    boolean mariadbDriver = isInstalled(MARIADB_DRIVER);
                    driver = mariadbDriver ? load(MARIADB_DRIVER, "MySQL", null) : load(MYSQL_DRIVER, "MySQL",
                            "MariaDB Connector/J (mariadb-java-client-*.jar) or MySQL Connector/J (mysql-connector-j-*.jar)");
                    url = (mariadbDriver ? "jdbc:mariadb://" : "jdbc:mysql://") + host(target) + ":" + target.getPort()
                            + "/" + (target.getDatabase() == null ? "" : target.getDatabase());
                    properties.setProperty("connectTimeout", Integer.toString(CONNECT_TIMEOUT_SECONDS * 1000));
                    properties.setProperty("socketTimeout", Integer.toString(SOCKET_TIMEOUT_SECONDS * 1000));
                    properties.setProperty("useServerPrepStmts", "false");

                    // Never send the server local files, nor run objects it
                    // sends, whatever the driver's defaults
                    properties.setProperty("allowLoadLocalInfile", "false");
                    properties.setProperty("allowLocalInfile", "false");
                    properties.setProperty("allowUrlInLocalInfile", "false");
                    properties.setProperty("autoDeserialize", "false");
                    if (mariadbDriver) {
                        if (!target.isEncrypted()) {
                            properties.setProperty("sslMode", "disable");
                            properties.setProperty("allowPublicKeyRetrieval", "true");
                        }
                        else if (!target.isVerified())
                            properties.setProperty("sslMode", "trust");
                        else {
                            properties.setProperty("sslMode", "verify-full");
                            if (!target.getAuthorities().isEmpty()) {
                                trust = writePem(target);
                                properties.setProperty("serverSslCert", trust.getPath());
                            }
                        }
                    }
                    else {
                        if (!target.isEncrypted()) {
                            properties.setProperty("sslMode", "DISABLED");
                            properties.setProperty("allowPublicKeyRetrieval", "true");
                        }
                        else if (!target.isVerified())
                            properties.setProperty("sslMode", "REQUIRED");
                        else {
                            properties.setProperty("sslMode", "VERIFY_IDENTITY");
                            if (!target.getAuthorities().isEmpty()) {
                                String storePassword = randomPassword();
                                trust = writeTrustStore(target, storePassword);
                                properties.setProperty("trustCertificateKeyStoreUrl", trust.toURI().toString());
                                properties.setProperty("trustCertificateKeyStoreType", "PKCS12");
                                properties.setProperty("trustCertificateKeyStorePassword", storePassword);
                                properties.setProperty("fallbackToSystemTrustStore", "false");
                            }
                        }
                    }
                    break;

                case SQLSERVER:
                    driver = load(SQLSERVER_DRIVER, "SQL Server",
                            "the Microsoft JDBC Driver for SQL Server (mssql-jdbc-*.jar)");
                    url = "jdbc:sqlserver://" + target.getHostname() + ":" + target.getPort();
                    properties.setProperty("databaseName", target.getDatabase() == null ? "master" : target.getDatabase());
                    properties.setProperty("loginTimeout", Integer.toString(CONNECT_TIMEOUT_SECONDS));
                    properties.setProperty("socketTimeout", Integer.toString(SOCKET_TIMEOUT_SECONDS * 1000));
                    properties.setProperty("applicationName", "guacamole-pam");
                    if (!target.isEncrypted())
                        properties.setProperty("encrypt", "false");
                    else if (!target.isVerified()) {
                        properties.setProperty("encrypt", "true");
                        properties.setProperty("trustServerCertificate", "true");
                    }
                    else {
                        properties.setProperty("encrypt", "true");
                        properties.setProperty("trustServerCertificate", "false");
                        properties.setProperty("hostNameInCertificate", target.getHostname());
                        if (!target.getAuthorities().isEmpty()) {
                            String storePassword = randomPassword();
                            trust = writeTrustStore(target, storePassword);
                            properties.setProperty("trustStore", trust.getPath());
                            properties.setProperty("trustStoreType", "PKCS12");
                            properties.setProperty("trustStorePassword", storePassword);
                        }
                    }
                    break;

                default:
                    throw new SQLException("Unknown database type.");

            }

            Connection connection = driver.connect(url, properties);
            if (connection == null)
                throw new SQLException("The driver does not accept " + url + ".");
            return connection;

        }
        finally {
            if (trust != null && !trust.delete())
                trust.deleteOnExit();
        }

    }

    /**
     * A hostname as JDBC URLs take it: IPv6 addresses in brackets.
     */
    private static String host(DatabaseTarget target) {
        String hostname = target.getHostname();
        return hostname.contains(":") && !hostname.startsWith("[") ? "[" + hostname + "]" : hostname;
    }

    private static boolean isInstalled(String driverClass) {
        try {
            Class.forName(driverClass, false, DatabaseClient.class.getClassLoader());
            return true;
        }
        catch (ClassNotFoundException | LinkageError e) {
            return false;
        }
    }

    /**
     * Loads an installed driver.
     *
     * @param jar
     *     The jar to install, as the error names it.
     */
    private static Driver load(String driverClass, String database, String jar) throws DriverMissing {
        try {
            return (Driver) Class.forName(driverClass, true, DatabaseClient.class.getClassLoader())
                    .getDeclaredConstructor().newInstance();
        }
        catch (ReflectiveOperationException | LinkageError e) {
            throw new DriverMissing("No " + database + " driver is installed: put " + jar
                    + " in GUACAMOLE_HOME/lib, then restart Guacamole.");
        }
    }

    /**
     * Writes the platform's certificates to a temporary PEM file, as
     * PostgreSQL's and MariaDB's drivers read them.
     */
    private static File writePem(DatabaseTarget target) throws SQLException {
        try {
            File file = File.createTempFile("guacamole-pam-", ".pem");
            StringBuilder pem = new StringBuilder();
            Base64.Encoder encoder = Base64.getMimeEncoder(64, new byte[] { '\n' });
            for (X509Certificate certificate : target.getAuthorities())
                pem.append("-----BEGIN CERTIFICATE-----\n").append(encoder.encodeToString(certificate.getEncoded()))
                   .append("\n-----END CERTIFICATE-----\n");
            Files.write(file.toPath(), pem.toString().getBytes(StandardCharsets.US_ASCII));
            return file;
        }
        catch (IOException | GeneralSecurityException e) {
            throw new SQLException("Unable to pass the CA certificates to the driver: " + e.getMessage(), e);
        }
    }

    /**
     * Writes the platform's certificates to a temporary PKCS #12 trust
     * store, as MySQL's and SQL Server's drivers read them.
     */
    private static File writeTrustStore(DatabaseTarget target, String password) throws SQLException {
        try {
            KeyStore store = KeyStore.getInstance("PKCS12");
            store.load(null, null);
            int i = 0;
            for (X509Certificate certificate : target.getAuthorities())
                store.setCertificateEntry("ca" + i++, certificate);
            File file = File.createTempFile("guacamole-pam-", ".p12");
            try (OutputStream out = new FileOutputStream(file)) {
                store.store(out, password.toCharArray());
            }
            return file;
        }
        catch (IOException | GeneralSecurityException e) {
            throw new SQLException("Unable to pass the CA certificates to the driver: " + e.getMessage(), e);
        }
    }

    private static boolean isMariaDb(Connection connection) throws SQLException {
        return connection.getMetaData().getDatabaseProductVersion().contains("MariaDB");
    }

    /**
     * Whether the server refused the account or its password, rather than
     * failing otherwise.
     */
    static boolean isAuthenticationFailure(SQLException e) {
        for (Throwable current = e; current != null; current = current.getCause()) {
            if (!(current instanceof SQLException))
                continue;
            SQLException sql = (SQLException) current;
            String state = sql.getSQLState();
            int code = sql.getErrorCode();
            // Not the password: PostgreSQL refusing the client's address
            if (sql.getMessage() != null && sql.getMessage().contains("pg_hba.conf"))
                return false;
            if ((state != null && state.startsWith("28")) || code == 1045 || code == 18456)
                return true;
        }
        return false;
    }

    /**
     * Why the server refused to change the password, with what the account
     * needs where it lacked a privilege.
     */
    private static String describeRefusal(DatabaseTarget target, boolean admin, SQLException e) {

        String reason = firstLine(e);
        String who = admin ? "The administrator account" : "The account";
        int code = e.getErrorCode();
        String state = e.getSQLState() == null ? "" : e.getSQLState();

        switch (target.getKind()) {
            case POSTGRESQL:
                if ("42501".equals(state))
                    return who + " may not change the role's password: " + reason + " It needs CREATEROLE and,"
                            + " since PostgreSQL 16, the ADMIN option on the role (or to be a superuser).";
                if ("42704".equals(state))
                    return "The role \"" + target.getUsername() + "\" does not exist: " + reason;
                break;
            case MYSQL:
                if (code == MARIADB_PLUGIN_UNSUPPORTED)
                    return reason;
                if (code == MARIADB_PLUGIN_UNREADABLE)
                    return reason + " Grant the administrator account SELECT on mysql.global_priv.";
                if (code == 1227 || code == 1044 || code == 1142)
                    return who + " may not change the account's password: " + reason + " It needs CREATE USER.";
                if (code == 1396)
                    return "The account '" + target.getUsername() + "'@'" + target.getAccountHost() + "' does not"
                            + " exist, or cannot be changed: " + reason;
                break;
            case SQLSERVER:
                if (code == 15151)
                    return "The login \"" + target.getUsername() + "\" does not exist, or " + who.toLowerCase()
                            + " may not change it: " + reason + " Changing another login needs ALTER ANY LOGIN,"
                            + " and a sysadmin login CONTROL SERVER.";
                break;
            default:
                break;
        }

        return "The " + target.describe() + " refused the change: " + reason;

    }

    /**
     * Why connecting failed, other than the account being refused.
     */
    private static String describe(DatabaseTarget target, SQLException e) {

        // MySQL's driver signing in to a MariaDB account using a method it
        // does not know
        for (Throwable cause = e; cause != null; cause = cause.getCause()) {
            String message = cause.getMessage() == null ? "" : cause.getMessage();
            if (message.contains("BadAuthenticationPlugin") || message.contains("Unable to load authentication plugin"))
                return "Unable to sign in to the " + target.describe() + ": " + connectorJAdvice("ed25519 (or other)");
        }

        // Some drivers (MySQL's) report a TLS failure as a lost connection,
        // with the reason among its causes
        for (Throwable cause = e; cause != null; cause = cause.getCause()) {
            String message = cause.getMessage() == null ? "" : cause.getMessage();
            String lower = message.toLowerCase();
            if (cause instanceof javax.net.ssl.SSLException || lower.contains("certificate") || lower.contains("ssl")
                    || lower.contains("tls") || lower.contains("pkix") || lower.contains("handshake"))
                return "Unable to trust the " + target.describe() + ": " + firstLine(message);
        }

        return "Unable to connect to the " + target.describe() + ": " + firstLine(e);

    }

    private static String firstLine(SQLException e) {
        return e.getMessage() == null ? e.getClass().getSimpleName() : firstLine(e.getMessage());
    }

    private static String firstLine(String message) {
        int end = message.indexOf('\n');
        return (end < 0 ? message : message.substring(0, end)).trim();
    }

    /**
     * Quotes a name for PostgreSQL, as "name".
     */
    static String quotePostgreSqlName(String name) {
        return "\"" + name.replace("\"", "\"\"") + "\"";
    }

    /**
     * Quotes a name for SQL Server, as [name].
     */
    static String quoteSqlServerName(String name) {
        return "[" + name.replace("]", "]]") + "]";
    }

    /**
     * Quotes a string for SQL Server, as N'text'.
     */
    static String quoteSqlServerString(String text) {
        return "N'" + text.replace("'", "''") + "'";
    }

    /**
     * The SCRAM-SHA-256 verifier of a password, as PostgreSQL stores it
     * (RFC 5802, RFC 7677): "SCRAM-SHA-256$iterations:salt$StoredKey:ServerKey".
     * Passwords are used as they are, as generated passwords need no
     * SASLprep normalization.
     */
    static String scramVerifier(String password) {
        byte[] salt = new byte[16];
        RANDOM.nextBytes(salt);
        return scramVerifier(password, salt, SCRAM_ITERATIONS);
    }

    static String scramVerifier(String password, byte[] salt, int iterations) {
        try {
            byte[] salted = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256")
                    .generateSecret(new PBEKeySpec(password.toCharArray(), salt, iterations, 256)).getEncoded();
            byte[] clientKey = hmac(salted, "Client Key");
            byte[] serverKey = hmac(salted, "Server Key");
            byte[] storedKey = MessageDigest.getInstance("SHA-256").digest(clientKey);
            Base64.Encoder base64 = Base64.getEncoder();
            return "SCRAM-SHA-256$" + iterations + ":" + base64.encodeToString(salt) + "$"
                    + base64.encodeToString(storedKey) + ":" + base64.encodeToString(serverKey);
        }
        catch (GeneralSecurityException e) {
            throw new IllegalStateException("SCRAM-SHA-256 is unavailable.", e);
        }
    }

    private static byte[] hmac(byte[] key, String text) throws GeneralSecurityException {
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(new SecretKeySpec(key, "HmacSHA256"));
        return mac.doFinal(text.getBytes(StandardCharsets.UTF_8));
    }

    /**
     * The mysql_native_password hash of a password, as MariaDB stores it:
     * "*" and SHA1(SHA1(password)) in upper case hexadecimal.
     */
    static String nativePasswordHash(String password) {
        try {
            MessageDigest sha1 = MessageDigest.getInstance("SHA-1");
            byte[] hash = sha1.digest(sha1.digest(password.getBytes(StandardCharsets.UTF_8)));
            StringBuilder text = new StringBuilder("*");
            for (byte b : hash)
                text.append(String.format("%02X", b));
            return text.toString();
        }
        catch (GeneralSecurityException e) {
            throw new IllegalStateException("SHA-1 is unavailable.", e);
        }
    }

    private static String randomPassword() {
        byte[] bytes = new byte[18];
        RANDOM.nextBytes(bytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }

    private static void close(Connection connection) {
        try {
            connection.close();
        }
        catch (SQLException e) {
            // Nothing more to do with it
        }
    }

    /**
     * The driver of a database is not installed.
     */
    private static final class DriverMissing extends Exception {

        private static final long serialVersionUID = 1L;

        DriverMissing(String message) {
            super(message);
        }

    }

}
