package io.github.ialzamil.guacamole.pam.ha;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.PrintWriter;
import java.nio.charset.StandardCharsets;
import java.sql.Connection;
import java.sql.Driver;
import java.sql.SQLException;
import java.sql.SQLFeatureNotSupportedException;
import java.sql.Statement;
import java.util.Arrays;
import java.util.Locale;
import java.util.Properties;
import java.util.concurrent.TimeUnit;
import java.util.logging.Logger;

import javax.sql.DataSource;

import org.apache.guacamole.GuacamoleException;
import org.apache.guacamole.GuacamoleServerException;
import org.apache.guacamole.environment.Environment;

import com.zaxxer.hikari.HikariConfig;
import com.zaxxer.hikari.HikariDataSource;

/**
 * The Guacamole database of one data source, reached with the properties
 * and the driver of Guacamole's own authentication for that database, as it
 * reaches it: the same host, port, database, user and encryption settings.
 * Connections come from a small pool of their own: a heartbeat every few
 * seconds, and a few per session or login opened or closed, each holding
 * one at a time, so the pool never waits on itself.
 */
final class Database {

    /**
     * Seconds to wait for the database when connecting.
     */
    private static final int CONNECT_TIMEOUT_SECONDS = 10;

    /**
     * Seconds to wait for an answer once connected: a connection cut off
     * mid-query never answers, and would hold the heartbeat forever.
     */
    private static final int SOCKET_TIMEOUT_SECONDS = 30;

    /**
     * The most connections open at once, and those kept open while idle.
     */
    private static final int MAX_CONNECTIONS = 10;
    private static final int MIN_IDLE_CONNECTIONS = 1;

    /**
     * This extension's tables.
     */
    private static final String[] TABLES = { "pam_ha_server", "pam_ha_session", "pam_ha_lock",
            "pam_ha_share", "pam_ha_login", "pam_ha_ban", "pam_ha_totp",
            "pam_ha_recording" };

    private final DatabaseType type;

    private final String driverClass;

    private final String url;

    private final Properties connectionProperties;

    private Driver driver;

    private HikariDataSource pool;

    private boolean closed;

    private Database(DatabaseType type, String driverClass, String url, Properties connectionProperties) {
        this.type = type;
        this.driverClass = driverClass;
        this.url = url;
        this.connectionProperties = connectionProperties;
    }

    /**
     * The database of the given type as Guacamole's authentication for it
     * is configured, or null if it is not: its database is not set.
     *
     * @throws GuacamoleException
     *     If the properties are invalid, or name a driver this extension
     *     does not support.
     */
    static Database fromEnvironment(DatabaseType type, Environment environment) throws GuacamoleException {

        String database = environment.getProperty(Settings.string(type.property("database")));
        if (database == null)
            return null;

        String hostname = environment.getProperty(Settings.string(type.property("hostname")), "localhost");
        int port = environment.getProperty(Settings.integer(type.property("port")), type.getDefaultPort());

        Properties properties = new Properties();
        put(properties, "user", environment.getProperty(Settings.string(type.property("username"))));
        put(properties, "password", environment.getProperty(Settings.string(type.property("password"))));

        switch (type) {

            case POSTGRESQL:
                put(properties, "sslmode", option(environment, type, "ssl-mode"));
                put(properties, "sslcert", option(environment, type, "ssl-cert-file"));
                put(properties, "sslkey", option(environment, type, "ssl-key-file"));
                put(properties, "sslrootcert", option(environment, type, "ssl-root-cert-file"));
                put(properties, "sslpassword", option(environment, type, "ssl-key-password"));
                put(properties, "connectTimeout", Integer.toString(CONNECT_TIMEOUT_SECONDS));
                put(properties, "socketTimeout", Integer.toString(SOCKET_TIMEOUT_SECONDS));
                return new Database(type, "org.postgresql.Driver",
                        "jdbc:postgresql://" + hostname + ":" + port + "/" + database, properties);

            case MYSQL:
                return mysql(environment, hostname, port, database, properties);

            case SQLSERVER:
                return sqlServer(environment, hostname, port, database, properties);

            default:
                throw new GuacamoleServerException("Unsupported database " + type + ".");

        }

    }

    /**
     * MySQL's Connector/J or MariaDB's driver, as "mysql-driver" chooses,
     * with the encryption "mysql-ssl-mode" asks for.
     */
    private static Database mysql(Environment environment, String hostname, int port, String database,
            Properties properties) throws GuacamoleException {

        DatabaseType type = DatabaseType.MYSQL;
        String driver = option(environment, type, "driver");
        String sslMode = option(environment, type, "ssl-mode");
        String serverTimezone = option(environment, type, "server-timezone");

        // As Guacamole: MariaDB's driver if installed, unless told
        if (driver == null)
            driver = isInstalled(MARIADB_DRIVER) ? "mariadb" : "mysql";

        if (driver.equalsIgnoreCase("mysql")) {
            if (sslMode != null)
                put(properties, "sslMode", sslMode.toUpperCase(Locale.ROOT).replace('-', '_'));
            put(properties, "serverTimezone", serverTimezone);
            put(properties, "connectTimeout", Integer.toString(CONNECT_TIMEOUT_SECONDS * 1000));
            put(properties, "socketTimeout", Integer.toString(SOCKET_TIMEOUT_SECONDS * 1000));
            putStores(environment, properties, "trustCertificateKeyStoreUrl", "trustCertificateKeyStorePassword",
                    "clientCertificateKeyStoreUrl", "clientCertificateKeyStorePassword");
            return new Database(type, "com.mysql.cj.jdbc.Driver",
                    "jdbc:mysql://" + hostname + ":" + port + "/" + database, properties);
        }

        if (driver.equalsIgnoreCase("mariadb")) {
            put(properties, "sslMode", mariaDbSslMode(sslMode));
            put(properties, "connectTimeout", Integer.toString(CONNECT_TIMEOUT_SECONDS * 1000));
            put(properties, "socketTimeout", Integer.toString(SOCKET_TIMEOUT_SECONDS * 1000));
            putStores(environment, properties, "trustStore", "trustStorePassword", "keyStore", "keyStorePassword");
            return new Database(type, MARIADB_DRIVER,
                    "jdbc:mariadb://" + hostname + ":" + port + "/" + database, properties);
        }

        throw new GuacamoleServerException("The MySQL driver \"" + driver + "\" is not supported: use \"mysql\""
                + " or \"mariadb\".");

    }

    /**
     * MariaDB's name for a "mysql-ssl-mode", or null to leave its default.
     */
    static String mariaDbSslMode(String sslMode) {
        if (sslMode == null)
            return null;
        switch (sslMode.toLowerCase(Locale.ROOT)) {
            case "disabled":
                return "disable";
            case "verify-ca":
                return "verify-ca";
            case "verify-identity":
                return "verify-full";
            default:
                return "trust";
        }
    }

    /**
     * Microsoft's driver, as Guacamole's "microsoft2005" (its default), or
     * jTDS, as "sqlserver-driver" chooses.
     */
    private static Database sqlServer(Environment environment, String hostname, int port, String database,
            Properties properties) throws GuacamoleException {

        DatabaseType type = DatabaseType.SQLSERVER;
        String driver = option(environment, type, "driver");
        String instance = option(environment, type, "instance");
        boolean trustAll = environment.getProperty(Settings.bool(
                type.property("trust-all-server-certificates")), false);

        if (driver == null || driver.equalsIgnoreCase("microsoft2005")) {
            if (trustAll)
                put(properties, "trustServerCertificate", "true");
            put(properties, "instanceName", instance);
            put(properties, "databaseName", database);
            put(properties, "loginTimeout", Integer.toString(CONNECT_TIMEOUT_SECONDS));
            put(properties, "socketTimeout", Integer.toString(SOCKET_TIMEOUT_SECONDS * 1000));
            return new Database(type, "com.microsoft.sqlserver.jdbc.SQLServerDriver",
                    "jdbc:sqlserver://" + hostname + ":" + port, properties);
        }

        if (driver.equalsIgnoreCase("jtds")) {
            put(properties, "instance", instance);
            put(properties, "loginTimeout", Integer.toString(CONNECT_TIMEOUT_SECONDS));
            put(properties, "socketTimeout", Integer.toString(SOCKET_TIMEOUT_SECONDS));
            return new Database(type, "net.sourceforge.jtds.jdbc.Driver",
                    "jdbc:jtds:sqlserver://" + hostname + ":" + port + "/" + database, properties);
        }

        throw new GuacamoleServerException("The SQL Server driver \"" + driver + "\" is not supported: use"
                + " \"microsoft2005\" or \"jtds\".");

    }

    private static String option(Environment environment, DatabaseType type, String name)
            throws GuacamoleException {
        String value = environment.getProperty(Settings.string(
                type.property(name)));
        return value == null || value.trim().isEmpty() ? null : value.trim();
    }

    private static final String MARIADB_DRIVER = "org.mariadb.jdbc.Driver";

    private static boolean isInstalled(String driverClass) {
        try {
            Class.forName(driverClass, false, Database.class.getClassLoader());
            return true;
        }
        catch (ClassNotFoundException | LinkageError e) {
            return false;
        }
    }

    /**
     * The trust and client stores of "mysql-ssl-trust-store",
     * "mysql-ssl-client-store" and their passwords, as the driver names
     * them.
     */
    private static void putStores(Environment environment, Properties properties, String trustStore,
            String trustPassword, String clientStore, String clientPassword) throws GuacamoleException {
        DatabaseType type = DatabaseType.MYSQL;
        String trust = option(environment, type, "ssl-trust-store");
        String client = option(environment, type, "ssl-client-store");
        put(properties, trustStore, trust == null ? null : new File(trust).toURI().toString());
        put(properties, trustPassword, option(environment, type, "ssl-trust-password"));
        put(properties, clientStore, client == null ? null : new File(client).toURI().toString());
        put(properties, clientPassword, option(environment, type, "ssl-client-password"));
    }

    private static void put(Properties properties, String name, String value) {
        if (value != null)
            properties.setProperty(name, value);
    }

    DatabaseType getType() {
        return type;
    }

    String getUrl() {
        return url;
    }

    Properties getConnectionProperties() {
        return connectionProperties;
    }

    /**
     * A connection from the pool, opened on first use; closing it returns
     * it.
     */
    Connection connect() throws SQLException {
        return pool().getConnection();
    }

    private synchronized HikariDataSource pool() throws SQLException {
        if (closed)
            throw new SQLException("The connections to the " + type.getIdentifier() + " database are closed.");
        if (pool == null) {
            HikariConfig config = new HikariConfig();
            config.setPoolName("guacamole-pam-ha-" + type.getIdentifier());
            config.setDataSource(new DriverSource());
            config.setMaximumPoolSize(MAX_CONNECTIONS);
            config.setMinimumIdle(MIN_IDLE_CONNECTIONS);
            config.setConnectionTimeout(TimeUnit.SECONDS.toMillis(CONNECT_TIMEOUT_SECONDS));
            // Connect on first use, not here: the database may be down
            config.setInitializationFailTimeout(-1);
            pool = new HikariDataSource(config);
        }
        return pool;
    }

    /**
     * Closes the pool's connections. Later requests for one fail.
     */
    synchronized void close() {
        closed = true;
        if (pool != null)
            pool.close();
        pool = null;
    }

    /**
     * Opens a connection, loading the driver on first use: Guacamole's
     * database authentication installs it where every extension can load
     * it.
     */
    private Connection open() throws SQLException {
        Connection connection = driver().connect(url, connectionProperties);
        if (connection == null)
            throw new SQLException("The driver " + driverClass + " does not accept " + url + ".");
        return connection;
    }

    /**
     * Where the pool opens its connections.
     */
    private final class DriverSource implements DataSource {

        private PrintWriter logWriter;

        @Override
        public Connection getConnection() throws SQLException {
            return open();
        }

        @Override
        public Connection getConnection(String username, String password) throws SQLException {
            throw new SQLFeatureNotSupportedException("The database user is that of Guacamole's properties.");
        }

        @Override
        public PrintWriter getLogWriter() {
            return logWriter;
        }

        @Override
        public void setLogWriter(PrintWriter out) {
            logWriter = out;
        }

        @Override
        public void setLoginTimeout(int seconds) {
            // Set by the connection properties
        }

        @Override
        public int getLoginTimeout() {
            return CONNECT_TIMEOUT_SECONDS;
        }

        @Override
        public Logger getParentLogger() throws SQLFeatureNotSupportedException {
            throw new SQLFeatureNotSupportedException();
        }

        @Override
        public <T> T unwrap(Class<T> iface) throws SQLException {
            throw new SQLException("Not a wrapper.");
        }

        @Override
        public boolean isWrapperFor(Class<?> iface) {
            return false;
        }

    }

    private synchronized Driver driver() throws SQLException {
        if (driver == null) {
            try {
                driver = (Driver) Class.forName(driverClass, true, Database.class.getClassLoader())
                        .getDeclaredConstructor().newInstance();
            }
            catch (ReflectiveOperationException | LinkageError e) {
                throw new SQLException("The database driver " + driverClass + " is not installed. It comes"
                        + " with Guacamole's " + type.getIdentifier() + " authentication.", e);
            }
        }
        return driver;
    }

    /**
     * Creates this extension's tables where missing, statement by
     * statement: each statement can run again, so servers starting at once
     * at most fail on a table just created by another, which is then there.
     *
     * @throws SQLException
     *     If a statement fails and the tables are still missing, such as
     *     when the database user may not create tables and nobody ran the
     *     schema script.
     */
    void createSchema() throws SQLException {

        String schema;
        try (InputStream input = Database.class.getResourceAsStream(type.getSchemaResource())) {
            if (input == null)
                throw new SQLException("Missing " + type.getSchemaResource() + ".");
            schema = new String(input.readAllBytes(), StandardCharsets.UTF_8);
        }
        catch (IOException e) {
            throw new SQLException("Unable to read " + type.getSchemaResource() + ".", e);
        }

        try (Connection connection = connect()) {
            SQLException failure = null;
            for (String sql : statements(schema)) {
                try (Statement statement = connection.createStatement()) {
                    statement.execute(sql);
                }
                catch (SQLException e) {
                    if (failure == null)
                        failure = e;
                }
            }
            if (failure != null && !hasTables(connection))
                throw failure;
        }

    }

    /**
     * The statements of a schema script: its comment lines left out, split
     * at each semicolon ending a line.
     */
    static String[] statements(String script) {
        StringBuilder withoutComments = new StringBuilder();
        for (String line : script.split("\\r?\\n")) {
            if (!line.trim().startsWith("--"))
                withoutComments.append(line).append('\n');
        }
        return Arrays.stream(withoutComments.toString().split(";[ \\t]*\\n"))
                .map(sql -> sql.trim()).filter(sql -> !sql.isEmpty()).toArray(String[]::new);
    }

    private static boolean hasTables(Connection connection) {
        for (String table : TABLES) {
            try (Statement statement = connection.createStatement()) {
                statement.executeQuery("SELECT 1 FROM " + table + " WHERE 1 = 0").close();
            }
            catch (SQLException e) {
                return false;
            }
        }
        return true;
    }

}
