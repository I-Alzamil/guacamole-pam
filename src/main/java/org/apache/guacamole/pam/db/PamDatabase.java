package org.apache.guacamole.pam.db;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.sql.Connection;
import java.sql.Driver;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.List;
import java.util.Properties;
import java.util.concurrent.CopyOnWriteArrayList;

import com.zaxxer.hikari.HikariConfig;
import com.zaxxer.hikari.HikariDataSource;

import org.apache.guacamole.GuacamoleException;
import org.apache.guacamole.GuacamoleServerException;
import org.apache.guacamole.environment.Environment;
import org.apache.guacamole.properties.IntegerGuacamoleProperty;
import org.apache.guacamole.properties.StringGuacamoleProperty;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Access to the Guacamole PostgreSQL database. Reuses the "postgresql-*"
 * properties and the driver of Guacamole's PostgreSQL authentication, and
 * creates this extension's own tables on first use, then runs what a fresh
 * install starts with ({@link #onFreshInstall}). The driver is loaded by
 * name, so this class loads (and {@link #getUnavailableReason} can tell why
 * the database cannot be used) even where the driver is missing.
 *
 * Connections come from a pool, opened on first use and holding at most
 * "pam-database-max-connections" (10 by default). Code holding a pooled
 * connection never asks for another, so a busy pool cannot deadlock.
 * Session-level advisory locks, released by closing their connection, use a
 * dedicated connection instead ({@link #getDedicatedConnection}).
 */
public class PamDatabase {

    private static final Logger logger = LoggerFactory.getLogger(PamDatabase.class);

    private static final StringGuacamoleProperty POSTGRESQL_HOSTNAME = new StringGuacamoleProperty() {
        @Override
        public String getName() { return "postgresql-hostname"; }
    };

    private static final IntegerGuacamoleProperty POSTGRESQL_PORT = new IntegerGuacamoleProperty() {
        @Override
        public String getName() { return "postgresql-port"; }
    };

    private static final StringGuacamoleProperty POSTGRESQL_DATABASE = new StringGuacamoleProperty() {
        @Override
        public String getName() { return "postgresql-database"; }
    };

    private static final StringGuacamoleProperty POSTGRESQL_USERNAME = new StringGuacamoleProperty() {
        @Override
        public String getName() { return "postgresql-username"; }
    };

    private static final StringGuacamoleProperty POSTGRESQL_PASSWORD = new StringGuacamoleProperty() {
        @Override
        public String getName() { return "postgresql-password"; }
    };

    private static final IntegerGuacamoleProperty MAX_CONNECTIONS = new IntegerGuacamoleProperty() {
        @Override
        public String getName() { return "pam-database-max-connections"; }
    };

    private static final int DEFAULT_MAX_CONNECTIONS = 10;

    /**
     * Pooled connections kept open while unused.
     */
    private static final int MIN_IDLE_CONNECTIONS = 2;

    /**
     * How long a request waits for a pooled connection before failing.
     */
    private static final long CONNECTION_TIMEOUT_MS = 30000;

    /**
     * Classpath resource holding the schema of this extension's tables.
     */
    private static final String SCHEMA_RESOURCE = "/schema/postgresql.sql";

    /**
     * Driver installed with Guacamole's PostgreSQL authentication.
     */
    private static final String DRIVER_CLASS = "org.postgresql.Driver";

    /**
     * Version the schema script records once it has run, which must match
     * the latest version it inserts into "pam_schema_version". A database
     * without it runs the script, creating or upgrading the tables.
     */
    private static final int SCHEMA_VERSION = 1;

    /**
     * SQL state of PostgreSQL's "insufficient_privilege".
     */
    private static final String INSUFFICIENT_PRIVILEGE = "42501";

    private final Driver driver;

    private final String username;

    /**
     * Whether the instructions for creating the tables by hand were logged,
     * so they are logged once rather than on every attempt.
     */
    private volatile boolean instructionsLogged = false;

    private final String url;

    private final Properties connectionProperties = new Properties();

    private final int maxConnections;

    /**
     * The pool, created on first use so the extension starts while the
     * database is unreachable. Null until then, and once closed.
     */
    private HikariDataSource pool;

    private boolean closed = false;

    private volatile boolean schemaReady = false;

    /**
     * Run once the schema script created the tables of a fresh install.
     */
    @FunctionalInterface
    public interface Initializer {
        void initialize(Connection connection) throws SQLException, GuacamoleException;
    }

    private final List<Initializer> initializers = new CopyOnWriteArrayList<>();

    /**
     * Adds what to run, through the connection that just created them, once
     * the tables of a fresh install exist. Not run where they were created
     * by hand, nor on later starts.
     */
    public void onFreshInstall(Initializer initializer) {
        initializers.add(initializer);
    }

    /**
     * Returns why this extension cannot use the Guacamole database here, or
     * null if it can: Guacamole's PostgreSQL authentication must be set up,
     * as the extension manages its connections.
     */
    public static String getUnavailableReason(Environment environment) throws GuacamoleException {

        if (environment.getProperty(POSTGRESQL_DATABASE) == null)
            return "Guacamole's PostgreSQL authentication is not configured (no \""
                    + POSTGRESQL_DATABASE.getName() + "\" property).";

        try {
            Class.forName(DRIVER_CLASS, false, PamDatabase.class.getClassLoader());
        }
        catch (ClassNotFoundException | LinkageError e) {
            return "the PostgreSQL JDBC driver is not installed. It comes with Guacamole's PostgreSQL"
                    + " authentication, which must be installed.";
        }

        return null;

    }

    public PamDatabase(Environment environment) throws GuacamoleException {

        try {
            driver = (Driver) Class.forName(DRIVER_CLASS, true, PamDatabase.class.getClassLoader())
                    .getDeclaredConstructor().newInstance();
        }
        catch (ReflectiveOperationException | LinkageError e) {
            throw new GuacamoleServerException("Unable to load the PostgreSQL JDBC driver.", e);
        }

        url = "jdbc:postgresql://"
                + environment.getProperty(POSTGRESQL_HOSTNAME, "localhost") + ":"
                + environment.getProperty(POSTGRESQL_PORT, 5432) + "/"
                + environment.getRequiredProperty(POSTGRESQL_DATABASE);

        username = environment.getRequiredProperty(POSTGRESQL_USERNAME);
        connectionProperties.setProperty("user", username);
        connectionProperties.setProperty("password", environment.getRequiredProperty(POSTGRESQL_PASSWORD));
        connectionProperties.setProperty("ApplicationName", "guacamole-pam");

        maxConnections = Math.max(2, environment.getProperty(MAX_CONNECTIONS, DEFAULT_MAX_CONNECTIONS));

    }

    private synchronized HikariDataSource pool() throws GuacamoleServerException {

        if (closed)
            throw new GuacamoleServerException("The PAM database is closed.");

        if (pool == null) {
            HikariConfig config = new HikariConfig();
            config.setPoolName("guacamole-pam");
            config.setDriverClassName(DRIVER_CLASS);
            config.setJdbcUrl(url);
            config.setDataSourceProperties(connectionProperties);
            config.setMaximumPoolSize(maxConnections);
            config.setMinimumIdle(Math.min(MIN_IDLE_CONNECTIONS, maxConnections));
            config.setConnectionTimeout(CONNECTION_TIMEOUT_MS);
            // Connect on first use, not here: the database may be down
            config.setInitializationFailTimeout(-1);
            pool = new HikariDataSource(config);
        }

        return pool;

    }

    /**
     * Returns a pooled database connection, creating the extension's tables
     * first if this is the first use. Closing it returns it to the pool.
     */
    public Connection getConnection() throws GuacamoleException {
        Connection connection;
        try {
            connection = pool().getConnection();
        }
        catch (SQLException e) {
            throw new GuacamoleServerException("Unable to connect to the PAM database.", e);
        }
        return withSchema(connection);
    }

    /**
     * Opens a database connection of its own, outside the pool, for
     * session-level advisory locks: closing it ends the database session,
     * releasing them.
     */
    public Connection getDedicatedConnection() throws GuacamoleException {
        Connection connection;
        try {
            connection = driver.connect(url, connectionProperties);
        }
        catch (SQLException e) {
            throw new GuacamoleServerException("Unable to connect to the PAM database.", e);
        }
        return withSchema(connection);
    }

    /**
     * Closes the pool's connections. Later requests for one fail.
     */
    public synchronized void close() {
        closed = true;
        if (pool != null)
            pool.close();
        pool = null;
    }

    private Connection withSchema(Connection connection) throws GuacamoleException {

        if (!schemaReady) {
            try {
                ensureSchema(connection);
            }
            catch (SQLException e) {
                logSchemaFailure(e);
                try {
                    connection.close();
                }
                catch (SQLException ignored) {
                }
                throw new SchemaUnavailableException("Unable to create the PAM database tables.", e);
            }
        }

        return connection;

    }

    private synchronized void ensureSchema(Connection connection) throws SQLException {

        if (schemaReady)
            return;

        String schema;
        try (InputStream in = PamDatabase.class.getResourceAsStream(SCHEMA_RESOURCE)) {
            schema = new String(in.readAllBytes(), StandardCharsets.UTF_8);
        }
        catch (IOException | NullPointerException e) {
            throw new SQLException("Unable to read " + SCHEMA_RESOURCE, e);
        }

        // Already there: nothing to run, which also lets a database user
        // without the privilege to create tables use tables created for it
        // (PostgreSQL refuses even "CREATE TABLE IF NOT EXISTS" to it)
        if (!hasVersion(connection, SCHEMA_VERSION)) {

            boolean fresh = !hasAnyVersion(connection);

            try (Statement statement = connection.createStatement()) {
                // Statements end with a semicolon at the end of a line
                for (String sql : schema.split(";[ \\t]*\\r?\\n")) {
                    if (!sql.trim().isEmpty())
                        statement.execute(sql);
                }
            }

            if (fresh) {
                for (Initializer initializer : initializers) {
                    try {
                        initializer.initialize(connection);
                    }
                    catch (GuacamoleException e) {
                        logger.warn("Unable to complete the fresh install: {}", e.getMessage());
                    }
                }
            }

        }

        schemaReady = true;
        logger.info("PAM database schema is ready.");

    }

    /**
     * Whether the tables of the given version of the schema exist: the
     * schema script records its versions last, once every statement ran.
     */
    private static boolean hasVersion(Connection connection, int version) throws SQLException {
        if (!hasTable(connection, "pam_schema_version"))
            return false;
        try (Statement statement = connection.createStatement();
             ResultSet results = statement.executeQuery(
                 "SELECT 1 FROM pam_schema_version WHERE version = " + version)) {
            return results.next();
        }
    }

    /**
     * Whether any version of the schema was installed, so it is not a fresh
     * install.
     */
    private static boolean hasAnyVersion(Connection connection) throws SQLException {
        if (!hasTable(connection, "pam_schema_version"))
            return false;
        try (Statement statement = connection.createStatement();
             ResultSet results = statement.executeQuery("SELECT 1 FROM pam_schema_version LIMIT 1")) {
            return results.next();
        }
    }

    private static boolean hasTable(Connection connection, String table) throws SQLException {
        try (PreparedStatement statement = connection.prepareStatement("SELECT to_regclass(?) IS NOT NULL")) {
            statement.setString(1, table);
            try (ResultSet results = statement.executeQuery()) {
                return results.next() && results.getBoolean(1);
            }
        }
    }

    /**
     * PostgreSQL adds the position of an error on further lines.
     */
    private static String firstLine(String message) {
        if (message == null)
            return "";
        int end = message.indexOf('\n');
        return end < 0 ? message : message.substring(0, end);
    }

    /**
     * Logs why the tables could not be created. When the database user lacks
     * the privilege, as with the grants of Guacamole's installation guide,
     * explains once how to create them by hand.
     */
    private void logSchemaFailure(SQLException e) {

        if (!INSUFFICIENT_PRIVILEGE.equals(e.getSQLState())) {
            logger.error("Unable to create the PAM database tables: {}", firstLine(e.getMessage()));
            return;
        }

        if (instructionsLogged) {
            logger.debug("The PAM database tables are still missing: {}", e.getMessage());
            return;
        }

        instructionsLogged = true;
        logger.error("The database user \"{}\" may not create the PAM extension's tables ({}). Create them"
                + " once as the database owner, by running schema/postgresql.sql from the extension's jar"
                + " (\"unzip -p guacamole-pam-*.jar schema/postgresql.sql | psql ...\"), then grant them to"
                + " Guacamole's user as for Guacamole's own tables:"
                + " GRANT SELECT,INSERT,UPDATE,DELETE ON ALL TABLES IN SCHEMA public TO \"{}\";"
                + " GRANT SELECT,USAGE ON ALL SEQUENCES IN SCHEMA public TO \"{}\";"
                + " Until then, connections stored in the database cannot be opened: their access cannot be checked.",
                username, firstLine(e.getMessage()), username, username);

    }

}
