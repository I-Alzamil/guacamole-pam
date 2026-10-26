package io.github.ialzamil.guacamole.pam.db;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.sql.Connection;
import java.sql.Driver;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;

import com.zaxxer.hikari.HikariConfig;
import com.zaxxer.hikari.HikariDataSource;

import org.apache.guacamole.GuacamoleException;
import org.apache.guacamole.GuacamoleServerException;
import org.apache.guacamole.environment.Environment;
import org.apache.guacamole.properties.IntegerGuacamoleProperty;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Access to the database of Guacamole's authentication whose connections are
 * managed (see {@link DatabaseSettings}): PostgreSQL, MySQL (or MariaDB) or
 * SQL Server. Reuses that authentication's properties and driver, and
 * creates this extension's own tables on first use, then runs what a fresh
 * install starts with ({@link #onFreshInstall}). The driver is loaded by
 * name, so this class loads (and {@link #getUnavailableReason} can tell why
 * the database cannot be used) even where the driver is missing.
 *
 * Connections come from a pool, opened on first use and holding at most
 * "pam-database-max-connections" (10 by default). Code holding a pooled
 * connection never asks for another, so a busy pool cannot deadlock.
 * Session-level locks, released by closing their connection, use a
 * dedicated connection instead ({@link #getDedicatedConnection}).
 */
public class PamDatabase {

    private static final Logger logger = LoggerFactory.getLogger(PamDatabase.class);

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
     * Version the schema script records once it has run, which must match
     * the latest version it inserts into "pam_schema_version". A database
     * without it runs the script, creating or upgrading the tables.
     */
    private static final int SCHEMA_VERSION = 1;

    /**
     * Lock taken by the server creating the tables (key 0), so servers
     * starting together create them one at a time: two running the script at
     * once can collide, even on "CREATE TABLE IF NOT EXISTS" with PostgreSQL.
     */
    private static final int SCHEMA_LOCK = 0x70616d64;

    /**
     * How long to wait for another server creating the tables before running
     * the script anyway, in milliseconds, and how often to try meanwhile.
     */
    private static final long SCHEMA_LOCK_WAIT_MS = 30000;
    private static final long SCHEMA_LOCK_RETRY_MS = 250;

    private final DatabaseSettings settings;

    private final SqlDialect dialect;

    /**
     * Classpath resource holding the schema of this extension's tables, for
     * the database used.
     */
    private final String schemaResource;

    private final Driver driver;

    /**
     * Whether the instructions for creating the tables by hand were logged,
     * so they are logged once rather than on every attempt.
     */
    private volatile boolean instructionsLogged = false;

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
     * Returns why this extension cannot use a Guacamole database here, or
     * null if it can (see {@link DatabaseSettings#getUnavailableReason}).
     */
    public static String getUnavailableReason(Environment environment) throws GuacamoleException {
        return DatabaseSettings.getUnavailableReason(environment);
    }

    public PamDatabase(Environment environment) throws GuacamoleException {

        settings = DatabaseSettings.fromEnvironment(environment);
        dialect = settings.getDialect();
        schemaResource = "/schema/" + dialect.getName() + ".sql";

        try {
            driver = (Driver) Class.forName(settings.getDriverClass(), true, PamDatabase.class.getClassLoader())
                    .getDeclaredConstructor().newInstance();
        }
        catch (ReflectiveOperationException | LinkageError e) {
            throw new GuacamoleServerException("Unable to load the " + dialect.getDisplayName()
                    + " JDBC driver.", e);
        }

        maxConnections = Math.max(2, environment.getProperty(MAX_CONNECTIONS, DEFAULT_MAX_CONNECTIONS));

    }

    /**
     * The SQL of the database used.
     */
    public SqlDialect getDialect() {
        return dialect;
    }

    private synchronized HikariDataSource pool() throws GuacamoleServerException {

        if (closed)
            throw new GuacamoleServerException("The PAM database is closed.");

        if (pool == null) {
            HikariConfig config = new HikariConfig();
            config.setPoolName("guacamole-pam");
            config.setDriverClassName(settings.getDriverClass());
            config.setJdbcUrl(settings.getUrl());
            config.setDataSourceProperties(settings.getProperties());
            if (settings.getSessionSetup() != null)
                config.setConnectionInitSql(settings.getSessionSetup());
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
     * session-level locks: closing it ends the database session, releasing
     * them.
     */
    public Connection getDedicatedConnection() throws GuacamoleException {
        Connection connection;
        try {
            connection = connectDirectly();
        }
        catch (SQLException e) {
            throw new GuacamoleServerException("Unable to connect to the PAM database.", e);
        }
        return withSchema(connection);
    }

    /**
     * A connection outside the pool, set up as the pool's are, whether or
     * not the tables exist.
     */
    private Connection connectDirectly() throws SQLException {
        Connection connection = driver.connect(settings.getUrl(), settings.getProperties());
        if (connection == null)
            throw new SQLException("The driver does not accept " + settings.getUrl());
        if (settings.getSessionSetup() != null) {
            try (Statement statement = connection.createStatement()) {
                statement.execute(settings.getSessionSetup());
            }
            catch (SQLException e) {
                close(connection);
                throw e;
            }
        }
        return connection;
    }

    /**
     * Waits until this server holds the lock of creating the tables, on the
     * given connection, or until another has held it too long.
     */
    private void lockSchema(Connection lock) throws SQLException {
        long end = System.currentTimeMillis() + SCHEMA_LOCK_WAIT_MS;
        while (!dialect.tryLock(lock, SCHEMA_LOCK, 0)) {
            if (System.currentTimeMillis() >= end) {
                logger.warn("Another server has been creating the PAM database tables for {} seconds: creating"
                        + " them anyway.", SCHEMA_LOCK_WAIT_MS / 1000);
                return;
            }
            try {
                Thread.sleep(SCHEMA_LOCK_RETRY_MS);
            }
            catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                throw new SQLException("Interrupted while waiting to create the PAM database tables.", e);
            }
        }
    }

    private static void close(Connection connection) {
        try {
            connection.close();
        }
        catch (SQLException ignored) {
        }
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
                close(connection);
                throw new SchemaUnavailableException("Unable to create the PAM database tables.", e);
            }
        }

        return connection;

    }

    private synchronized void ensureSchema(Connection connection) throws SQLException {

        if (schemaReady)
            return;

        String schema;
        try (InputStream in = PamDatabase.class.getResourceAsStream(schemaResource)) {
            schema = new String(in.readAllBytes(), StandardCharsets.UTF_8);
        }
        catch (IOException | NullPointerException e) {
            throw new SQLException("Unable to read " + schemaResource, e);
        }

        // Already there: nothing to run, which also lets a database user
        // without the privilege to create tables use tables created for it
        // (PostgreSQL refuses even "CREATE TABLE IF NOT EXISTS" to it)
        if (!hasVersion(connection, SCHEMA_VERSION)) {
            // Closing the lock's own connection releases it
            try (Connection lock = connectDirectly()) {
                lockSchema(lock);
                createSchema(connection, schema);
            }
        }

        schemaReady = true;
        logger.info("PAM database schema is ready.");

    }

    /**
     * Runs the schema script, unless another server did meanwhile, and on a
     * fresh install the initializers.
     */
    private void createSchema(Connection connection, String schema) throws SQLException {

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

    }

    /**
     * Whether the tables of the given version of the schema exist: the
     * schema script records its versions last, once every statement ran.
     */
    private boolean hasVersion(Connection connection, int version) throws SQLException {
        if (!dialect.hasTable(connection, "pam_schema_version"))
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
    private boolean hasAnyVersion(Connection connection) throws SQLException {
        if (!dialect.hasTable(connection, "pam_schema_version"))
            return false;
        try (Statement statement = connection.createStatement();
             ResultSet results = statement.executeQuery("SELECT COUNT(*) FROM pam_schema_version")) {
            return results.next() && results.getInt(1) > 0;
        }
    }

    /**
     * Logs why the tables could not be created. When the database user lacks
     * the privilege, as with the grants of Guacamole's installation guide,
     * explains once how to create them by hand.
     */
    private void logSchemaFailure(SQLException e) {

        if (!dialect.isPermissionDenied(e)) {
            logger.error("Unable to create the PAM database tables: {}", SqlDialect.firstLine(e.getMessage()));
            return;
        }

        if (instructionsLogged) {
            logger.debug("The PAM database tables are still missing: {}", e.getMessage());
            return;
        }

        instructionsLogged = true;
        logger.error("The database user \"{}\" may not create the PAM extension's tables ({}). {} Until then,"
                + " connections stored in the database cannot be opened: their access cannot be checked.",
                settings.getUsername(), SqlDialect.firstLine(e.getMessage()),
                dialect.getManualSchemaInstructions(settings.getUsername()));

    }

}
