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
import java.util.Properties;

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
 * creates this extension's own tables on first use. The driver is loaded by
 * name, so this class loads (and {@link #getUnavailableReason} can tell why
 * the database cannot be used) even where the driver is missing.
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
     * the version it inserts into "pam_schema_version".
     */
    private static final int SCHEMA_VERSION = 3;

    /**
     * The first version, whose tables are enough to run on a single server.
     */
    private static final int SINGLE_SERVER_VERSION = 1;

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

    private volatile boolean schemaReady = false;

    private volatile boolean sessionTable = false;

    private volatile boolean passwordTable = false;

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

    }

    /**
     * Opens a new database connection, creating the extension's tables first
     * if this is the first use.
     */
    public Connection getConnection() throws GuacamoleException {
        Connection connection;
        try {
            connection = driver.connect(url, connectionProperties);
        }
        catch (SQLException e) {
            throw new GuacamoleServerException("Unable to connect to the PAM database.", e);
        }

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
            try (Statement statement = connection.createStatement()) {
                // Statements end with a semicolon at the end of a line
                for (String sql : schema.split(";[ \\t]*\\r?\\n")) {
                    if (!sql.trim().isEmpty())
                        statement.execute(sql);
                }
            }
            catch (SQLException e) {

                // Tables of the first version created by hand still work,
                // on a single server, until the new ones are created
                if (!INSUFFICIENT_PRIVILEGE.equals(e.getSQLState())
                        || !hasVersion(connection, SINGLE_SERVER_VERSION))
                    throw e;

                logger.warn("The database user \"{}\" may not upgrade the PAM extension's tables ({}). Until"
                        + " schema/postgresql.sql from the extension's jar is run again as the database owner,"
                        + " and its new tables granted to Guacamole's user, the extension works as its earlier"
                        + " versions: without \"pam_session\", servers sharing this database do not see each"
                        + " other's sessions (run a single server); without \"pam_connection_password\", the"
                        + " passwords of managed connections are not encrypted.",
                        username, firstLine(e.getMessage()));

            }
        }

        sessionTable = hasTable(connection, "pam_session");
        passwordTable = hasTable(connection, "pam_connection_password");
        schemaReady = true;
        logger.info("PAM database schema is ready.");

    }

    /**
     * Whether the tables of the given version of the schema exist: the
     * schema script records its versions last.
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

    private static boolean hasTable(Connection connection, String table) throws SQLException {
        try (PreparedStatement statement = connection.prepareStatement("SELECT to_regclass(?) IS NOT NULL")) {
            statement.setString(1, table);
            try (ResultSet results = statement.executeQuery()) {
                return results.next() && results.getBoolean(1);
            }
        }
    }

    /**
     * Whether "pam_session" exists, letting servers sharing the database
     * see each other's sessions. Known once the database was first used.
     */
    public boolean hasSessionTable() {
        return sessionTable;
    }

    /**
     * Whether "pam_connection_password" exists, letting the passwords of
     * managed connections be kept encrypted. Known once the database was
     * first used.
     */
    public boolean hasPasswordTable() {
        return passwordTable;
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
