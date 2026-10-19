package org.apache.guacamole.pam.db;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.sql.Connection;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.Properties;

import org.apache.guacamole.GuacamoleException;
import org.apache.guacamole.GuacamoleServerException;
import org.apache.guacamole.environment.Environment;
import org.apache.guacamole.properties.IntegerGuacamoleProperty;
import org.apache.guacamole.properties.StringGuacamoleProperty;
import org.postgresql.Driver;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Access to the Guacamole PostgreSQL database. Reuses the "postgresql-*"
 * properties of the JDBC auth extension, and creates this extension's own
 * tables on first use.
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

    private final Driver driver = new Driver();

    private final String url;

    private final Properties connectionProperties = new Properties();

    private volatile boolean schemaReady = false;

    public PamDatabase(Environment environment) throws GuacamoleException {

        url = "jdbc:postgresql://"
                + environment.getProperty(POSTGRESQL_HOSTNAME, "localhost") + ":"
                + environment.getProperty(POSTGRESQL_PORT, 5432) + "/"
                + environment.getRequiredProperty(POSTGRESQL_DATABASE);

        connectionProperties.setProperty("user", environment.getRequiredProperty(POSTGRESQL_USERNAME));
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
                logger.error("Unable to create the PAM database tables: {}", e.getMessage());
                try {
                    connection.close();
                }
                catch (SQLException ignored) {
                }
                throw new GuacamoleServerException("Unable to create the PAM database tables.", e);
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

        try (Statement statement = connection.createStatement()) {
            // Statements end with a semicolon at the end of a line
            for (String sql : schema.split(";[ \\t]*\\r?\\n")) {
                if (!sql.trim().isEmpty())
                    statement.execute(sql);
            }
        }

        SchemaMigrations.run(connection);

        schemaReady = true;
        logger.info("PAM database schema is ready.");

    }

}
