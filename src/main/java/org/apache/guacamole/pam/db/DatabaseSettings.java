package org.apache.guacamole.pam.db;

import java.io.File;
import java.util.Arrays;
import java.util.Properties;

import org.apache.guacamole.GuacamoleException;
import org.apache.guacamole.GuacamoleServerException;
import org.apache.guacamole.environment.Environment;
import org.apache.guacamole.properties.FileGuacamoleProperty;
import org.apache.guacamole.properties.IntegerGuacamoleProperty;
import org.apache.guacamole.properties.StringGuacamoleProperty;

/**
 * How to reach the database of Guacamole's PostgreSQL authentication, whose
 * connections are managed. Everything is read from that authentication's
 * own properties, its SSL settings included, and passed to the driver as it
 * does, so this extension connects as securely as Guacamole itself.
 */
public final class DatabaseSettings {

    private static final String POSTGRESQL_DRIVER = "org.postgresql.Driver";

    /**
     * Name given to the database sessions of this extension, where the
     * database shows it.
     */
    private static final String APPLICATION_NAME = "guacamole-pam";

    private final String driverClass;

    private final String url;

    private final Properties properties = new Properties();

    private final String username;

    private DatabaseSettings(String driverClass, String url, String username) {
        this.driverClass = driverClass;
        this.url = url;
        this.username = username;
    }

    private static StringGuacamoleProperty string(String name) {
        return new StringGuacamoleProperty() {
            @Override
            public String getName() { return name; }
        };
    }

    private static IntegerGuacamoleProperty integer(String name) {
        return new IntegerGuacamoleProperty() {
            @Override
            public String getName() { return name; }
        };
    }

    private static FileGuacamoleProperty file(String name) {
        return new FileGuacamoleProperty() {
            @Override
            public String getName() { return name; }
        };
    }

    /**
     * Returns why this extension cannot use the Guacamole database here, or
     * null if it can: Guacamole's PostgreSQL authentication must be set up,
     * with its driver installed, as the extension manages its connections.
     */
    public static String getUnavailableReason(Environment environment) throws GuacamoleException {

        if (environment.getProperty(string("postgresql-database")) == null)
            return "Guacamole's PostgreSQL authentication is not configured (no \"postgresql-database\" property).";

        try {
            fromEnvironment(environment);
        }
        catch (GuacamoleServerException e) {
            return e.getMessage();
        }

        try {
            Class.forName(POSTGRESQL_DRIVER, false, DatabaseSettings.class.getClassLoader());
        }
        catch (ClassNotFoundException | LinkageError e) {
            return "the PostgreSQL JDBC driver is not installed. It comes with Guacamole's PostgreSQL"
                    + " authentication, which must be installed.";
        }

        return null;

    }

    private static String required(Environment environment, String name) throws GuacamoleException {
        return environment.getRequiredProperty(string(name));
    }

    private static String choice(Environment environment, String name, String defaultValue, String... allowed)
            throws GuacamoleException {
        String value = environment.getProperty(string(name), defaultValue).trim().toLowerCase();
        if (!Arrays.asList(allowed).contains(value))
            throw new GuacamoleServerException("\"" + name + "\" must be one of " + String.join(", ", allowed)
                    + ", not \"" + value + "\".");
        return value;
    }

    private void setIfPresent(String key, String value) {
        if (value != null)
            properties.setProperty(key, value);
    }

    private void setIfPresent(String key, File file) {
        if (file != null)
            properties.setProperty(key, file.getAbsolutePath());
    }

    /**
     * Reads the settings of Guacamole's PostgreSQL authentication.
     *
     * @throws GuacamoleServerException
     *     If they are missing or invalid; the message says why.
     */
    public static DatabaseSettings fromEnvironment(Environment environment) throws GuacamoleException {

        String url = "jdbc:postgresql://"
                + environment.getProperty(string("postgresql-hostname"), "localhost") + ":"
                + environment.getProperty(integer("postgresql-port"), 5432) + "/"
                + required(environment, "postgresql-database");

        DatabaseSettings settings = new DatabaseSettings(POSTGRESQL_DRIVER, url,
                required(environment, "postgresql-username"));
        settings.properties.setProperty("user", settings.username);
        settings.properties.setProperty("password", required(environment, "postgresql-password"));

        settings.properties.setProperty("ApplicationName", APPLICATION_NAME);
        settings.properties.setProperty("sslmode", choice(environment, "postgresql-ssl-mode", "prefer",
                "disable", "allow", "prefer", "require", "verify-ca", "verify-full"));
        settings.setIfPresent("sslcert", environment.getProperty(file("postgresql-ssl-cert-file")));
        settings.setIfPresent("sslkey", environment.getProperty(file("postgresql-ssl-key-file")));
        settings.setIfPresent("sslrootcert", environment.getProperty(file("postgresql-ssl-root-cert-file")));
        settings.setIfPresent("sslpassword", environment.getProperty(string("postgresql-ssl-key-password")));
        settings.properties.setProperty("socketTimeout",
                Integer.toString(environment.getProperty(integer("postgresql-socket-timeout"), 0)));

        return settings;

    }

    public String getDriverClass() {
        return driverClass;
    }

    public String getUrl() {
        return url;
    }

    /**
     * The driver's connection properties, credentials included.
     */
    public Properties getProperties() {
        return properties;
    }

    public String getUsername() {
        return username;
    }

}
