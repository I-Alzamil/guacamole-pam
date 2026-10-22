package org.apache.guacamole.pam.db;

import java.io.File;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Properties;

import org.apache.guacamole.GuacamoleException;
import org.apache.guacamole.GuacamoleServerException;
import org.apache.guacamole.environment.Environment;
import org.apache.guacamole.properties.BooleanGuacamoleProperty;
import org.apache.guacamole.properties.FileGuacamoleProperty;
import org.apache.guacamole.properties.IntegerGuacamoleProperty;
import org.apache.guacamole.properties.StringGuacamoleProperty;

/**
 * How to reach the database of the Guacamole authentication whose
 * connections are managed: PostgreSQL, MySQL (or MariaDB) or SQL Server.
 * Everything is read from that authentication's own properties, its SSL
 * settings included, and passed to the same driver as it does, so this
 * extension connects as securely as Guacamole itself.
 *
 * The database is the one whose authentication is configured, or, if
 * several are, the one "pam-database" names.
 */
public final class DatabaseSettings {

    private static final List<String> DATABASES = Arrays.asList("postgresql", "mysql", "sqlserver");

    private static final StringGuacamoleProperty PAM_DATABASE = string("pam-database");

    private static final String POSTGRESQL_DRIVER = "org.postgresql.Driver";

    private static final String MYSQL_DRIVER = "com.mysql.cj.jdbc.Driver";

    private static final String MARIADB_DRIVER = "org.mariadb.jdbc.Driver";

    private static final String SQLSERVER_DRIVER = "com.microsoft.sqlserver.jdbc.SQLServerDriver";

    /**
     * Name given to the database sessions of this extension, where the
     * database shows it.
     */
    private static final String APPLICATION_NAME = "guacamole-pam";

    private final SqlDialect dialect;

    private final String driverClass;

    private final String url;

    private final Properties properties = new Properties();

    private final String username;

    private DatabaseSettings(SqlDialect dialect, String driverClass, String url, String username) {
        this.dialect = dialect;
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

    private static BooleanGuacamoleProperty bool(String name) {
        return new BooleanGuacamoleProperty() {
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
     * The database whose connections are managed ("postgresql", "mysql" or
     * "sqlserver"), or why there is none: the message of the exception.
     */
    private static String chooseDatabase(Environment environment) throws GuacamoleException {

        String chosen = environment.getProperty(PAM_DATABASE);
        if (chosen != null) {
            chosen = chosen.trim().toLowerCase();
            if (!DATABASES.contains(chosen))
                throw new GuacamoleServerException("\"" + PAM_DATABASE.getName() + "\" must be one of "
                        + String.join(", ", DATABASES) + ".");
            if (environment.getProperty(string(chosen + "-database")) == null)
                throw new GuacamoleServerException("\"" + PAM_DATABASE.getName() + "\" names " + chosen
                        + ", whose Guacamole authentication is not configured (no \"" + chosen
                        + "-database\" property).");
            return chosen;
        }

        List<String> configured = new ArrayList<>();
        for (String database : DATABASES) {
            if (environment.getProperty(string(database + "-database")) != null)
                configured.add(database);
        }

        if (configured.isEmpty())
            throw new GuacamoleServerException("none of Guacamole's database authentications (PostgreSQL,"
                    + " MySQL or SQL Server) is configured.");

        if (configured.size() > 1)
            throw new GuacamoleServerException("several of Guacamole's database authentications are configured ("
                    + String.join(", ", configured) + "). Set \"" + PAM_DATABASE.getName()
                    + "\" to the one whose connections the extension manages.");

        return configured.get(0);

    }

    /**
     * Returns why this extension cannot use a Guacamole database here, or
     * null if it can: one of Guacamole's database authentications must be
     * set up, with its driver installed, as the extension manages its
     * connections.
     */
    public static String getUnavailableReason(Environment environment) throws GuacamoleException {

        DatabaseSettings settings;
        try {
            settings = fromEnvironment(environment);
        }
        catch (GuacamoleServerException e) {
            return e.getMessage();
        }

        try {
            Class.forName(settings.driverClass, false, DatabaseSettings.class.getClassLoader());
        }
        catch (ClassNotFoundException | LinkageError e) {
            return "the " + settings.dialect.getDisplayName() + " JDBC driver (" + settings.driverClass
                    + ") is not installed. It comes with Guacamole's " + settings.dialect.getDisplayName()
                    + " authentication, which must be installed.";
        }

        return null;

    }

    /**
     * Reads the settings of the database whose connections are managed.
     *
     * @throws GuacamoleServerException
     *     If there is no such database, or its settings are invalid; the
     *     message says why.
     */
    public static DatabaseSettings fromEnvironment(Environment environment) throws GuacamoleException {
        String database = chooseDatabase(environment);
        switch (database) {
            case "mysql":
                return mysql(environment);
            case "sqlserver":
                return sqlServer(environment);
            default:
                return postgresql(environment);
        }
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

    private void setCredentials(Environment environment, String prefix) throws GuacamoleException {
        properties.setProperty("user", username);
        properties.setProperty("password", required(environment, prefix + "-password"));
    }

    private static DatabaseSettings postgresql(Environment environment) throws GuacamoleException {

        String url = "jdbc:postgresql://"
                + environment.getProperty(string("postgresql-hostname"), "localhost") + ":"
                + environment.getProperty(integer("postgresql-port"), 5432) + "/"
                + required(environment, "postgresql-database");

        DatabaseSettings settings = new DatabaseSettings(new PostgreSqlDialect(), POSTGRESQL_DRIVER, url,
                required(environment, "postgresql-username"));
        settings.setCredentials(environment, "postgresql");

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

    /**
     * Whether a driver class can be loaded, as Guacamole checks before
     * choosing between the MariaDB and MySQL drivers.
     */
    private static boolean isInstalled(String driverClass) {
        try {
            Class.forName(driverClass, false, DatabaseSettings.class.getClassLoader());
            return true;
        }
        catch (ClassNotFoundException | LinkageError e) {
            return false;
        }
    }

    private static DatabaseSettings mysql(Environment environment) throws GuacamoleException {

        // Like Guacamole: the MariaDB driver if installed, unless told
        String driver = environment.getProperty(string("mysql-driver")) == null
                ? (isInstalled(MARIADB_DRIVER) ? "mariadb" : "mysql")
                : choice(environment, "mysql-driver", null, "mysql", "mariadb");

        String url = "jdbc:" + driver + "://"
                + environment.getProperty(string("mysql-hostname"), "localhost") + ":"
                + environment.getProperty(integer("mysql-port"), 3306) + "/"
                + required(environment, "mysql-database");

        DatabaseSettings settings = new DatabaseSettings(new MySqlDialect(),
                driver.equals("mariadb") ? MARIADB_DRIVER : MYSQL_DRIVER, url, required(environment, "mysql-username"));
        settings.setCredentials(environment, "mysql");

        settings.properties.setProperty("characterEncoding", "UTF-8");
        String sslMode = choice(environment, "mysql-ssl-mode", "preferred",
                "disabled", "preferred", "required", "verify-ca", "verify-identity");
        settings.properties.setProperty("sslMode", sslMode);
        settings.properties.setProperty("useSSL", Boolean.toString(!sslMode.equals("disabled")));

        File trustStore = environment.getProperty(file("mysql-ssl-trust-store"));
        if (trustStore != null)
            settings.properties.setProperty("trustCertificateKeyStoreUrl", trustStore.toURI().toString());
        settings.setIfPresent("trustCertificateKeyStorePassword",
                environment.getProperty(string("mysql-ssl-trust-password")));

        File clientStore = environment.getProperty(file("mysql-ssl-client-store"));
        if (clientStore != null)
            settings.properties.setProperty("clientCertificateKeyStoreUrl", clientStore.toURI().toString());
        settings.setIfPresent("clientCertificateKeyStorePassword",
                environment.getProperty(string("mysql-ssl-client-password")));

        return settings;

    }

    private static DatabaseSettings sqlServer(Environment environment) throws GuacamoleException {

        String driver = choice(environment, "sqlserver-driver", "microsoft2005",
                "microsoft2005", "microsoft", "jtds", "datadirect");
        if (!driver.equals("microsoft2005"))
            throw new GuacamoleServerException("the extension supports only Microsoft's current SQL Server driver"
                    + " (\"sqlserver-driver: microsoft2005\", the default), not \"" + driver + "\".");

        String url = "jdbc:sqlserver://"
                + environment.getProperty(string("sqlserver-hostname"), "localhost") + ":"
                + environment.getProperty(integer("sqlserver-port"), 1433);

        DatabaseSettings settings = new DatabaseSettings(new SqlServerDialect(), SQLSERVER_DRIVER, url,
                required(environment, "sqlserver-username"));
        settings.setCredentials(environment, "sqlserver");

        settings.properties.setProperty("databaseName", required(environment, "sqlserver-database"));
        settings.properties.setProperty("applicationName", APPLICATION_NAME);
        settings.setIfPresent("instanceName", environment.getProperty(string("sqlserver-instance")));
        if (environment.getProperty(bool("sqlserver-trust-all-server-certificates"), false))
            settings.properties.setProperty("trustServerCertificate", "true");

        return settings;

    }

    public SqlDialect getDialect() {
        return dialect;
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

    /**
     * SQL run first on every database session, or null.
     */
    public String getSessionSetup() {
        return dialect instanceof MySqlDialect ? MySqlDialect.SESSION_SETUP : null;
    }

}
