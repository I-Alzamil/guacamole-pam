package io.github.ialzamil.guacamole.pam.db;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

import java.io.File;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.Properties;

import org.apache.guacamole.GuacamoleException;
import org.apache.guacamole.GuacamoleServerException;
import org.apache.guacamole.environment.Environment;
import org.apache.guacamole.net.auth.GuacamoleProxyConfiguration;
import org.apache.guacamole.properties.GuacamoleProperty;
import org.apache.guacamole.protocols.ProtocolInfo;
import org.junit.Test;

/**
 * Which database is used, and that its driver gets the settings Guacamole
 * gives its own, SSL included.
 */
public class DatabaseSettingsTest {

    private static final class TestEnvironment implements Environment {

        private final Map<String, String> properties = new HashMap<>();

        TestEnvironment with(String name, String value) {
            properties.put(name, value);
            return this;
        }

        /**
         * With the required properties of the given database.
         */
        TestEnvironment database(String prefix) {
            return with(prefix + "-database", "guacamole").with(prefix + "-username", "guac")
                    .with(prefix + "-password", "secret");
        }

        @Override
        public File getGuacamoleHome() {
            return new File(".");
        }

        @Override
        public Map<String, ProtocolInfo> getProtocols() {
            return Collections.emptyMap();
        }

        @Override
        public ProtocolInfo getProtocol(String name) {
            return null;
        }

        @Override
        public <T> T getProperty(GuacamoleProperty<T> property) throws GuacamoleException {
            return property.parseValue(properties.get(property.getName()));
        }

        @Override
        public <T> T getProperty(GuacamoleProperty<T> property, T defaultValue) throws GuacamoleException {
            T value = getProperty(property);
            return value == null ? defaultValue : value;
        }

        @Override
        public <T> T getRequiredProperty(GuacamoleProperty<T> property) throws GuacamoleException {
            T value = getProperty(property);
            if (value == null)
                throw new GuacamoleServerException("Property " + property.getName() + " is required.");
            return value;
        }

        @Override
        public GuacamoleProxyConfiguration getDefaultGuacamoleProxyConfiguration() {
            return null;
        }

    }

    private static String unavailable(TestEnvironment environment) throws GuacamoleException {
        try {
            DatabaseSettings.fromEnvironment(environment);
            return null;
        }
        catch (GuacamoleServerException e) {
            return e.getMessage();
        }
    }

    @Test
    public void usesTheOnlyDatabaseConfigured() throws GuacamoleException {
        DatabaseSettings settings = DatabaseSettings.fromEnvironment(new TestEnvironment().database("mysql")
                .with("mysql-hostname", "db").with("mysql-driver", "mysql"));
        assertEquals("mysql", settings.getDialect().getName());
        assertEquals("jdbc:mysql://db:3306/guacamole", settings.getUrl());
        assertEquals("guac", settings.getProperties().getProperty("user"));
        assertEquals("SET time_zone = '+00:00'", settings.getSessionSetup());
    }

    @Test
    public void refusesSeveralDatabasesUnlessOneIsChosen() throws GuacamoleException {
        TestEnvironment environment = new TestEnvironment().database("postgresql").database("sqlserver");
        assertTrue(unavailable(environment).contains("pam-database"));
        environment.with("pam-database", "sqlserver");
        assertEquals("sqlserver", DatabaseSettings.fromEnvironment(environment).getDialect().getName());
    }

    @Test
    public void refusesNoDatabase() throws GuacamoleException {
        assertTrue(unavailable(new TestEnvironment()).contains("none"));
        assertTrue(unavailable(new TestEnvironment().with("pam-database", "mysql")).contains("not configured"));
    }

    @Test
    public void passesPostgreSqlSslSettings() throws GuacamoleException {
        Properties properties = DatabaseSettings.fromEnvironment(new TestEnvironment().database("postgresql")
                .with("postgresql-ssl-mode", "verify-full").with("postgresql-ssl-root-cert-file", "/ca.pem"))
                .getProperties();
        assertEquals("verify-full", properties.getProperty("sslmode"));
        assertEquals(new File("/ca.pem").getAbsolutePath(), properties.getProperty("sslrootcert"));
        assertNull(properties.getProperty("sslcert"));
    }

    @Test
    public void defaultsToPreferredSsl() throws GuacamoleException {
        assertEquals("prefer", DatabaseSettings.fromEnvironment(new TestEnvironment().database("postgresql"))
                .getProperties().getProperty("sslmode"));
        Properties mysql = DatabaseSettings.fromEnvironment(new TestEnvironment().database("mysql")
                .with("mysql-ssl-mode", "disabled")).getProperties();
        assertEquals("DISABLED", mysql.getProperty("sslMode"));
        assertEquals("VERIFY_IDENTITY", DatabaseSettings.fromEnvironment(new TestEnvironment().database("mysql")
                .with("mysql-ssl-mode", "verify-identity")).getProperties().getProperty("sslMode"));
        assertEquals("false", mysql.getProperty("useSSL"));
    }

    @Test
    public void refusesAnUnknownSslMode() throws GuacamoleException {
        assertTrue(unavailable(new TestEnvironment().database("postgresql")
                .with("postgresql-ssl-mode", "sometimes")).contains("postgresql-ssl-mode"));
    }

    @Test
    public void passesSqlServerSettings() throws GuacamoleException {
        DatabaseSettings settings = DatabaseSettings.fromEnvironment(new TestEnvironment().database("sqlserver")
                .with("sqlserver-instance", "PAM").with("sqlserver-trust-all-server-certificates", "true"));
        assertEquals("jdbc:sqlserver://localhost:1433", settings.getUrl());
        assertEquals("guacamole", settings.getProperties().getProperty("databaseName"));
        assertEquals("PAM", settings.getProperties().getProperty("instanceName"));
        assertEquals("true", settings.getProperties().getProperty("trustServerCertificate"));
        assertNull(settings.getSessionSetup());
        assertTrue(unavailable(new TestEnvironment().database("sqlserver").with("sqlserver-driver", "jtds"))
                .contains("microsoft2005"));
    }

}
