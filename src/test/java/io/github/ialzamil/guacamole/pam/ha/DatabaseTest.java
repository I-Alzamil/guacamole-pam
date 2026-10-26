package io.github.ialzamil.guacamole.pam.ha;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;

import org.apache.guacamole.GuacamoleException;
import org.junit.Test;

/**
 * Reaching each database as Guacamole's authentication for it is
 * configured, and its schema script.
 */
public class DatabaseTest {

    @Test
    public void isUnusedWithoutItsDatabase() throws GuacamoleException {
        assertNull(Database.fromEnvironment(DatabaseType.POSTGRESQL,
                new TestEnvironment("mysql-database", "guacamole")));
    }

    @Test
    public void readsPostgresqlAsGuacamoleDoes() throws GuacamoleException {
        Database database = Database.fromEnvironment(DatabaseType.POSTGRESQL, new TestEnvironment(
                "postgresql-hostname", "db.example", "postgresql-database", "guac",
                "postgresql-username", "guac", "postgresql-password", "secret", "postgresql-ssl-mode", "require"));
        assertEquals("jdbc:postgresql://db.example:5432/guac", database.getUrl());
        assertEquals("guac", database.getConnectionProperties().getProperty("user"));
        assertEquals("secret", database.getConnectionProperties().getProperty("password"));
        assertEquals("require", database.getConnectionProperties().getProperty("sslmode"));
    }

    @Test
    public void readsMysqlAndMariadbAsGuacamoleDoes() throws GuacamoleException {
        Database mysql = Database.fromEnvironment(DatabaseType.MYSQL, new TestEnvironment(
                "mysql-database", "guac", "mysql-port", "3307", "mysql-ssl-mode", "verify-identity",
                "mysql-server-timezone", "UTC"));
        assertEquals("jdbc:mysql://localhost:3307/guac", mysql.getUrl());
        assertEquals("VERIFY_IDENTITY", mysql.getConnectionProperties().getProperty("sslMode"));
        assertEquals("UTC", mysql.getConnectionProperties().getProperty("serverTimezone"));

        Database mariadb = Database.fromEnvironment(DatabaseType.MYSQL, new TestEnvironment(
                "mysql-database", "guac", "mysql-driver", "mariadb", "mysql-ssl-mode", "verify-identity"));
        assertEquals("jdbc:mariadb://localhost:3306/guac", mariadb.getUrl());
        assertEquals("verify-full", mariadb.getConnectionProperties().getProperty("sslMode"));
    }

    @Test
    public void readsSqlServerAsGuacamoleDoes() throws GuacamoleException {
        Database microsoft = Database.fromEnvironment(DatabaseType.SQLSERVER, new TestEnvironment(
                "sqlserver-hostname", "mssql", "sqlserver-database", "guac", "sqlserver-instance", "GUAC",
                "sqlserver-trust-all-server-certificates", "true"));
        assertEquals("jdbc:sqlserver://mssql:1433", microsoft.getUrl());
        assertEquals("guac", microsoft.getConnectionProperties().getProperty("databaseName"));
        assertEquals("GUAC", microsoft.getConnectionProperties().getProperty("instanceName"));
        assertEquals("true", microsoft.getConnectionProperties().getProperty("trustServerCertificate"));

        Database untrusting = Database.fromEnvironment(DatabaseType.SQLSERVER, new TestEnvironment(
                "sqlserver-database", "guac"));
        assertNull(untrusting.getConnectionProperties().getProperty("trustServerCertificate"));

        Database jtds = Database.fromEnvironment(DatabaseType.SQLSERVER, new TestEnvironment(
                "sqlserver-database", "guac", "sqlserver-driver", "jtds"));
        assertEquals("jdbc:jtds:sqlserver://localhost:1433/guac", jtds.getUrl());
    }

    @Test
    public void refusesDriversItDoesNotSupport() {
        try {
            Database.fromEnvironment(DatabaseType.SQLSERVER, new TestEnvironment(
                    "sqlserver-database", "guac", "sqlserver-driver", "datadirect"));
            fail("Accepted an unsupported driver.");
        }
        catch (GuacamoleException e) {
            assertTrue(e.getMessage(), e.getMessage().contains("datadirect"));
        }
    }

    @Test
    public void splitsSchemaScripts() {
        assertArrayEquals(new String[] { "CREATE TABLE a (\n  x integer\n)", "INSERT INTO a VALUES (1)" },
                Database.statements("-- comment;\nCREATE TABLE a (\n  x integer\n);\n\nINSERT INTO a VALUES (1);\n"));
    }

    @Test
    public void hasASchemaPerDatabase() throws IOException {
        for (DatabaseType type : DatabaseType.values()) {
            try (InputStream schema = Database.class.getResourceAsStream(type.getSchemaResource())) {
                String text = new String(schema.readAllBytes(), StandardCharsets.UTF_8);
                // Eight tables and the lock's row, and PostgreSQL's indexes of its own
                assertEquals(type + " statements", type == DatabaseType.POSTGRESQL ? 12 : 9,
                        Database.statements(text).length);
                for (String table : new String[] { "pam_ha_server", "pam_ha_session",
                        "pam_ha_lock", "pam_ha_share", "pam_ha_login", "pam_ha_ban",
                        "pam_ha_totp", "pam_ha_recording" })
                    assertTrue(type + " " + table, text.contains(table));
            }
        }
    }

}
