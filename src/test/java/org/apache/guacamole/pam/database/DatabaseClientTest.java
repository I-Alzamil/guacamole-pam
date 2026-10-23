package org.apache.guacamole.pam.database;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.sql.SQLException;
import java.util.HashMap;
import java.util.Map;

import org.junit.Test;

/**
 * What the database client computes and quotes itself: the hashes it sends
 * instead of passwords, against values computed elsewhere, and the quoting
 * of names and strings it writes into statements. The live suites test it
 * against the databases themselves.
 */
public class DatabaseClientTest {

    /**
     * Against Python's hashlib and hmac, for the same salt: the verifier
     * PostgreSQL 18 accepted as the password "T3-Hashed-Pass5".
     */
    @Test
    public void computesScramVerifiersAsPostgreSql() {
        byte[] salt = new byte[16];
        for (int i = 0; i < salt.length; i++)
            salt[i] = (byte) i;
        assertEquals("SCRAM-SHA-256$4096:AAECAwQFBgcICQoLDA0ODw==$JgZWF63XwoHK3PNCSO0YphWaunUAhULRTmrFzJwR5Ac="
                + ":fk/a69wbgVpHrdLAHs4n1usO8rwbBx4riKzpQq23ivo=",
                DatabaseClient.scramVerifier("T3-Hashed-Pass5", salt, 4096));
    }

    @Test
    public void saltsEachScramVerifier() {
        assertFalse(DatabaseClient.scramVerifier("same").equals(DatabaseClient.scramVerifier("same")));
    }

    /**
     * As MariaDB 11.4 logged it, setting the password "T3-Hashed-Pass8".
     */
    @Test
    public void computesNativePasswordHashesAsMariaDb() {
        assertEquals("*F2BED94218EBC0C09273E7DBBB677F654C7A683E", DatabaseClient.nativePasswordHash("T3-Hashed-Pass8"));
    }

    @Test
    public void quotesNamesAndStrings() {
        assertEquals("\"dba\"", DatabaseClient.quotePostgreSqlName("dba"));
        assertEquals("\"a\"\"; DROP ROLE x; --\"", DatabaseClient.quotePostgreSqlName("a\"; DROP ROLE x; --"));
        assertEquals("[a]]; DROP LOGIN x; --]", DatabaseClient.quoteSqlServerName("a]; DROP LOGIN x; --"));
        assertEquals("N'it''s'", DatabaseClient.quoteSqlServerString("it's"));
    }

    @Test
    public void tellsRefusedAccountsFromOtherFailures() {
        assertTrue(DatabaseClient.isAuthenticationFailure(new SQLException("password authentication failed", "28P01")));
        assertTrue(DatabaseClient.isAuthenticationFailure(new SQLException("Access denied", "28000", 1045)));
        assertTrue(DatabaseClient.isAuthenticationFailure(new SQLException("Login failed for user", "S0001", 18456)));
        assertTrue(DatabaseClient.isAuthenticationFailure(new SQLException("wrapped",
                new SQLException("Access denied", "28000", 1045))));
        assertFalse(DatabaseClient.isAuthenticationFailure(new SQLException(
                "no pg_hba.conf entry for host \"10.0.0.5\", user \"dba\"", "28000")));
        assertFalse(DatabaseClient.isAuthenticationFailure(new SQLException("Host is not allowed", "HY000", 1130)));
        assertFalse(DatabaseClient.isAuthenticationFailure(new SQLException("Connection refused", "08001")));
    }

    @Test
    public void readsItsSettings() {
        Map<String, String> settings = new HashMap<>();
        settings.put(DatabaseTarget.TYPE, "mysql");
        settings.put(DatabaseTarget.HOSTNAME, "db1");
        settings.put(DatabaseTarget.USERNAME, "dba");
        DatabaseTarget target = DatabaseTarget.fromParameters(settings);
        assertEquals(3306, target.getPort());
        assertEquals("%", target.getAccountHost());
        assertTrue(target.isEncrypted());
        assertTrue(target.isVerified());
        assertEquals("MySQL or MariaDB server db1:3306", target.describe());

        settings.put(DatabaseTarget.TYPE, "sqlserver");
        settings.put(DatabaseTarget.ENCRYPTION, DatabaseTarget.ENCRYPTION_UNVERIFIED);
        target = DatabaseTarget.fromParameters(settings);
        assertEquals(1433, target.getPort());
        assertTrue(target.isEncrypted());
        assertFalse(target.isVerified());

        settings.put(DatabaseTarget.TYPE, "oracle");
        try {
            DatabaseTarget.fromParameters(settings);
            fail("An unknown database type is accepted.");
        }
        catch (IllegalArgumentException e) {
            assertEquals("The platform has no database type.", e.getMessage());
        }

        settings.put(DatabaseTarget.TYPE, "postgresql");
        settings.put(DatabaseTarget.ADMIN_USERNAME, "admin");
        settings.put(DatabaseTarget.ADMIN_PASSWORD, "secret");
        for (String hostname : new String[] { "db1", "db-1.example.org", "192.0.2.7", "2001:db8::7", "[2001:db8::7]" }) {
            settings.put(DatabaseTarget.HOSTNAME, hostname);
            assertEquals(hostname, DatabaseTarget.fromParameters(settings).getHostname());
        }
        settings.put(DatabaseTarget.DATABASE, "app_db-1");
        assertEquals("app_db-1", DatabaseTarget.fromParameters(settings).getDatabase());
        settings.remove(DatabaseTarget.ADMIN_PASSWORD);
        settings.put(DatabaseTarget.HOSTNAME, "db1");
        settings.remove(DatabaseTarget.DATABASE);
        try {
            DatabaseTarget.fromParameters(settings);
            fail("An administrator account without a password is accepted.");
        }
        catch (IllegalArgumentException e) {
            assertEquals("The administrator account has no password.", e.getMessage());
        }
    }

    /**
     * Hostnames and database names are written into JDBC URLs, where
     * anything more would set other options of the driver.
     */
    @Test
    public void refusesDriverOptionsInHostnamesAndDatabases() {
        Map<String, String> settings = new HashMap<>();
        settings.put(DatabaseTarget.TYPE, "mysql");
        settings.put(DatabaseTarget.USERNAME, "dba");

        for (String hostname : new String[] { "evil:3306/x?allowLoadLocalInfile=true", "db1/x", "db1?a=b",
                "db1;trustServerCertificate=true", "db1&a=b", "db 1", "-db1", "db1#" }) {
            settings.put(DatabaseTarget.HOSTNAME, hostname);
            try {
                DatabaseTarget.fromParameters(settings);
                fail("The hostname \"" + hostname + "\" is accepted.");
            }
            catch (IllegalArgumentException e) {
                assertTrue(e.getMessage().startsWith("Invalid database hostname"));
            }
        }

        settings.put(DatabaseTarget.HOSTNAME, "db1");
        for (String database : new String[] { "x?allowLoadLocalInfile=true", "x&autoDeserialize=true", "x;a=b",
                "x/y", "x y", "x%3Fa" }) {
            settings.put(DatabaseTarget.DATABASE, database);
            try {
                DatabaseTarget.fromParameters(settings);
                fail("The database name \"" + database + "\" is accepted.");
            }
            catch (IllegalArgumentException e) {
                assertTrue(e.getMessage().startsWith("Invalid database name"));
            }
        }
    }

}
