package org.apache.guacamole.pam.db;

import java.io.IOException;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import com.fasterxml.jackson.databind.ObjectMapper;

import org.apache.guacamole.pam.AccountProtocol;
import org.apache.guacamole.pam.PamAttributes;
import org.apache.guacamole.pam.ldap.LdapTarget;
import org.apache.guacamole.pam.management.LdapManagementType;
import org.apache.guacamole.pam.management.SshManagementType;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Schema upgrades needing more than plain SQL, run after the schema script.
 * Each runs once, in a transaction, and records its version.
 */
final class SchemaMigrations {

    private static final Logger logger = LoggerFactory.getLogger(SchemaMigrations.class);

    private static final ObjectMapper JSON = new ObjectMapper();

    /**
     * Connection parameter of version 3 naming how an Account was managed.
     */
    private static final String LEGACY_MANAGEMENT = "account-management";

    /**
     * Connection parameters of version 3 Account connections managed over
     * LDAP, which now belong to their platform.
     */
    private static final List<String> LEGACY_LDAP_SETTINGS = Arrays.asList(
            LdapTarget.HOSTNAME, LdapTarget.PORT, LdapTarget.ENCRYPTION, LdapTarget.CERTIFICATE,
            LdapTarget.DIRECTORY_TYPE, LdapTarget.ADMIN_DN);

    private SchemaMigrations() {
    }

    static void run(Connection connection) throws SQLException {
        if (!isApplied(connection, 4))
            inTransaction(connection, () -> migrateToPlatforms(connection), 4);
        if (!isApplied(connection, 5))
            inTransaction(connection, () -> migrateToRequestsByDefault(connection), 5);
    }

    /**
     * Version 5: requests become the default, connections opting out
     * instead of in. Connections that did not require a request keep
     * allowing access without one, so the upgrade locks nobody out; new
     * connections require a request unless set otherwise.
     */
    private static void migrateToRequestsByDefault(Connection connection) throws SQLException {

        try (PreparedStatement statement = connection.prepareStatement(
                "INSERT INTO guacamole_connection_attribute (connection_id, attribute_name, attribute_value)"
              + " SELECT c.connection_id, ?, 'true' FROM guacamole_connection c"
              + " WHERE c.protocol <> ?"
              + " AND NOT EXISTS (SELECT 1 FROM guacamole_connection_attribute a WHERE a.connection_id = c.connection_id"
              + "   AND ((a.attribute_name = ? AND a.attribute_value = 'true')"
              + "   OR (a.attribute_name = ? AND a.attribute_value NOT IN ('', '0'))))"
              + " ON CONFLICT (connection_id, attribute_name) DO NOTHING")) {
            statement.setString(1, PamAttributes.REQUEST_EXEMPT);
            statement.setString(2, AccountProtocol.NAME);
            statement.setString(3, PamAttributes.LEGACY_REQUEST_REQUIRED);
            statement.setString(4, PamAttributes.APPROVALS_REQUIRED);
            int exempted = statement.executeUpdate();
            logger.info("{} existing connection(s) keep allowing access without a request.", exempted);
        }

        try (PreparedStatement statement = connection.prepareStatement(
                "DELETE FROM guacamole_connection_attribute WHERE attribute_name = ?")) {
            statement.setString(1, PamAttributes.LEGACY_REQUEST_REQUIRED);
            statement.executeUpdate();
        }

    }

    /**
     * Version 4: sequence profiles become SSH platforms (keeping their
     * identifiers, so connections keep pointing at them), and LDAP settings
     * of Account connections become one LDAP platform per connection.
     */
    private static void migrateToPlatforms(Connection connection) throws SQLException {

        boolean hasProfiles;
        try (Statement statement = connection.createStatement();
             ResultSet results = statement.executeQuery("SELECT to_regclass('pam_sequence_profile') IS NOT NULL")) {
            results.next();
            hasProfiles = results.getBoolean(1);
        }

        if (hasProfiles) {
            try (Statement statement = connection.createStatement()) {

                int converted = statement.executeUpdate(
                    "INSERT INTO pam_platform (platform_id, name, description, type, settings, last_modified)"
                  + " SELECT profile_id, name, description, '" + SshManagementType.NAME + "',"
                  + " json_build_object('" + SshManagementType.SCRIPT + "', script)::text, last_modified"
                  + " FROM pam_sequence_profile");

                statement.execute("SELECT setval(pg_get_serial_sequence('pam_platform', 'platform_id'),"
                        + " (SELECT coalesce(max(platform_id), 0) + 1 FROM pam_platform), false)");

                statement.executeUpdate("UPDATE guacamole_connection_attribute SET attribute_name = '"
                        + PamAttributes.PLATFORM + "' WHERE attribute_name = '"
                        + PamAttributes.LEGACY_SEQUENCE_PROFILE + "'");

                statement.execute("DROP TABLE pam_sequence_profile");
                logger.info("Converted {} sequence profiles to SSH platforms.", converted);

            }
        }

        // Account connections managed over LDAP
        Map<Integer, String> ldapAccounts = new LinkedHashMap<>();
        try (PreparedStatement statement = connection.prepareStatement(
                "SELECT c.connection_id, c.connection_name FROM guacamole_connection c"
              + " JOIN guacamole_connection_parameter p ON p.connection_id = c.connection_id"
              + " WHERE c.protocol = ? AND p.parameter_name = ? AND p.parameter_value = ?")) {
            statement.setString(1, AccountProtocol.NAME);
            statement.setString(2, LEGACY_MANAGEMENT);
            statement.setString(3, LdapManagementType.NAME);
            try (ResultSet results = statement.executeQuery()) {
                while (results.next())
                    ldapAccounts.put(results.getInt(1), results.getString(2));
            }
        }

        for (Map.Entry<Integer, String> account : ldapAccounts.entrySet())
            convertLdapAccount(connection, account.getKey(), account.getValue());

        // What the old parameter said now lives in the platform attribute
        try (PreparedStatement statement = connection.prepareStatement(
                "DELETE FROM guacamole_connection_parameter WHERE parameter_name = ?")) {
            statement.setString(1, LEGACY_MANAGEMENT);
            statement.executeUpdate();
        }

    }

    private static void convertLdapAccount(Connection connection, int id, String name) throws SQLException {

        Map<String, String> parameters = new HashMap<>();
        try (PreparedStatement statement = connection.prepareStatement(
                "SELECT parameter_name, parameter_value FROM guacamole_connection_parameter WHERE connection_id = ?")) {
            statement.setInt(1, id);
            try (ResultSet results = statement.executeQuery()) {
                while (results.next())
                    parameters.put(results.getString(1), results.getString(2));
            }
        }

        Map<String, String> settings = new HashMap<>();
        for (String setting : LEGACY_LDAP_SETTINGS) {
            if (parameters.get(setting) != null && !parameters.get(setting).isEmpty())
                settings.put(setting, parameters.get(setting));
        }

        Map<String, String> secrets = new HashMap<>();
        if (parameters.get(LdapTarget.ADMIN_PASSWORD) != null && !parameters.get(LdapTarget.ADMIN_PASSWORD).isEmpty())
            secrets.put(LdapTarget.ADMIN_PASSWORD, parameters.get(LdapTarget.ADMIN_PASSWORD));

        int platformId;
        try (PreparedStatement statement = connection.prepareStatement(
                "INSERT INTO pam_platform (name, description, type, settings, secrets)"
              + " VALUES (?, ?, ?, ?, ?) RETURNING platform_id")) {
            statement.setString(1, uniqueName(connection, "Directory of " + name));
            statement.setString(2, "Created from the LDAP settings of \"" + name + "\" on upgrade.");
            statement.setString(3, LdapManagementType.NAME);
            statement.setString(4, toJson(settings));
            statement.setString(5, toJson(secrets));
            try (ResultSet results = statement.executeQuery()) {
                results.next();
                platformId = results.getInt(1);
            }
        }

        setAttribute(connection, id, PamAttributes.PLATFORM, Integer.toString(platformId));
        if (parameters.get(LdapTarget.USER_DN) != null)
            setAttribute(connection, id, LdapManagementType.LDAP_DN, parameters.get(LdapTarget.USER_DN));

        // The settings, including the rotation account password, now belong
        // to the platform only
        List<String> moved = new ArrayList<>(LEGACY_LDAP_SETTINGS);
        moved.add(LdapTarget.ADMIN_PASSWORD);
        moved.add(LdapTarget.USER_DN);
        try (PreparedStatement statement = connection.prepareStatement(
                "DELETE FROM guacamole_connection_parameter WHERE connection_id = ? AND parameter_name = ANY (?)")) {
            statement.setInt(1, id);
            statement.setArray(2, connection.createArrayOf("varchar", moved.toArray()));
            statement.executeUpdate();
        }

        logger.info("Moved the LDAP settings of connection \"{}\" to platform {}.", name, platformId);

    }

    private static String uniqueName(Connection connection, String base) throws SQLException {
        String name = base.length() > 120 ? base.substring(0, 120) : base;
        for (int i = 2; exists(connection, name); i++)
            name = base + " (" + i + ")";
        return name;
    }

    private static boolean exists(Connection connection, String name) throws SQLException {
        try (PreparedStatement statement = connection.prepareStatement(
                "SELECT 1 FROM pam_platform WHERE name = ?")) {
            statement.setString(1, name);
            try (ResultSet results = statement.executeQuery()) {
                return results.next();
            }
        }
    }

    private static void setAttribute(Connection connection, int id, String name, String value) throws SQLException {
        try (PreparedStatement statement = connection.prepareStatement(
                "INSERT INTO guacamole_connection_attribute (connection_id, attribute_name, attribute_value)"
              + " VALUES (?, ?, ?) ON CONFLICT (connection_id, attribute_name)"
              + " DO UPDATE SET attribute_value = EXCLUDED.attribute_value")) {
            statement.setInt(1, id);
            statement.setString(2, name);
            statement.setString(3, value);
            statement.executeUpdate();
        }
    }

    private static String toJson(Map<String, String> values) throws SQLException {
        try {
            return JSON.writeValueAsString(values);
        }
        catch (IOException e) {
            throw new SQLException(e);
        }
    }

    private static boolean isApplied(Connection connection, int version) throws SQLException {
        try (PreparedStatement statement = connection.prepareStatement(
                "SELECT 1 FROM pam_schema_version WHERE version = ?")) {
            statement.setInt(1, version);
            try (ResultSet results = statement.executeQuery()) {
                return results.next();
            }
        }
    }

    private interface Step {
        void run() throws SQLException;
    }

    private static void inTransaction(Connection connection, Step step, int version) throws SQLException {

        boolean autoCommit = connection.getAutoCommit();
        connection.setAutoCommit(false);

        try {

            step.run();

            try (PreparedStatement statement = connection.prepareStatement(
                    "INSERT INTO pam_schema_version (version) VALUES (?)")) {
                statement.setInt(1, version);
                statement.executeUpdate();
            }

            connection.commit();
            logger.info("PAM database upgraded to version {}.", version);

        }
        catch (SQLException e) {
            connection.rollback();
            throw e;
        }
        finally {
            connection.setAutoCommit(autoCommit);
        }

    }

}
