package org.apache.guacamole.pam.platform;

import java.io.IOException;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.TreeSet;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;

import org.apache.guacamole.GuacamoleClientException;
import org.apache.guacamole.GuacamoleException;
import org.apache.guacamole.GuacamoleResourceNotFoundException;
import org.apache.guacamole.GuacamoleServerException;
import org.apache.guacamole.form.Field;
import org.apache.guacamole.form.Form;
import org.apache.guacamole.pam.PamAttributes;
import org.apache.guacamole.pam.Values;
import org.apache.guacamole.pam.crypto.MigrationReport;
import org.apache.guacamole.pam.crypto.Secrets;
import org.apache.guacamole.pam.db.PamDatabase;
import org.apache.guacamole.pam.management.ManagementType;
import org.apache.guacamole.pam.management.ManagementTypes;

/**
 * Storage of platforms in "pam_platform". Settings, secrets and policy are
 * stored as JSON objects, secrets in their own column, encrypted if a key is
 * set (see {@link Secrets}). Platforms returned here carry their secrets for
 * server-side use; {@link Platform} never serializes them, so they cannot
 * reach a client.
 */
public class PlatformRepository {

    private static final String UNIQUE_VIOLATION = "23505";

    private static final int MAX_NAME_LENGTH = 128;

    private static final int MAX_DESCRIPTION_LENGTH = 1024;

    private static final int MAX_INTERVAL_HOURS = 24 * 365;

    private static final ObjectMapper JSON = new ObjectMapper();

    private static final TypeReference<Map<String, String>> STRING_MAP = new TypeReference<Map<String, String>>() { };

    private static final String SELECT = "SELECT platform_id, name, description, type, settings, secrets, policy,"
            + " last_modified FROM pam_platform";

    private final PamDatabase database;

    private final Secrets secrets;

    public PlatformRepository(PamDatabase database, Secrets secrets) {
        this.database = database;
        this.secrets = secrets;
    }

    /**
     * Lists platforms ordered by name, without secrets. Settings and policy
     * are only included when requested, for administrators.
     */
    public List<Platform> list(boolean includeSettings) throws GuacamoleException {

        List<Platform> platforms = new ArrayList<>();

        try (Connection connection = database.getConnection();
             PreparedStatement statement = connection.prepareStatement(SELECT + " ORDER BY lower(name)");
             ResultSet results = statement.executeQuery()) {

            while (results.next()) {
                // Only the editor shows which secrets are stored (getWithSecrets)
                Platform platform = toPlatform(results, false);
                if (!includeSettings) {
                    platform.setSettings(null);
                    platform.setPolicy(null);
                    platform.setSecrets(null);
                    platform.setDescription(null);
                }
                platforms.add(platform);
            }

        }
        catch (SQLException e) {
            throw new GuacamoleServerException("Unable to list platforms.", e);
        }

        return platforms;

    }

    /**
     * Returns every platform by identifier, without secrets.
     */
    public Map<String, Platform> getAll() throws GuacamoleException {

        Map<String, Platform> platforms = new HashMap<>();

        try (Connection connection = database.getConnection();
             PreparedStatement statement = connection.prepareStatement(SELECT);
             ResultSet results = statement.executeQuery()) {

            while (results.next()) {
                Platform platform = toPlatform(results, false);
                platforms.put(Integer.toString(platform.getId()), platform);
            }

        }
        catch (SQLException e) {
            throw new GuacamoleServerException("Unable to list platforms.", e);
        }

        return platforms;

    }

    /**
     * Returns the platform with the given identifier, without secrets, or
     * null.
     */
    public Platform get(int id) throws GuacamoleException {
        return get(id, false);
    }

    /**
     * Returns the platform with the given identifier, with its secrets
     * decrypted for server-side use, or null.
     */
    public Platform getWithSecrets(int id) throws GuacamoleException {
        return get(id, true);
    }

    /**
     * Returns the platform named by a connection attribute value, with its
     * secrets, or null.
     */
    public Platform getWithSecrets(String id) throws GuacamoleException {
        Integer number = Values.parseId(id);
        return number == null ? null : get(number, true);
    }

    private Platform get(int id, boolean withSecrets) throws GuacamoleException {

        try (Connection connection = database.getConnection();
             PreparedStatement statement = connection.prepareStatement(SELECT + " WHERE platform_id = ?")) {

            statement.setInt(1, id);
            try (ResultSet results = statement.executeQuery()) {
                return results.next() ? toPlatform(results, withSecrets) : null;
            }

        }
        catch (SQLException e) {
            throw new GuacamoleServerException("Unable to read platform " + id + ".", e);
        }

    }

    /**
     * Returns the platform named by a connection attribute value, without
     * secrets, or null.
     */
    public Platform get(String id) throws GuacamoleException {
        Integer number = Values.parseId(id);
        return number == null ? null : get(number, false);
    }

    public Platform create(Platform platform) throws GuacamoleException {

        Platform clean = sanitize(platform, null);

        int id;
        try (Connection connection = database.getConnection();
             PreparedStatement statement = connection.prepareStatement(
                 "INSERT INTO pam_platform (name, description, type, settings, secrets, policy)"
               + " VALUES (?, ?, ?, ?, ?, ?) RETURNING platform_id")) {

            statement.setString(1, clean.getName());
            statement.setString(2, clean.getDescription());
            statement.setString(3, clean.getType());
            statement.setString(4, toJson(clean.getSettings()));
            statement.setString(5, secrets.protect(Secrets.PLATFORM_SECRETS, toJson(clean.getSecrets())));
            statement.setString(6, toJson(clean.getPolicy()));

            try (ResultSet results = statement.executeQuery()) {
                results.next();
                id = results.getInt(1);
            }

        }
        catch (SQLException e) {
            throw translate(e, clean);
        }

        return getWithSecrets(id);

    }

    /**
     * Updates a platform. Its type cannot change, and secrets left empty
     * keep their stored value.
     */
    public Platform update(int id, Platform platform) throws GuacamoleException {

        Platform existing = getWithSecrets(id);
        if (existing == null)
            throw new GuacamoleResourceNotFoundException("No such platform.");

        if (platform != null && platform.getType() != null && !platform.getType().equals(existing.getType()))
            throw new GuacamoleClientException("The type of a platform cannot be changed.");

        if (platform != null)
            platform.setType(existing.getType());

        Platform clean = sanitize(platform, existing);

        try (Connection connection = database.getConnection();
             PreparedStatement statement = connection.prepareStatement(
                 "UPDATE pam_platform SET name = ?, description = ?, settings = ?, secrets = ?, policy = ?,"
               + " last_modified = CURRENT_TIMESTAMP WHERE platform_id = ?")) {

            statement.setString(1, clean.getName());
            statement.setString(2, clean.getDescription());
            statement.setString(3, toJson(clean.getSettings()));
            statement.setString(4, secrets.protect(Secrets.PLATFORM_SECRETS, toJson(clean.getSecrets())));
            statement.setString(5, toJson(clean.getPolicy()));
            statement.setInt(6, id);
            statement.executeUpdate();

        }
        catch (SQLException e) {
            throw translate(e, clean);
        }

        return getWithSecrets(id);

    }

    /**
     * Deletes a platform. Platforms still used by a connection cannot be
     * deleted.
     */
    public void delete(int id) throws GuacamoleException {

        try (Connection connection = database.getConnection()) {

            try (PreparedStatement statement = connection.prepareStatement(
                    "SELECT c.connection_name FROM guacamole_connection_attribute a"
                  + " JOIN guacamole_connection c ON c.connection_id = a.connection_id"
                  + " WHERE a.attribute_name = ? AND a.attribute_value = ?"
                  + " ORDER BY c.connection_name")) {

                statement.setString(1, PamAttributes.PLATFORM);
                statement.setString(2, Integer.toString(id));

                List<String> names = new ArrayList<>();
                try (ResultSet results = statement.executeQuery()) {
                    while (results.next())
                        names.add(results.getString(1));
                }

                if (!names.isEmpty())
                    throw new GuacamoleClientException("This platform is still used by: "
                            + String.join(", ", names) + ".");

            }

            try (PreparedStatement statement = connection.prepareStatement(
                    "DELETE FROM pam_platform WHERE platform_id = ?")) {
                statement.setInt(1, id);
                if (statement.executeUpdate() == 0)
                    throw new GuacamoleResourceNotFoundException("No such platform.");
            }

        }
        catch (SQLException e) {
            throw new GuacamoleServerException("Unable to delete platform " + id + ".", e);
        }

    }

    /**
     * Validates a platform sent by a client, keeping only the fields of its
     * type and moving secrets apart. Empty secrets keep those of the stored
     * platform, unless a field deciding where they are sent changed.
     *
     * @param stored
     *     The platform as stored, with its secrets, or null for a new one.
     *
     * @throws GuacamoleClientException
     *     If the platform is invalid, or a stored secret would be sent to
     *     another server than it was entered for.
     */
    static Platform sanitize(Platform platform, Platform stored) throws GuacamoleClientException {

        if (platform == null || platform.getName() == null || platform.getName().trim().isEmpty())
            throw new GuacamoleClientException("The platform needs a name.");
        if (platform.getName().trim().length() > MAX_NAME_LENGTH)
            throw new GuacamoleClientException("Platform names are limited to " + MAX_NAME_LENGTH + " characters.");
        if (platform.getDescription() != null && platform.getDescription().length() > MAX_DESCRIPTION_LENGTH)
            throw new GuacamoleClientException("Descriptions are limited to " + MAX_DESCRIPTION_LENGTH + " characters.");

        ManagementType type = ManagementTypes.get(platform.getType());
        if (type == null)
            throw new GuacamoleClientException("Unknown platform type \"" + platform.getType() + "\".");

        Platform clean = new Platform();
        clean.setName(platform.getName().trim());
        clean.setDescription(platform.getDescription() == null || platform.getDescription().trim().isEmpty()
                ? null : platform.getDescription().trim());
        clean.setType(type.getName());

        Set<String> secretFields = type.getSecretFields();
        Map<String, String> storedSecrets = stored == null ? Collections.<String, String>emptyMap()
                : stored.getSecrets();
        Map<String, String> settings = new HashMap<>();
        Map<String, String> secrets = new HashMap<>();
        Set<String> kept = new TreeSet<>();

        for (String field : fieldNames(type)) {
            String value = platform.getSettings().get(field);
            if (secretFields.contains(field)) {
                if (value != null && !value.isEmpty())
                    secrets.put(field, value);
                else if (storedSecrets.get(field) != null) {
                    secrets.put(field, storedSecrets.get(field));
                    kept.add(field);
                }
            }
            else if (value != null && !value.trim().isEmpty())
                settings.put(field, value);
        }

        // Otherwise, whoever may edit the platform could have the stored
        // password sent to a server of their choosing, or less safely
        if (stored != null && !kept.isEmpty()) {
            Set<String> changed = new TreeSet<>();
            for (String field : type.getDestinationFields()) {
                if (!Objects.equals(settings.get(field), stored.getSettings().get(field)))
                    changed.add(field);
            }
            if (!changed.isEmpty())
                throw new GuacamoleClientException("Changing " + String.join(", ", changed) + " changes where the"
                        + " stored " + String.join(", ", kept) + " is sent: enter it again to save.");
        }

        clean.setSettings(settings);
        clean.setSecrets(secrets);
        clean.setPolicy(sanitizePolicy(platform.getPolicy()));

        type.validate(clean);
        return clean;

    }

    private static Map<String, String> sanitizePolicy(Map<String, String> policy) throws GuacamoleClientException {

        Map<String, String> clean = new HashMap<>();

        String mode = Values.trimToNull(policy.get(Platform.POLICY_ROTATION_MODE));
        if (mode != null) {
            if (!mode.equals(Platform.MODE_NEVER) && !mode.equals(Platform.MODE_AFTER_USE)
                    && !mode.equals(Platform.MODE_PERIODIC))
                throw new GuacamoleClientException("Unknown rotation mode \"" + mode + "\".");
            clean.put(Platform.POLICY_ROTATION_MODE, mode);
        }

        Integer interval = parseNumber(policy.get(Platform.POLICY_ROTATION_INTERVAL), 1, MAX_INTERVAL_HOURS,
                "The rotation interval must be between 1 and " + MAX_INTERVAL_HOURS + " hours.");
        if (interval != null)
            clean.put(Platform.POLICY_ROTATION_INTERVAL, interval.toString());

        if (Platform.MODE_PERIODIC.equals(mode) && interval == null)
            throw new GuacamoleClientException("Periodic rotation needs an interval.");

        Integer length = parseNumber(policy.get(Platform.POLICY_PASSWORD_LENGTH), 12, 128,
                "The password length must be between 12 and 128 characters.");
        if (length != null)
            clean.put(Platform.POLICY_PASSWORD_LENGTH, length.toString());

        return clean;

    }

    private static Integer parseNumber(String value, int min, int max, String error)
            throws GuacamoleClientException {
        if (Values.trimToNull(value) == null)
            return null;
        try {
            int number = Integer.parseInt(value.trim());
            if (number < min || number > max)
                throw new GuacamoleClientException(error);
            return number;
        }
        catch (NumberFormatException e) {
            throw new GuacamoleClientException(error);
        }
    }

    private static Set<String> fieldNames(ManagementType type) {
        Set<String> names = new HashSet<>();
        for (Form form : type.getPlatformForms()) {
            for (Field field : form.getFields())
                names.add(field.getName());
        }
        return names;
    }

    private static GuacamoleException translate(SQLException e, Platform platform) {
        if (UNIQUE_VIOLATION.equals(e.getSQLState()))
            return new GuacamoleClientException("A platform named \"" + platform.getName() + "\" already exists.");
        return new GuacamoleServerException("Unable to save platform.", e);
    }

    /**
     * Stores every platform's secrets in the form {@link Secrets} requires
     * now. A platform saved meanwhile is left as saved; secrets that cannot
     * be decrypted here are skipped, and reported.
     */
    public void migrateSecrets(MigrationReport report) throws GuacamoleException {

        try (Connection connection = database.getConnection()) {

            Map<Integer, String> stored = new HashMap<>();
            try (PreparedStatement statement = connection.prepareStatement(
                    "SELECT platform_id, secrets FROM pam_platform");
                 ResultSet results = statement.executeQuery()) {
                while (results.next())
                    stored.put(results.getInt(1), results.getString(2));
            }

            for (Map.Entry<Integer, String> entry : stored.entrySet()) {
                if (!secrets.canReveal(entry.getValue())) {
                    report.unreadable(entry.getValue());
                    continue;
                }
                if (!secrets.needsMigration(entry.getValue()))
                    continue;
                try (PreparedStatement statement = connection.prepareStatement(
                        "UPDATE pam_platform SET secrets = ? WHERE platform_id = ? AND secrets = ?")) {
                    statement.setString(1, secrets.protect(Secrets.PLATFORM_SECRETS, entry.getValue()));
                    statement.setInt(2, entry.getKey());
                    statement.setString(3, entry.getValue());
                    report.changed(statement.executeUpdate());
                }
            }

        }
        catch (SQLException e) {
            throw new GuacamoleServerException("Unable to migrate platform secrets.", e);
        }

    }

    private Platform toPlatform(ResultSet results, boolean withSecrets) throws SQLException, GuacamoleException {
        Platform platform = new Platform();
        platform.setId(results.getInt("platform_id"));
        platform.setName(results.getString("name"));
        platform.setDescription(results.getString("description"));
        platform.setType(results.getString("type"));
        platform.setSettings(fromJson(results.getString("settings")));
        platform.setSecrets(withSecrets
                ? fromJson(secrets.reveal(Secrets.PLATFORM_SECRETS, results.getString("secrets")))
                : new HashMap<String, String>());
        platform.setPolicy(fromJson(results.getString("policy")));
        platform.setLastModified(results.getTimestamp("last_modified").getTime());
        return platform;
    }

    static String toJson(Map<String, String> values) throws SQLException {
        try {
            return JSON.writeValueAsString(values);
        }
        catch (IOException e) {
            throw new SQLException("Unable to encode platform settings.", e);
        }
    }

    static Map<String, String> fromJson(String json) throws SQLException {
        try {
            Map<String, String> values = json == null ? null : JSON.readValue(json, STRING_MAP);
            return values == null ? new HashMap<String, String>() : values;
        }
        catch (IOException e) {
            throw new SQLException("Unable to decode platform settings.", e);
        }
    }

}
