package io.github.ialzamil.guacamole.pam.password;

import java.io.IOException;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;

import org.apache.guacamole.GuacamoleClientException;
import org.apache.guacamole.GuacamoleException;
import org.apache.guacamole.GuacamoleResourceNotFoundException;
import org.apache.guacamole.GuacamoleServerException;

import io.github.ialzamil.guacamole.pam.PamAttributes;
import io.github.ialzamil.guacamole.pam.Values;
import io.github.ialzamil.guacamole.pam.db.PamDatabase;
import io.github.ialzamil.guacamole.pam.db.SqlDialect;
import io.github.ialzamil.guacamole.pam.platform.Platform;

/**
 * Storage of password policies ("pam_password_policy"), their rules as JSON.
 * Platforms choose one in their policy ({@link Platform#POLICY_PASSWORD_POLICY}),
 * and connections may choose another ({@link PamAttributes#PASSWORD_POLICY}),
 * both by identifier; without one, {@link PasswordRules#defaults} apply. A
 * policy in use cannot be deleted.
 */
public final class PasswordPolicyRepository {

    private static final ObjectMapper JSON = new ObjectMapper();

    private static final TypeReference<Map<String, String>> STRING_MAP = new TypeReference<Map<String, String>>() { };

    private static final int MAX_NAME_LENGTH = 128;

    private static final int MAX_DESCRIPTION_LENGTH = 1024;

    private static final String SELECT =
            "SELECT policy_id, name, description, rules, last_modified FROM pam_password_policy";

    private final PamDatabase database;

    public PasswordPolicyRepository(PamDatabase database) {
        this.database = database;
    }

    /**
     * Every policy by name, each with what uses it.
     */
    public List<PasswordPolicy> list() throws GuacamoleException {

        try (Connection connection = database.getConnection()) {

            Map<Integer, PasswordPolicy> policies = new LinkedHashMap<>();
            try (PreparedStatement statement = connection.prepareStatement(SELECT + " ORDER BY name");
                 ResultSet results = statement.executeQuery()) {
                while (results.next()) {
                    PasswordPolicy policy = toPolicy(results);
                    policy.setPlatforms(new ArrayList<>());
                    policy.setConnections(new ArrayList<>());
                    policies.put(policy.getId(), policy);
                }
            }

            for (Map.Entry<Integer, List<String>> use : platformsUsing(connection).entrySet()) {
                PasswordPolicy policy = policies.get(use.getKey());
                if (policy != null)
                    policy.getPlatforms().addAll(use.getValue());
            }
            for (Map.Entry<Integer, List<String>> use : connectionsUsing(connection).entrySet()) {
                PasswordPolicy policy = policies.get(use.getKey());
                if (policy != null)
                    policy.getConnections().addAll(use.getValue());
            }

            return new ArrayList<>(policies.values());

        }
        catch (SQLException e) {
            throw new GuacamoleServerException("Unable to list password policies.", e);
        }

    }

    /**
     * The policy of the given identifier, or null if there is none.
     */
    public PasswordPolicy get(int id) throws GuacamoleException {
        try (Connection connection = database.getConnection();
             PreparedStatement statement = connection.prepareStatement(SELECT + " WHERE policy_id = ?")) {
            statement.setInt(1, id);
            try (ResultSet results = statement.executeQuery()) {
                return results.next() ? toPolicy(results) : null;
            }
        }
        catch (SQLException e) {
            throw new GuacamoleServerException("Unable to read password policy " + id + ".", e);
        }
    }

    /**
     * The policy of the given name, or null if there is none.
     */
    public PasswordPolicy getByName(String name) throws GuacamoleException {
        try (Connection connection = database.getConnection();
             PreparedStatement statement = connection.prepareStatement(SELECT + " WHERE name = ?")) {
            statement.setString(1, name);
            try (ResultSet results = statement.executeQuery()) {
                return results.next() ? toPolicy(results) : null;
            }
        }
        catch (SQLException e) {
            throw new GuacamoleServerException("Unable to read password policy \"" + name + "\".", e);
        }
    }

    /**
     * The rules a platform or connection gets by the identifier it stores:
     * the defaults for none.
     *
     * @throws GuacamoleClientException
     *     If the identifier names no policy.
     */
    public PasswordRules rulesOf(String id) throws GuacamoleException {
        if (Values.trimToNull(id) == null)
            return PasswordRules.defaults();
        Integer number = Values.parseId(id.trim());
        PasswordPolicy policy = number == null ? null : get(number);
        if (policy == null)
            throw new GuacamoleClientException("Password policy " + id.trim() + " no longer exists: choose another.");
        return policy.getRules();
    }

    public PasswordPolicy create(PasswordPolicy policy) throws GuacamoleException {

        PasswordPolicy clean = sanitize(policy);
        SqlDialect dialect = database.getDialect();

        // Read once its connection is back: holding one, never ask for
        // another (see PamDatabase)
        int id;
        try (Connection connection = database.getConnection();
             PreparedStatement statement = connection.prepareStatement(
                 "INSERT INTO pam_password_policy (name, description, rules, last_modified) VALUES (?, ?, ?, "
               + dialect.now() + ")", new String[] { "policy_id" })) {
            statement.setString(1, clean.getName());
            statement.setString(2, clean.getDescription());
            statement.setString(3, toJson(clean.getRules()));
            statement.executeUpdate();
            try (ResultSet keys = statement.getGeneratedKeys()) {
                if (!keys.next())
                    throw new GuacamoleServerException("The new password policy has no identifier.");
                id = keys.getInt(1);
            }
        }
        catch (SQLException e) {
            throw translate(e, clean);
        }
        return get(id);

    }

    public PasswordPolicy update(int id, PasswordPolicy policy) throws GuacamoleException {

        PasswordPolicy clean = sanitize(policy);

        try (Connection connection = database.getConnection();
             PreparedStatement statement = connection.prepareStatement(
                 "UPDATE pam_password_policy SET name = ?, description = ?, rules = ?, last_modified = "
               + database.getDialect().now() + " WHERE policy_id = ?")) {
            statement.setString(1, clean.getName());
            statement.setString(2, clean.getDescription());
            statement.setString(3, toJson(clean.getRules()));
            statement.setInt(4, id);
            if (statement.executeUpdate() == 0)
                throw new GuacamoleResourceNotFoundException("No such password policy.");
        }
        catch (SQLException e) {
            throw translate(e, clean);
        }

        return get(id);

    }

    /**
     * Deletes a policy no platform or connection uses.
     *
     * @throws GuacamoleClientException
     *     If any does, naming them.
     */
    public void delete(int id) throws GuacamoleException {

        try (Connection connection = database.getConnection()) {

            List<String> users = new ArrayList<>();
            for (String platform : platformsUsing(connection).getOrDefault(id, new ArrayList<>()))
                users.add("platform \"" + platform + "\"");
            for (String name : connectionsUsing(connection).getOrDefault(id, new ArrayList<>()))
                users.add("connection \"" + name + "\"");
            if (!users.isEmpty())
                throw new GuacamoleClientException("This password policy is still used by "
                        + String.join(", ", users) + ".");

            try (PreparedStatement statement = connection.prepareStatement(
                    "DELETE FROM pam_password_policy WHERE policy_id = ?")) {
                statement.setInt(1, id);
                if (statement.executeUpdate() == 0)
                    throw new GuacamoleResourceNotFoundException("No such password policy.");
            }

        }
        catch (SQLException e) {
            throw new GuacamoleServerException("Unable to delete password policy " + id + ".", e);
        }

    }

    /**
     * The policy as stored: a name, a description or none, valid rules.
     */
    static PasswordPolicy sanitize(PasswordPolicy policy) throws GuacamoleClientException {

        if (policy == null || Values.trimToNull(policy.getName()) == null)
            throw new GuacamoleClientException("The password policy needs a name.");
        if (policy.getName().trim().length() > MAX_NAME_LENGTH)
            throw new GuacamoleClientException("Names are limited to " + MAX_NAME_LENGTH + " characters.");
        if (policy.getDescription() != null && policy.getDescription().trim().length() > MAX_DESCRIPTION_LENGTH)
            throw new GuacamoleClientException("Descriptions are limited to " + MAX_DESCRIPTION_LENGTH
                    + " characters.");
        if (policy.getRules() == null)
            throw new GuacamoleClientException("The password policy has no rules.");

        PasswordPolicy clean = new PasswordPolicy();
        clean.setName(policy.getName().trim());
        clean.setDescription(Values.trimToNull(policy.getDescription()));
        clean.setRules(policy.getRules().validate());
        return clean;

    }

    /**
     * Names of the platforms choosing each policy, by policy identifier.
     */
    private static Map<Integer, List<String>> platformsUsing(Connection connection) throws SQLException {
        Map<Integer, List<String>> using = new HashMap<>();
        try (PreparedStatement statement = connection.prepareStatement(
                 "SELECT name, policy FROM pam_platform ORDER BY name");
             ResultSet results = statement.executeQuery()) {
            while (results.next()) {
                Integer id;
                try {
                    Map<String, String> policy = JSON.readValue(results.getString("policy"), STRING_MAP);
                    id = policy == null ? null : Values.parseId(policy.get(Platform.POLICY_PASSWORD_POLICY));
                }
                catch (IOException e) {
                    id = null;
                }
                if (id != null)
                    using.computeIfAbsent(id, key -> new ArrayList<>()).add(results.getString("name"));
            }
        }
        return using;
    }

    /**
     * Names of the connections choosing each policy themselves, by policy
     * identifier.
     */
    private static Map<Integer, List<String>> connectionsUsing(Connection connection) throws SQLException {
        Map<Integer, List<String>> using = new HashMap<>();
        try (PreparedStatement statement = connection.prepareStatement(
                 "SELECT a.attribute_value, c.connection_name FROM guacamole_connection_attribute a"
               + " JOIN guacamole_connection c ON c.connection_id = a.connection_id"
               + " WHERE a.attribute_name = ? ORDER BY c.connection_name")) {
            statement.setString(1, PamAttributes.PASSWORD_POLICY);
            try (ResultSet results = statement.executeQuery()) {
                while (results.next()) {
                    Integer id = Values.parseId(Values.trimToNull(results.getString(1)));
                    if (id != null)
                        using.computeIfAbsent(id, key -> new ArrayList<>()).add(results.getString(2));
                }
            }
        }
        return using;
    }

    private PasswordPolicy toPolicy(ResultSet results) throws SQLException {
        PasswordPolicy policy = new PasswordPolicy();
        policy.setId(results.getInt("policy_id"));
        policy.setName(results.getString("name"));
        policy.setDescription(results.getString("description"));
        try {
            policy.setRules(JSON.readValue(results.getString("rules"), PasswordRules.class));
        }
        catch (IOException e) {
            throw new SQLException("Unreadable rules of password policy " + policy.getId() + ".", e);
        }
        policy.setLastModified(SqlDialect.getTimestamp(results, "last_modified").getTime());
        return policy;
    }

    private static String toJson(PasswordRules rules) throws SQLException {
        try {
            return JSON.writeValueAsString(rules);
        }
        catch (IOException e) {
            throw new SQLException("Unable to store the rules.", e);
        }
    }

    private GuacamoleException translate(SQLException e, PasswordPolicy policy) {
        if (database.getDialect().isUniqueViolation(e))
            return new GuacamoleClientException("A password policy named \"" + policy.getName()
                    + "\" already exists.");
        return new GuacamoleServerException("Unable to save the password policy.", e);
    }

}
