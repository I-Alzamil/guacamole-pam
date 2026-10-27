package io.github.ialzamil.guacamole.pam.notification.email;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;

import org.apache.guacamole.GuacamoleException;
import org.apache.guacamole.GuacamoleServerException;

import io.github.ialzamil.guacamole.pam.PamAttributes;
import io.github.ialzamil.guacamole.pam.Values;
import io.github.ialzamil.guacamole.pam.approval.ApproverDirectory;
import io.github.ialzamil.guacamole.pam.db.PamDatabase;
import io.github.ialzamil.guacamole.pam.db.SqlDialect;

/**
 * Who receives emails, read from Guacamole's own tables of the managed data
 * source: the administrators, the approvers of a connection, and their
 * email addresses (the "Email address" of their Guacamole profile, which
 * Guacamole keeps in "guacamole_user"). Only enabled users, and
 * memberships of enabled groups, count: those stored there, and those
 * another extension, such as LDAP, gave a user at their last login, kept
 * in "pam_login_group".
 *
 */
public class Directory {

    private final PamDatabase database;

    private final SqlDialect dialect;

    /**
     * Identifier of the root connection group, containing every connection.
     */
    private static final String ROOT_GROUP = "ROOT";

    public Directory(PamDatabase database) {
        this.database = database;
        this.dialect = database.getDialect();
    }

    /**
     * Usernames of the users holding the ADMINISTER system permission, of
     * their own or through a group.
     */
    public Set<String> getAdministrators() throws GuacamoleException {
        try (Connection connection = database.getConnection()) {
            Set<Integer> entities = new HashSet<>();
            try (PreparedStatement statement = connection.prepareStatement(
                    "SELECT entity_id FROM guacamole_system_permission WHERE permission = 'ADMINISTER'");
                 ResultSet results = statement.executeQuery()) {
                while (results.next())
                    entities.add(results.getInt(1));
            }
            return getUsersOf(connection, entities);
        }
        catch (SQLException e) {
            throw new GuacamoleServerException("Unable to read the administrators.", e);
        }
    }

    /**
     * Usernames of the users whose approval permission covers the given
     * connection, as {@link ApproverDirectory} decides it: the grants of
     * enabled users and groups listing the connection, or a connection
     * group above it, read at once, then the members of the groups.
     */
    public Set<String> getApproversOf(String connectionIdentifier) throws GuacamoleException {

        Integer id = Values.parseId(connectionIdentifier);
        if (id == null)
            return Collections.emptySet();

        try (Connection connection = database.getConnection()) {

            Set<String> groupsAbove = getGroupsAbove(connection, id);
            Map<Integer, Map<String, String>> grants = new HashMap<>();
            readGrants(connection, "SELECT u.entity_id, a.attribute_name, a.attribute_value"
                  + " FROM guacamole_user_attribute a JOIN guacamole_user u ON u.user_id = a.user_id"
                  + " WHERE u.disabled = " + dialect.bool(false), grants);
            readGrants(connection, "SELECT g.entity_id, a.attribute_name, a.attribute_value"
                  + " FROM guacamole_user_group_attribute a JOIN guacamole_user_group g ON g.user_group_id = a.user_group_id"
                  + " WHERE g.disabled = " + dialect.bool(false), grants);

            Set<Integer> covering = new HashSet<>();
            for (Map.Entry<Integer, Map<String, String>> grant : grants.entrySet()) {
                Map<String, String> attributes = grant.getValue();
                if (!"true".equals(attributes.get(PamAttributes.APPROVER)))
                    continue;
                boolean covers = ApproverDirectory.parseIdentifiers(attributes.get(PamAttributes.APPROVER_CONNECTIONS))
                        .contains(connectionIdentifier);
                for (String group : ApproverDirectory.parseIdentifiers(
                        attributes.get(PamAttributes.APPROVER_CONNECTION_GROUPS)))
                    covers |= groupsAbove.contains(group);
                if (covers)
                    covering.add(grant.getKey());
            }
            return getUsersOf(connection, covering);

        }
        catch (SQLException e) {
            throw new GuacamoleServerException("Unable to read the approvers.", e);
        }

    }

    /**
     * Adds the approval attributes the given query reads (entity, name,
     * value), by entity.
     */
    private static void readGrants(Connection connection, String query, Map<Integer, Map<String, String>> grants)
            throws SQLException {
        try (PreparedStatement statement = connection.prepareStatement(query + " AND a.attribute_name IN (?, ?, ?)")) {
            statement.setString(1, PamAttributes.APPROVER);
            statement.setString(2, PamAttributes.APPROVER_CONNECTIONS);
            statement.setString(3, PamAttributes.APPROVER_CONNECTION_GROUPS);
            try (ResultSet results = statement.executeQuery()) {
                while (results.next())
                    grants.computeIfAbsent(results.getInt(1), entity -> new HashMap<>())
                            .put(results.getString(2), results.getString(3));
            }
        }
    }

    /**
     * Identifiers of the connection groups the connection is within, at
     * any depth, "ROOT" included.
     */
    private static Set<String> getGroupsAbove(Connection connection, int id) throws SQLException {

        Set<String> groups = new HashSet<>();
        groups.add(ROOT_GROUP);

        Integer parent;
        try (PreparedStatement statement = connection.prepareStatement(
                "SELECT parent_id FROM guacamole_connection WHERE connection_id = ?")) {
            statement.setInt(1, id);
            try (ResultSet results = statement.executeQuery()) {
                parent = results.next() ? (Integer) results.getObject(1) : null;
            }
        }

        // Up to the root, a group seen twice ending it
        try (PreparedStatement statement = connection.prepareStatement(
                "SELECT parent_id FROM guacamole_connection_group WHERE connection_group_id = ?")) {
            while (parent != null && groups.add(parent.toString())) {
                statement.setInt(1, parent);
                try (ResultSet results = statement.executeQuery()) {
                    parent = results.next() ? (Integer) results.getObject(1) : null;
                }
            }
        }

        return groups;

    }

    /**
     * Keeps the groups a user belongs to as they logged in, which other
     * extensions, such as LDAP, may give, for the next emails: replaced if
     * they changed.
     */
    public void recordLoginGroups(String username, Set<String> groups) throws GuacamoleException {

        try (Connection connection = database.getConnection()) {

            Set<String> stored = new TreeSet<>();
            try (PreparedStatement statement = connection.prepareStatement(
                    "SELECT group_name FROM pam_login_group WHERE username = ?")) {
                statement.setString(1, username);
                try (ResultSet results = statement.executeQuery()) {
                    while (results.next())
                        stored.add(results.getString(1));
                }
            }
            if (stored.equals(new TreeSet<>(groups)))
                return;

            connection.setAutoCommit(false);
            try {
                try (PreparedStatement statement = connection.prepareStatement(
                        "DELETE FROM pam_login_group WHERE username = ?")) {
                    statement.setString(1, username);
                    statement.executeUpdate();
                }
                try (PreparedStatement statement = connection.prepareStatement(
                        "INSERT INTO pam_login_group (username, group_name) VALUES (?, ?)")) {
                    for (String group : groups) {
                        statement.setString(1, username);
                        statement.setString(2, group);
                        statement.addBatch();
                    }
                    statement.executeBatch();
                }
                connection.commit();
            }
            catch (SQLException e) {
                connection.rollback();
                throw e;
            }

        }
        catch (SQLException e) {
            throw new GuacamoleServerException("Unable to record the groups of a user.", e);
        }

    }

    /**
     * The email address of each of the given users who has one, by
     * username.
     */
    public Map<String, String> getAddresses(Collection<String> usernames) throws GuacamoleException {

        Map<String, String> addresses = new HashMap<>();
        if (usernames.isEmpty())
            return addresses;

        try (Connection connection = database.getConnection();
             PreparedStatement statement = connection.prepareStatement(
                 "SELECT e.name, u.email_address FROM guacamole_entity e"
               + " JOIN guacamole_user u ON u.entity_id = e.entity_id"
               + " WHERE e.type = 'USER' AND u.disabled = " + dialect.bool(false)
               + " AND e.name IN " + SqlDialect.parameters(usernames.size()))) {
            int index = 1;
            for (String username : usernames)
                statement.setString(index++, username);
            try (ResultSet results = statement.executeQuery()) {
                while (results.next()) {
                    String address = results.getString(2);
                    if (address != null && !address.trim().isEmpty())
                        addresses.put(results.getString(1), address.trim());
                }
            }
        }
        catch (SQLException e) {
            throw new GuacamoleServerException("Unable to read email addresses.", e);
        }

        return addresses;

    }

    /**
     * Usernames of the enabled users among the given entities, and among
     * the members of the enabled groups among them, at any depth, members
     * at their last login included. Followed level by level, so a group
     * belonging to itself through others ends the search.
     */
    private Set<String> getUsersOf(Connection connection, Set<Integer> entities) throws SQLException {

        Set<String> users = new HashSet<>();
        Set<Integer> seen = new HashSet<>(entities);
        Set<Integer> level = entities;

        while (!level.isEmpty()) {

            try (PreparedStatement statement = connection.prepareStatement(
                    "SELECT e.name FROM guacamole_entity e JOIN guacamole_user u ON u.entity_id = e.entity_id"
                  + " WHERE e.entity_id IN " + SqlDialect.in(level) + " AND u.disabled = " + dialect.bool(false));
                 ResultSet results = statement.executeQuery()) {
                while (results.next())
                    users.add(results.getString(1));
            }

            try (PreparedStatement statement = connection.prepareStatement(
                    "SELECT l.username FROM pam_login_group l JOIN guacamole_entity e ON e.name = l.group_name"
                  + " JOIN guacamole_user_group g ON g.entity_id = e.entity_id"
                  + " WHERE e.entity_id IN " + SqlDialect.in(level) + " AND g.disabled = " + dialect.bool(false));
                 ResultSet results = statement.executeQuery()) {
                while (results.next())
                    users.add(results.getString(1));
            }

            Set<Integer> next = new HashSet<>();
            try (PreparedStatement statement = connection.prepareStatement(
                    "SELECT m.member_entity_id FROM guacamole_user_group_member m"
                  + " JOIN guacamole_user_group g ON g.user_group_id = m.user_group_id"
                  + " WHERE g.entity_id IN " + SqlDialect.in(level) + " AND g.disabled = " + dialect.bool(false));
                 ResultSet results = statement.executeQuery()) {
                while (results.next()) {
                    if (seen.add(results.getInt(1)))
                        next.add(results.getInt(1));
                }
            }
            level = next;

        }

        return users;

    }

}
