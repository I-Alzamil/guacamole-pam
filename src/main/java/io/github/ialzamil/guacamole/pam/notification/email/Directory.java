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

import org.apache.guacamole.GuacamoleException;
import org.apache.guacamole.GuacamoleServerException;

import io.github.ialzamil.guacamole.pam.PamAttributes;
import io.github.ialzamil.guacamole.pam.approval.ApproverDirectory;
import io.github.ialzamil.guacamole.pam.db.PamDatabase;
import io.github.ialzamil.guacamole.pam.db.SqlDialect;

/**
 * Who receives emails, read from Guacamole's own tables of the managed data
 * source: the administrators, the approvers of a connection, and their
 * email addresses (the "Email address" of their Guacamole profile, which
 * Guacamole keeps in "guacamole_user"). Only
 * enabled users, and memberships of enabled groups stored there, count:
 * groups a user belongs to only through another extension, such as LDAP,
 * are not known here.
 */
public class Directory {

    private final PamDatabase database;

    private final SqlDialect dialect;

    private final ApproverDirectory approvers;

    public Directory(PamDatabase database, ApproverDirectory approvers) {
        this.database = database;
        this.dialect = database.getDialect();
        this.approvers = approvers;
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
     * connection, as {@link ApproverDirectory} decides it.
     */
    public Set<String> getApproversOf(String connectionIdentifier) throws GuacamoleException {

        Set<String> candidates;
        try (Connection connection = database.getConnection()) {

            // Users and groups giving the permission at all
            Set<Integer> entities = new HashSet<>();
            try (PreparedStatement statement = connection.prepareStatement(
                    "SELECT u.entity_id FROM guacamole_user_attribute a JOIN guacamole_user u ON u.user_id = a.user_id"
                  + " WHERE a.attribute_name = ? AND a.attribute_value = 'true'"
                  + " UNION SELECT g.entity_id FROM guacamole_user_group_attribute a"
                  + " JOIN guacamole_user_group g ON g.user_group_id = a.user_group_id"
                  + " WHERE a.attribute_name = ? AND a.attribute_value = 'true'")) {
                statement.setString(1, PamAttributes.APPROVER);
                statement.setString(2, PamAttributes.APPROVER);
                try (ResultSet results = statement.executeQuery()) {
                    while (results.next())
                        entities.add(results.getInt(1));
                }
            }
            candidates = getUsersOf(connection, entities);

        }
        catch (SQLException e) {
            throw new GuacamoleServerException("Unable to read the approvers.", e);
        }

        // Each decided as when they approve, so emails go to those who can
        Set<String> qualified = new HashSet<>();
        for (String candidate : candidates) {
            if (approvers.getApprovableConnections(candidate, Collections.<String>emptySet())
                    .contains(connectionIdentifier))
                qualified.add(candidate);
        }
        return qualified;

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
     * the members of the enabled groups among them, at any depth. Followed
     * level by level, so a group belonging to itself through others ends the
     * search.
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
