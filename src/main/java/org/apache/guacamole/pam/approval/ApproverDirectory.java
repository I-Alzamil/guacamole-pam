package org.apache.guacamole.pam.approval;

import java.io.IOException;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;

import org.apache.guacamole.GuacamoleException;
import org.apache.guacamole.GuacamoleServerException;
import org.apache.guacamole.pam.PamAttributes;
import org.apache.guacamole.pam.db.PamDatabase;
import org.apache.guacamole.pam.db.SqlDialect;

/**
 * Who may approve requests: the approval permissions of users and user
 * groups, read from Guacamole's own tables of the managed data source.
 */
public class ApproverDirectory {

    private static final ObjectMapper JSON = new ObjectMapper();

    /**
     * Identifier of the root connection group, containing every connection.
     */
    private static final String ROOT_GROUP = "ROOT";

    /**
     * Attributes deciding who may approve.
     */
    private static final List<String> APPROVAL_ATTRIBUTES = Arrays.asList(PamAttributes.APPROVER,
            PamAttributes.APPROVER_CONNECTIONS, PamAttributes.APPROVER_CONNECTION_GROUPS);

    private static final TypeReference<List<String>> STRING_LIST = new TypeReference<List<String>>() { };

    private final PamDatabase database;

    private final SqlDialect dialect;

    public ApproverDirectory(PamDatabase database) {
        this.database = database;
        this.dialect = database.getDialect();
    }

    /**
     * Returns the identifiers of the connections whose requests the user may
     * approve: those listed by the user's own approval permission, and by
     * that of every enabled group the user belongs to (directly, through
     * nested groups, or as reported by the authenticating extension), with
     * listed connection groups expanded to every connection within them.
     */
    public Set<String> getApprovableConnections(String username, Collection<String> reportedGroups)
            throws GuacamoleException {

        Set<String> connections = new HashSet<>();
        Set<String> groups = new HashSet<>();

        try (Connection connection = database.getConnection()) {

            List<Map<String, String>> grants = new ArrayList<>();

            // The user's own attributes, unless disabled...
            Map<String, String> own = new HashMap<>();
            Integer entity = null;
            try (PreparedStatement statement = connection.prepareStatement(
                    "SELECT e.entity_id, u.disabled, a.attribute_name, a.attribute_value FROM guacamole_entity e"
                  + " JOIN guacamole_user u ON u.entity_id = e.entity_id"
                  + " LEFT JOIN guacamole_user_attribute a ON a.user_id = u.user_id"
                  + "   AND a.attribute_name IN " + SqlDialect.parameters(APPROVAL_ATTRIBUTES.size())
                  + " WHERE e.type = 'USER' AND e.name = ?")) {
                int index = 1;
                for (String name : APPROVAL_ATTRIBUTES)
                    statement.setString(index++, name);
                statement.setString(index, username);
                try (ResultSet results = statement.executeQuery()) {
                    while (results.next()) {
                        entity = results.getInt(1);
                        if (!results.getBoolean(2) && results.getString(3) != null)
                            own.put(results.getString(3), results.getString(4));
                    }
                }
            }
            grants.add(own);

            // ...and those of the groups the user belongs to
            Set<Integer> memberOf = entity == null ? new HashSet<>() : getGroupsOf(connection, entity);
            memberOf.addAll(getGroupsNamed(connection, reportedGroups));
            grants.addAll(getGroupAttributes(connection, memberOf));

            // Connections and connection groups listed by those granting the
            // permission
            for (Map<String, String> grant : grants) {
                if (!"true".equals(grant.get(PamAttributes.APPROVER)))
                    continue;
                connections.addAll(parseIdentifiers(grant.get(PamAttributes.APPROVER_CONNECTIONS)));
                groups.addAll(parseIdentifiers(grant.get(PamAttributes.APPROVER_CONNECTION_GROUPS)));
            }

            if (!groups.isEmpty())
                connections.addAll(getConnectionsWithin(connection, groups));

        }
        catch (SQLException e) {
            throw new GuacamoleServerException("Unable to read approval permissions.", e);
        }

        return connections;

    }

    /**
     * Returns the entity ids of the enabled groups the given entity belongs
     * to, directly or through nested groups. Followed level by level, so a
     * group belonging to itself through others ends the search.
     */
    private Set<Integer> getGroupsOf(Connection connection, int entity) throws SQLException {

        Set<Integer> found = new HashSet<>();
        Set<Integer> level = Collections.singleton(entity);

        while (!level.isEmpty()) {

            Set<Integer> next = new HashSet<>();
            try (PreparedStatement statement = connection.prepareStatement(
                    "SELECT g.entity_id FROM guacamole_user_group_member m"
                  + " JOIN guacamole_user_group g ON g.user_group_id = m.user_group_id"
                  + " WHERE m.member_entity_id IN " + SqlDialect.in(level)
                  + " AND g.disabled = " + dialect.bool(false));
                 ResultSet results = statement.executeQuery()) {
                while (results.next()) {
                    if (found.add(results.getInt(1)))
                        next.add(results.getInt(1));
                }
            }
            level = next;

        }

        return found;

    }

    /**
     * Returns the entity ids of the enabled groups of the given names, such
     * as those reported by the authenticating extension.
     */
    private Set<Integer> getGroupsNamed(Connection connection, Collection<String> names) throws SQLException {

        Set<Integer> found = new HashSet<>();
        if (names.isEmpty())
            return found;

        try (PreparedStatement statement = connection.prepareStatement(
                "SELECT g.entity_id FROM guacamole_user_group g"
              + " JOIN guacamole_entity e ON e.entity_id = g.entity_id"
              + " WHERE e.type = 'USER_GROUP' AND e.name IN " + SqlDialect.parameters(names.size())
              + " AND g.disabled = " + dialect.bool(false))) {
            int index = 1;
            for (String name : names)
                statement.setString(index++, name);
            try (ResultSet results = statement.executeQuery()) {
                while (results.next())
                    found.add(results.getInt(1));
            }
        }

        return found;

    }

    /**
     * Returns the approval attributes of each of the given groups.
     */
    private static Collection<Map<String, String>> getGroupAttributes(Connection connection, Set<Integer> groups)
            throws SQLException {

        Map<Integer, Map<String, String>> attributes = new HashMap<>();
        if (groups.isEmpty())
            return attributes.values();

        try (PreparedStatement statement = connection.prepareStatement(
                "SELECT g.entity_id, a.attribute_name, a.attribute_value FROM guacamole_user_group_attribute a"
              + " JOIN guacamole_user_group g ON g.user_group_id = a.user_group_id"
              + " WHERE g.entity_id IN " + SqlDialect.in(groups)
              + " AND a.attribute_name IN " + SqlDialect.parameters(APPROVAL_ATTRIBUTES.size()))) {
            int index = 1;
            for (String name : APPROVAL_ATTRIBUTES)
                statement.setString(index++, name);
            try (ResultSet results = statement.executeQuery()) {
                while (results.next())
                    attributes.computeIfAbsent(results.getInt(1), id -> new HashMap<>())
                            .put(results.getString(2), results.getString(3));
            }
        }

        return attributes.values();

    }

    /**
     * Returns the identifiers of every connection within the given
     * connection groups, at any depth. "ROOT" stands for every connection.
     */
    private static Set<String> getConnectionsWithin(Connection connection, Set<String> groups)
            throws SQLException {

        Set<String> connections = new HashSet<>();

        String where;
        if (groups.contains(ROOT_GROUP))
            where = "";
        else {

            Set<Integer> within = new HashSet<>();
            for (String group : groups) {
                try {
                    within.add(Integer.valueOf(group));
                }
                catch (NumberFormatException e) {
                    // Only ROOT is not numeric
                }
            }

            // Every group below, level by level
            Set<Integer> level = new HashSet<>(within);
            while (!level.isEmpty()) {
                Set<Integer> next = new HashSet<>();
                try (PreparedStatement statement = connection.prepareStatement(
                        "SELECT connection_group_id FROM guacamole_connection_group"
                      + " WHERE parent_id IN " + SqlDialect.in(level));
                     ResultSet results = statement.executeQuery()) {
                    while (results.next()) {
                        if (within.add(results.getInt(1)))
                            next.add(results.getInt(1));
                    }
                }
                level = next;
            }

            where = " WHERE parent_id IN " + SqlDialect.in(within);

        }

        try (PreparedStatement statement = connection.prepareStatement(
                "SELECT connection_id FROM guacamole_connection" + where);
             ResultSet results = statement.executeQuery()) {
            while (results.next())
                connections.add(Integer.toString(results.getInt(1)));
        }

        return connections;

    }

    /**
     * Reads a list of connection identifiers stored as a JSON array.
     * Anything else counts as no connections.
     */
    static List<String> parseIdentifiers(String value) {
        if (value == null || value.trim().isEmpty())
            return Collections.emptyList();
        try {
            List<String> identifiers = JSON.readValue(value, STRING_LIST);
            return identifiers == null ? Collections.<String>emptyList() : identifiers;
        }
        catch (IOException e) {
            return Collections.emptyList();
        }
    }

}
