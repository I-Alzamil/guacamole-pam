package org.apache.guacamole.pam.approval;

import java.io.IOException;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Timestamp;
import java.sql.Types;
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

import org.apache.guacamole.GuacamoleClientException;
import org.apache.guacamole.GuacamoleException;
import org.apache.guacamole.GuacamoleResourceNotFoundException;
import org.apache.guacamole.GuacamoleServerException;
import org.apache.guacamole.pam.AccountProtocol;
import org.apache.guacamole.pam.PamAttributes;
import org.apache.guacamole.pam.checkout.Checkout;
import org.apache.guacamole.pam.db.PamDatabase;
import org.apache.guacamole.pam.db.SearchPattern;
import org.apache.guacamole.pam.db.SqlDialect;

/**
 * Storage of requests needing approval ("pam_request") and their
 * approvals ("pam_request_approval"), and the approval permissions of users
 * and user groups deciding who may approve them. Creating a request locks
 * the row of its connection, as creating a checkout does, so a user has at
 * most one pending request per connection; on PostgreSQL and MySQL a unique
 * index enforces it too. So does approving a request made ahead of time, so
 * that reservations of a connection checked out alone never overlap.
 */
public class ApprovalRepository {

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

    private static final String ALREADY_PENDING = "You already have a request for this password awaiting approval.";

    /**
     * How long a request may stay pending, in hours.
     */
    private static final int PENDING_HOURS = 24;

    /**
     * How often reads expire stale requests first, in milliseconds.
     */
    private static final long EXPIRY_CHECK_MS = 60000;

    private volatile long lastExpiry = 0;

    /**
     * The connection's current name, or the one it had once deleted.
     */
    private static final String SELECT = "SELECT r.request_id, r.connection_id,"
            + " coalesce(c.connection_name, r.connection_name),"
            + " (SELECT parameter_value FROM guacamole_connection_parameter p"
            + "   WHERE p.connection_id = r.connection_id AND p.parameter_name = '" + AccountProtocol.USERNAME + "'),"
            + " r.username, r.reason, r.requested, r.approvals_required, r.status, r.decided, r.decided_by,"
            + " r.checkout_id, r.decision_reason, r.remote_host, r.starts, r.ends, r.decided_host,"
            + " r.periods, r.extends_checkout, r.extension_minutes"
            + " FROM pam_request r LEFT JOIN guacamole_connection c ON c.connection_id = r.connection_id";



    private final PamDatabase database;

    private final SqlDialect dialect;

    public ApprovalRepository(PamDatabase database) {
        this.database = database;
        this.dialect = database.getDialect();
    }

    /**
     * Condition of requests made ahead of time, approved, and neither used
     * nor over yet: reservations, which end once their holder checks out.
     *
     * @param prefix
     *     What the columns of pam_request are prefixed with, such as "r.",
     *     or "".
     */
    public static String reserved(SqlDialect dialect, String prefix) {
        return prefix + "status = 'APPROVED' AND " + prefix + "checkout_id IS NULL AND " + prefix + "starts IS NOT NULL"
                + " AND " + prefix + "ends > " + dialect.now();
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

    /**
     * Creates a pending request.
     *
     * @param remoteHost
     *     Where the user requests from, or null if unknown.
     *
     * @param starts
     *     When the access asked for starts, for a request made ahead of time,
     *     or null for access from the final approval on.
     *
     * @param ends
     *     When the access asked for ahead of time ends, or null.
     *
     * @param exclusive
     *     Whether the access asked for ahead of time excludes other holders.
     *
     * @param periods
     *     How many times the connection's time limit the access lasts.
     *
     * @throws GuacamoleClientException
     *     If the user already has a pending request for the connection, or
     *     the time asked for is not free (see {@link #requireFree}).
     */
    public ApprovalRequest create(int connectionId, String username, String remoteHost, String reason,
            int approvalsRequired, Long starts, Long ends, boolean exclusive, int periods) throws GuacamoleException {

        expireStale(true);

        int id;
        try (Connection connection = database.getConnection()) {

            connection.setAutoCommit(false);
            try {

                // Serializes requests for this connection until commit, as
                // checkouts are, so the checks below cannot be raced
                lockConnection(connection, connectionId);

                try (PreparedStatement statement = connection.prepareStatement(
                        "SELECT 1 FROM pam_request WHERE connection_id = ? AND username = ? AND status = 'PENDING'"
                      + " AND extends_checkout IS NULL")) {
                    statement.setInt(1, connectionId);
                    statement.setString(2, username);
                    try (ResultSet results = statement.executeQuery()) {
                        if (results.next())
                            throw new GuacamoleClientException(ALREADY_PENDING);
                    }
                }

                if (starts != null)
                    requireFree(connection, connectionId, username, starts, ends, exclusive);

                try (PreparedStatement statement = connection.prepareStatement(
                        "INSERT INTO pam_request (connection_id, connection_name, username, remote_host, reason,"
                      + " approvals_required, starts, ends, periods) SELECT connection_id, connection_name, ?, ?, ?, ?, ?, ?, ?"
                      + " FROM guacamole_connection WHERE connection_id = ?", new String[] { "request_id" })) {

                    statement.setString(1, username);
                    statement.setString(2, remoteHost);
                    statement.setString(3, reason);
                    statement.setInt(4, approvalsRequired);
                    if (starts == null) {
                        statement.setNull(5, Types.TIMESTAMP);
                        statement.setNull(6, Types.TIMESTAMP);
                    }
                    else {
                        SqlDialect.setTimestamp(statement, 5, starts);
                        SqlDialect.setTimestamp(statement, 6, ends);
                    }
                    statement.setInt(7, periods);
                    statement.setInt(8, connectionId);

                    statement.executeUpdate();
                    try (ResultSet results = statement.getGeneratedKeys()) {
                        if (!results.next())
                            throw new GuacamoleResourceNotFoundException("The connection no longer exists.");
                        id = results.getInt(1);
                    }

                }

                connection.commit();

            }
            catch (SQLException | GuacamoleException e) {
                connection.rollback();
                throw e;
            }

        }
        catch (SQLException e) {
            if (dialect.isUniqueViolation(e))
                throw new GuacamoleClientException(ALREADY_PENDING);
            throw new GuacamoleServerException("Unable to create the request.", e);
        }

        return get(id);

    }

    /**
     * Locks the row of the connection until commit, as creating a checkout
     * does.
     *
     * @throws GuacamoleResourceNotFoundException
     *     If the connection no longer exists.
     */
    private void lockConnection(Connection connection, int connectionId) throws SQLException, GuacamoleException {
        try (PreparedStatement statement = connection.prepareStatement(
                "SELECT connection_id FROM " + dialect.lockingRead("guacamole_connection")
              + " WHERE connection_id = ?" + dialect.forUpdate())) {
            statement.setInt(1, connectionId);
            try (ResultSet results = statement.executeQuery()) {
                if (!results.next())
                    throw new GuacamoleResourceNotFoundException("The connection no longer exists.");
            }
        }
    }

    /**
     * Refuses access asked for ahead of time that would overlap the user's
     * own reservation of the connection or, if exclusive, the time someone
     * else holds or has reserved it: active checkouts end before it starts,
     * and others cannot check it out once it started (see
     * CheckoutRepository). Run with the connection's row locked.
     *
     * @throws GuacamoleClientException
     *     If the time is not free.
     */
    private void requireFree(Connection connection, int connectionId, String username, long starts, long ends,
            boolean exclusive) throws SQLException, GuacamoleException {

        try (PreparedStatement statement = connection.prepareStatement(
                "SELECT r.username FROM pam_request r WHERE r.connection_id = ? AND " + reserved(dialect, "r.")
              + " AND r.starts < ? AND r.ends > ? ORDER BY r.starts")) {
            statement.setInt(1, connectionId);
            SqlDialect.setTimestamp(statement, 2, ends);
            SqlDialect.setTimestamp(statement, 3, starts);
            try (ResultSet results = statement.executeQuery()) {
                while (results.next()) {
                    String holder = results.getString(1);
                    if (holder.equals(username))
                        throw new GuacamoleClientException("You already have approved access to this at that time.");
                    if (exclusive)
                        throw new GuacamoleClientException("This is reserved by \"" + holder + "\" at that time."
                                + " Please choose another time.");
                }
            }
        }

        if (!exclusive)
            return;

        try (PreparedStatement statement = connection.prepareStatement(
                "SELECT username FROM pam_checkout WHERE connection_id = ? AND released IS NULL"
              + " AND expires > ? AND username <> ?")) {
            statement.setInt(1, connectionId);
            SqlDialect.setTimestamp(statement, 2, starts);
            statement.setString(3, username);
            try (ResultSet results = statement.executeQuery()) {
                if (results.next())
                    throw new GuacamoleClientException("This is checked out by \"" + results.getString(1)
                            + "\" past that time. Please choose a later time.");
            }
        }

    }

    public ApprovalRequest get(int requestId) throws GuacamoleException {
        List<ApprovalRequest> requests = query(SELECT + " WHERE r.request_id = ?", requestId);
        return requests.isEmpty() ? null : requests.get(0);
    }

    /**
     * Returns the user's pending request for a connection (not an
     * extension), or null.
     */
    public ApprovalRequest getPending(int connectionId, String username) throws GuacamoleException {
        expireStale(false);
        List<ApprovalRequest> requests = query(SELECT + " WHERE r.connection_id = ? AND r.username = ?"
                + " AND r.status = 'PENDING' AND r.extends_checkout IS NULL", connectionId, username);
        return requests.isEmpty() ? null : requests.get(0);
    }

    /**
     * Returns the user's most recent request for a connection (not an
     * extension), or null.
     */
    public ApprovalRequest getLatest(int connectionId, String username) throws GuacamoleException {
        List<ApprovalRequest> requests = query(SELECT
                + " WHERE r.connection_id = ? AND r.username = ? AND r.extends_checkout IS NULL"
                + " ORDER BY r.requested DESC, r.request_id DESC" + dialect.limit(), connectionId, username, 1);
        return requests.isEmpty() ? null : requests.get(0);
    }

    /**
     * Returns the user's pending requests (not extensions), by connection
     * id.
     */
    public Map<Integer, ApprovalRequest> listPendingOf(String username) throws GuacamoleException {
        expireStale(false);
        return byConnection(query(SELECT + " WHERE r.username = ? AND r.status = 'PENDING'"
                + " AND r.extends_checkout IS NULL AND r.connection_id IS NOT NULL", username));
    }

    /**
     * Returns the most recent request to extend the given checkout, or
     * null.
     */
    public ApprovalRequest getLatestExtension(int checkoutId) throws GuacamoleException {
        expireStale(false);
        List<ApprovalRequest> requests = query(SELECT + " WHERE r.extends_checkout = ?"
                + " ORDER BY r.requested DESC, r.request_id DESC" + dialect.limit(), checkoutId, 1);
        return requests.isEmpty() ? null : requests.get(0);
    }

    /**
     * Creates a pending request to extend an active checkout of the user by
     * the given minutes. Like other requests, it locks the row of the
     * checkout's connection.
     *
     * @throws GuacamoleClientException
     *     If the checkout is no longer the user's active checkout, cannot be
     *     extended any more, or an extension of it already awaits approval.
     */
    public ApprovalRequest createExtension(Checkout checkout, String username, String remoteHost, String reason,
            int approvalsRequired, int minutes) throws GuacamoleException {

        expireStale(true);

        Integer connectionId = checkout.getConnectionIdentifier() == null ? null
                : Integer.valueOf(checkout.getConnectionIdentifier());
        if (connectionId == null)
            throw new GuacamoleResourceNotFoundException("The connection no longer exists.");

        int id;
        try (Connection connection = database.getConnection()) {

            connection.setAutoCommit(false);
            try {

                lockConnection(connection, connectionId);

                try (PreparedStatement statement = connection.prepareStatement(
                        "SELECT extensions, max_extensions FROM pam_checkout WHERE checkout_id = ? AND username = ?"
                      + " AND released IS NULL AND expires > " + dialect.now())) {
                    statement.setInt(1, checkout.getId());
                    statement.setString(2, username);
                    try (ResultSet results = statement.executeQuery()) {
                        if (!results.next())
                            throw new GuacamoleClientException("Your checkout has ended.");
                        if (results.getInt(1) >= results.getInt(2))
                            throw new GuacamoleClientException("This checkout cannot be extended any more.");
                    }
                }

                try (PreparedStatement statement = connection.prepareStatement(
                        "SELECT 1 FROM pam_request WHERE extends_checkout = ? AND status = 'PENDING'")) {
                    statement.setInt(1, checkout.getId());
                    try (ResultSet results = statement.executeQuery()) {
                        if (results.next())
                            throw new GuacamoleClientException("An extension of your checkout already awaits approval.");
                    }
                }

                try (PreparedStatement statement = connection.prepareStatement(
                        "INSERT INTO pam_request (connection_id, connection_name, username, remote_host, reason,"
                      + " approvals_required, extends_checkout, extension_minutes)"
                      + " SELECT connection_id, connection_name, ?, ?, ?, ?, ?, ? FROM guacamole_connection"
                      + " WHERE connection_id = ?", new String[] { "request_id" })) {
                    statement.setString(1, username);
                    statement.setString(2, remoteHost);
                    statement.setString(3, reason);
                    statement.setInt(4, approvalsRequired);
                    statement.setInt(5, checkout.getId());
                    statement.setInt(6, minutes);
                    statement.setInt(7, connectionId);
                    statement.executeUpdate();
                    try (ResultSet results = statement.getGeneratedKeys()) {
                        if (!results.next())
                            throw new GuacamoleResourceNotFoundException("The connection no longer exists.");
                        id = results.getInt(1);
                    }
                }

                connection.commit();

            }
            catch (SQLException | GuacamoleException e) {
                connection.rollback();
                throw e;
            }

        }
        catch (SQLException e) {
            throw new GuacamoleServerException("Unable to create the extension request.", e);
        }

        return get(id);

    }

    /**
     * Returns the user's most recent request for each connection, by
     * connection id.
     */
    public Map<Integer, ApprovalRequest> listLatestOf(String username) throws GuacamoleException {
        return byConnection(query(SELECT + " WHERE r.username = ? AND r.connection_id IS NOT NULL"
                + " AND r.extends_checkout IS NULL"
                + " AND NOT EXISTS (SELECT 1 FROM pam_request n WHERE n.connection_id = r.connection_id"
                + "   AND n.username = r.username AND n.extends_checkout IS NULL AND (n.requested > r.requested"
                + "   OR (n.requested = r.requested AND n.request_id > r.request_id)))", username));
    }

    private static Map<Integer, ApprovalRequest> byConnection(List<ApprovalRequest> requests) {
        Map<Integer, ApprovalRequest> map = new HashMap<>();
        for (ApprovalRequest request : requests)
            map.put(Integer.valueOf(request.getConnectionIdentifier()), request);
        return map;
    }

    /**
     * Returns every pending request for a connection.
     */
    public List<ApprovalRequest> listPending(int connectionId) throws GuacamoleException {
        expireStale(false);
        return query(SELECT + " WHERE r.connection_id = ? AND r.status = 'PENDING'", connectionId);
    }

    public List<ApprovalRequest> listPending() throws GuacamoleException {
        expireStale(false);
        return query(SELECT + " WHERE r.status = 'PENDING' AND r.connection_id IS NOT NULL ORDER BY r.requested");
    }

    /**
     * Returns the user's next reservation of a connection (a request made
     * ahead of time, approved, and neither used nor over), or null.
     */
    public ApprovalRequest getReservation(int connectionId, String username) throws GuacamoleException {
        List<ApprovalRequest> requests = query(SELECT + " WHERE r.connection_id = ? AND r.username = ? AND "
                + reserved(dialect, "r.") + " ORDER BY r.starts" + dialect.limit(), connectionId, username, 1);
        return requests.isEmpty() ? null : requests.get(0);
    }

    /**
     * Returns every reservation of a connection, the earliest first.
     */
    public List<ApprovalRequest> listReservations(int connectionId) throws GuacamoleException {
        return query(SELECT + " WHERE r.connection_id = ? AND " + reserved(dialect, "r.") + " ORDER BY r.starts",
                connectionId);
    }

    /**
     * Returns every reservation, by connection id, the earliest first.
     */
    public Map<Integer, List<ApprovalRequest>> listReservations() throws GuacamoleException {
        Map<Integer, List<ApprovalRequest>> map = new HashMap<>();
        for (ApprovalRequest request : query(SELECT + " WHERE r.connection_id IS NOT NULL AND "
                + reserved(dialect, "r.") + " ORDER BY r.starts"))
            map.computeIfAbsent(Integer.valueOf(request.getConnectionIdentifier()), id -> new ArrayList<>())
                    .add(request);
        return map;
    }

    /**
     * Searches decided requests, most recently decided first. Every term
     * must match the requester, connection, account, reason, outcome, who
     * decided, the reason for a denial, an approver, or where any of them
     * acted from. Extensions granted without approval are left out, as the
     * checkout history lists them. Only requests of the
     * given connections are searched (before the limit applies), or of all
     * if null.
     */
    public List<ApprovalRequest> searchDecided(List<String> terms, int limit, Set<String> connections)
            throws GuacamoleException {

        expireStale(false);

        // Requests needing no approval (extensions granted at once) are kept
        // for the checkout history only
        StringBuilder sql = new StringBuilder(SELECT).append(" WHERE r.status <> 'PENDING' AND r.approvals_required > 0");
        List<Object> parameters = new ArrayList<>();

        if (connections != null) {
            List<Integer> ids = new ArrayList<>();
            for (String identifier : connections) {
                try {
                    ids.add(Integer.valueOf(identifier));
                }
                catch (NumberFormatException e) {
                    // Not a connection of this data source
                }
            }
            sql.append(" AND r.connection_id IN ").append(SqlDialect.in(ids));
        }

        for (String term : terms) {
            if (term == null || term.trim().isEmpty())
                continue;
            sql.append(" AND (" + SearchPattern.matches("r.username")
                    + " OR " + SearchPattern.matches("coalesce(c.connection_name, r.connection_name)")
                    + " OR " + SearchPattern.matches("coalesce((SELECT parameter_value FROM guacamole_connection_parameter p"
                    + "   WHERE p.connection_id = r.connection_id AND p.parameter_name = '" + AccountProtocol.USERNAME
                    + "'), '')")
                    + " OR " + SearchPattern.matches("r.reason") + " OR " + SearchPattern.matches("r.status")
                    + " OR " + SearchPattern.matches("coalesce(r.decided_by, '')")
                    + " OR " + SearchPattern.matches("coalesce(r.decision_reason, '')")
                    + " OR " + SearchPattern.matches("coalesce(r.remote_host, '')")
                    + " OR " + SearchPattern.matches("coalesce(r.decided_host, '')")
                    + " OR EXISTS (SELECT 1 FROM pam_request_approval a"
                    + "   WHERE a.request_id = r.request_id AND (" + SearchPattern.matches("a.approver")
                    + "   OR " + SearchPattern.matches("coalesce(a.remote_host, '')") + ")))");
            String pattern = SearchPattern.contains(term);
            for (int i = 0; i < 11; i++)
                parameters.add(pattern);
        }

        sql.append(" ORDER BY coalesce(r.decided, r.requested) DESC, r.request_id DESC").append(dialect.limit());
        parameters.add(limit);

        return query(sql.toString(), parameters.toArray());

    }

    /**
     * Records an approval of a pending request, returning the request with
     * the approval included.
     *
     * @param remoteHost
     *     Where the approver approves from, or null if unknown.
     *
     * @throws GuacamoleClientException
     *     If the request is no longer pending, or was already approved by
     *     the approver.
     */
    public ApprovalRequest approve(int requestId, String approver, String remoteHost) throws GuacamoleException {

        expireStale(true);

        try (Connection connection = database.getConnection()) {

            connection.setAutoCommit(false);
            try {

                requirePending(connection, requestId);

                // The request is locked, so no other approval by the same
                // approver can be added meanwhile
                try (PreparedStatement statement = connection.prepareStatement(
                        "INSERT INTO pam_request_approval (request_id, approver, remote_host) SELECT ?, ?, ?"
                      + " WHERE NOT EXISTS (SELECT 1 FROM pam_request_approval WHERE request_id = ? AND approver = ?)")) {
                    statement.setInt(1, requestId);
                    statement.setString(2, approver);
                    statement.setString(3, remoteHost);
                    statement.setInt(4, requestId);
                    statement.setString(5, approver);
                    if (statement.executeUpdate() == 0)
                        throw new GuacamoleClientException("You already approved this request.");
                }

                connection.commit();

            }
            catch (SQLException | GuacamoleException e) {
                connection.rollback();
                throw e;
            }

        }
        catch (SQLException e) {
            throw new GuacamoleServerException("Unable to record the approval.", e);
        }

        return get(requestId);

    }

    /**
     * Withdraws an approval, when the checkout it should have started could
     * not be started.
     */
    public void withdrawApproval(int requestId, String approver) throws GuacamoleException {
        update("DELETE FROM pam_request_approval WHERE request_id = ? AND approver = ?", requestId, approver);
    }

    /**
     * Marks a pending request as approved, linked to its checkout.
     */
    public void markApproved(int requestId, int checkoutId, String approver) throws GuacamoleException {
        try (Connection connection = database.getConnection();
             PreparedStatement statement = connection.prepareStatement(
                 "UPDATE pam_request SET status = 'APPROVED', decided = " + dialect.now() + ", decided_by = ?,"
               + " checkout_id = ? WHERE request_id = ? AND status = 'PENDING'")) {
            statement.setString(1, approver);
            statement.setInt(2, checkoutId);
            statement.setInt(3, requestId);
            statement.executeUpdate();
        }
        catch (SQLException e) {
            throw new GuacamoleServerException("Unable to record the approval.", e);
        }
    }

    /**
     * Marks a pending request made ahead of time as approved: a reservation,
     * until its requester uses it. If the access excludes other holders,
     * others' pending requests for an overlapping time are rejected, as they
     * could no longer be approved.
     *
     * @param exclusive
     *     Whether the access excludes other holders.
     *
     * @return
     *     The identifiers of the requests rejected.
     *
     * @throws GuacamoleClientException
     *     If the request is no longer pending, or its time is no longer free
     *     (see {@link #requireFree}).
     */
    public List<Integer> markReserved(ApprovalRequest request, String approver, boolean exclusive)
            throws GuacamoleException {

        Integer connectionId = request.getConnectionIdentifier() == null ? null
                : Integer.valueOf(request.getConnectionIdentifier());
        if (connectionId == null || request.getStarts() == null)
            throw new GuacamoleResourceNotFoundException("The connection no longer exists.");

        try (Connection connection = database.getConnection()) {

            connection.setAutoCommit(false);
            try {

                lockConnection(connection, connectionId);
                requireFree(connection, connectionId, request.getUsername(), request.getStarts(), request.getEnds(),
                        exclusive);

                try (PreparedStatement statement = connection.prepareStatement(
                        "UPDATE pam_request SET status = 'APPROVED', decided = " + dialect.now() + ", decided_by = ?"
                      + " WHERE request_id = ? AND status = 'PENDING'")) {
                    statement.setString(1, approver);
                    statement.setInt(2, request.getId());
                    if (statement.executeUpdate() == 0)
                        throw new GuacamoleClientException("This request is no longer awaiting approval.");
                }

                List<Integer> rejected = exclusive
                        ? rejectOverlapping(connection, connectionId, request) : Collections.<Integer>emptyList();

                connection.commit();
                return rejected;

            }
            catch (SQLException | GuacamoleException e) {
                connection.rollback();
                throw e;
            }

        }
        catch (SQLException e) {
            throw new GuacamoleServerException("Unable to record the approval.", e);
        }

    }

    /**
     * Rejects the requests of others made ahead of time, still pending, for
     * a time overlapping the given one just reserved: they could no longer
     * be approved. Rejected by no one, with the reason shown to their
     * requesters. Run with the connection's row locked.
     *
     * @return
     *     The identifiers of the requests rejected.
     */
    private List<Integer> rejectOverlapping(Connection connection, int connectionId, ApprovalRequest reserved)
            throws SQLException {

        List<Integer> rejected = new ArrayList<>();
        try (PreparedStatement statement = connection.prepareStatement(
                "SELECT request_id FROM pam_request WHERE connection_id = ? AND status = 'PENDING'"
              + " AND starts IS NOT NULL AND username <> ? AND starts < ? AND ends > ?")) {
            statement.setInt(1, connectionId);
            statement.setString(2, reserved.getUsername());
            SqlDialect.setTimestamp(statement, 3, reserved.getEnds());
            SqlDialect.setTimestamp(statement, 4, reserved.getStarts());
            try (ResultSet results = statement.executeQuery()) {
                while (results.next())
                    rejected.add(results.getInt(1));
            }
        }

        if (rejected.isEmpty())
            return rejected;

        try (PreparedStatement statement = connection.prepareStatement(
                "UPDATE pam_request SET status = 'DENIED', decided = " + dialect.now() + ", decided_by = NULL,"
              + " decision_reason = ? WHERE status = 'PENDING' AND request_id IN " + SqlDialect.in(rejected))) {
            statement.setString(1, "Rejected automatically: the time asked for overlaps that of \""
                    + reserved.getUsername() + "\" (request " + reserved.getId() + "), approved first, and"
                    + " this is held by one user at a time. Please request another time.");
            statement.executeUpdate();
        }

        return rejected;

    }

    /**
     * Links a reservation to the checkout its holder started with it, which
     * ends it.
     */
    public void markUsed(int requestId, int checkoutId) throws GuacamoleException {
        try (Connection connection = database.getConnection();
             PreparedStatement statement = connection.prepareStatement(
                 "UPDATE pam_request SET checkout_id = ? WHERE request_id = ? AND checkout_id IS NULL")) {
            statement.setInt(1, checkoutId);
            statement.setInt(2, requestId);
            statement.executeUpdate();
        }
        catch (SQLException e) {
            throw new GuacamoleServerException("Unable to update the request.", e);
        }
    }

    /**
     * Cancels a reservation not used yet, recording who cancelled it (its
     * holder, or who deleted its connection), and from where (or null).
     *
     * @throws GuacamoleClientException
     *     If it was used or ended meanwhile.
     */
    public void cancelReservation(int requestId, String cancelledBy, String remoteHost) throws GuacamoleException {
        try (Connection connection = database.getConnection();
             PreparedStatement statement = connection.prepareStatement(
                 "UPDATE pam_request SET status = 'CANCELLED', decided = " + dialect.now() + ", decided_by = ?,"
               + " decided_host = ? WHERE request_id = ? AND " + reserved(dialect, ""))) {
            statement.setString(1, cancelledBy);
            statement.setString(2, remoteHost);
            statement.setInt(3, requestId);
            if (statement.executeUpdate() == 0)
                throw new GuacamoleClientException("This access was already used, or has ended.");
        }
        catch (SQLException e) {
            throw new GuacamoleServerException("Unable to update the request.", e);
        }
    }

    /**
     * Ends a pending request without a checkout: denied by an approver, or
     * cancelled by its requester (or who deleted its connection).
     *
     * @param remoteHost
     *     Where who decided did so from, or null if unknown.
     *
     * @throws GuacamoleClientException
     *     If the request is no longer pending.
     */
    public void decide(int requestId, String status, String decidedBy, String remoteHost) throws GuacamoleException {
        decide(requestId, status, decidedBy, remoteHost, null);
    }

    /**
     * Ends a pending request without a checkout, recording why (for a
     * denial), or null.
     *
     * @param remoteHost
     *     Where who decided did so from, or null if unknown.
     *
     * @throws GuacamoleClientException
     *     If the request is no longer pending.
     */
    public void decide(int requestId, String status, String decidedBy, String remoteHost, String reason)
            throws GuacamoleException {

        expireStale(true);

        try (Connection connection = database.getConnection();
             PreparedStatement statement = connection.prepareStatement(
                 "UPDATE pam_request SET status = ?, decided = " + dialect.now() + ", decided_by = ?,"
               + " decided_host = ?, decision_reason = ? WHERE request_id = ? AND status = 'PENDING'")) {

            statement.setString(1, status);
            statement.setString(2, decidedBy);
            statement.setString(3, remoteHost);
            statement.setString(4, reason);
            statement.setInt(5, requestId);
            if (statement.executeUpdate() == 0)
                throw new GuacamoleClientException("This request is no longer awaiting approval.");

        }
        catch (SQLException e) {
            throw new GuacamoleServerException("Unable to update the request.", e);
        }

    }

    /**
     * Expires requests left pending for too long (24 hours, or until the end
     * of the time asked for ahead of time, or of the checkout an extension
     * would extend): always before a decision, at
     * most once a minute before a read, so reads may show a request for up
     * to a minute past its expiry.
     */
    private void expireStale(boolean always) throws GuacamoleException {

        long now = System.currentTimeMillis();
        if (!always && now - lastExpiry < EXPIRY_CHECK_MS)
            return;

        try (Connection connection = database.getConnection();
             PreparedStatement statement = connection.prepareStatement(
                 "UPDATE pam_request SET status = 'EXPIRED', decided = " + dialect.now()
               + " WHERE status = 'PENDING' AND ((ends IS NULL AND requested < " + dialect.plusSeconds(dialect.now(), "?")
               + ") OR ends <= " + dialect.now()
               + " OR extends_checkout IN (SELECT checkout_id FROM pam_checkout"
               + "   WHERE released IS NOT NULL OR expires <= " + dialect.now() + "))")) {
            statement.setInt(1, -PENDING_HOURS * 3600);
            statement.executeUpdate();
        }
        catch (SQLException e) {
            throw new GuacamoleServerException("Unable to expire requests.", e);
        }

        lastExpiry = now;

    }

    private void requirePending(Connection connection, int requestId)
            throws SQLException, GuacamoleException {

        try (PreparedStatement statement = connection.prepareStatement(
                "SELECT status FROM " + dialect.lockingRead("pam_request") + " WHERE request_id = ?"
              + dialect.forUpdate())) {
            statement.setInt(1, requestId);
            try (ResultSet results = statement.executeQuery()) {
                if (!results.next())
                    throw new GuacamoleResourceNotFoundException("No such request.");
                if (!ApprovalRequest.PENDING.equals(results.getString(1)))
                    throw new GuacamoleClientException("This request is no longer awaiting approval.");
            }
        }

    }

    private void update(String sql, int id, String value) throws GuacamoleException {
        try (Connection connection = database.getConnection();
             PreparedStatement statement = connection.prepareStatement(sql)) {
            statement.setInt(1, id);
            statement.setString(2, value);
            statement.executeUpdate();
        }
        catch (SQLException e) {
            throw new GuacamoleServerException("Unable to update the request.", e);
        }
    }

    /**
     * Runs a query of requests. Parameters are integers or strings.
     */
    private List<ApprovalRequest> query(String sql, Object... parameters) throws GuacamoleException {

        List<ApprovalRequest> requests = new ArrayList<>();

        try (Connection connection = database.getConnection();
             PreparedStatement statement = connection.prepareStatement(sql)) {

            for (int i = 0; i < parameters.length; i++) {
                if (parameters[i] instanceof String)
                    statement.setString(i + 1, (String) parameters[i]);
                else
                    statement.setInt(i + 1, (Integer) parameters[i]);
            }

            try (ResultSet results = statement.executeQuery()) {
                while (results.next()) {
                    ApprovalRequest request = new ApprovalRequest();
                    request.setId(results.getInt(1));
                    int connectionId = results.getInt(2);
                    request.setConnectionIdentifier(results.wasNull() ? null : Integer.toString(connectionId));
                    request.setConnectionName(results.getString(3));
                    request.setAccountName(results.getString(4));
                    request.setUsername(results.getString(5));
                    request.setReason(results.getString(6));
                    request.setRequested(SqlDialect.getTimestamp(results, 7).getTime());
                    request.setApprovalsRequired(results.getInt(8));
                    request.setStatus(results.getString(9));
                    Timestamp decided = SqlDialect.getTimestamp(results, 10);
                    request.setDecided(decided == null ? null : decided.getTime());
                    request.setDecidedBy(results.getString(11));
                    int checkoutId = results.getInt(12);
                    request.setCheckoutId(results.wasNull() ? null : checkoutId);
                    request.setDecisionReason(results.getString(13));
                    request.setRemoteHost(results.getString(14));
                    Timestamp starts = SqlDialect.getTimestamp(results, 15);
                    request.setStarts(starts == null ? null : starts.getTime());
                    Timestamp ends = SqlDialect.getTimestamp(results, 16);
                    request.setEnds(ends == null ? null : ends.getTime());
                    request.setDecidedHost(results.getString(17));
                    request.setPeriods(results.getInt(18));
                    int extendsCheckout = results.getInt(19);
                    request.setExtendsCheckout(results.wasNull() ? null : extendsCheckout);
                    int extensionMinutes = results.getInt(20);
                    request.setExtensionMinutes(results.wasNull() ? null : extensionMinutes);
                    requests.add(request);
                }
            }

            readApprovers(connection, requests);

        }
        catch (SQLException e) {
            throw new GuacamoleServerException("Unable to read requests.", e);
        }

        return requests;

    }

    /**
     * Adds who approved each request, in the order they approved, with when
     * and from where.
     */
    private static void readApprovers(Connection connection, List<ApprovalRequest> requests) throws SQLException {

        Map<Integer, ApprovalRequest> byId = new HashMap<>();
        for (ApprovalRequest request : requests)
            byId.put(request.getId(), request);
        if (byId.isEmpty())
            return;

        try (PreparedStatement statement = connection.prepareStatement(
                "SELECT request_id, approver, approved, remote_host FROM pam_request_approval"
              + " WHERE request_id IN " + SqlDialect.in(byId.keySet()) + " ORDER BY approved, approver");
             ResultSet results = statement.executeQuery()) {
            while (results.next()) {
                ApprovalRequest request = byId.get(results.getInt(1));
                request.getApprovers().add(results.getString(2));
                request.getApprovals().add(new ApprovalRequest.Approval(results.getString(2),
                        SqlDialect.getTimestamp(results, 3).getTime(), results.getString(4)));
            }
        }

    }

}
