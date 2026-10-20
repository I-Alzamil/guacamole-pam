package org.apache.guacamole.pam.approval;

import java.io.IOException;
import java.sql.Array;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Timestamp;
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
import org.apache.guacamole.pam.db.PamDatabase;
import org.apache.guacamole.pam.db.SearchPattern;

/**
 * Storage of requests needing approval ("pam_request") and their
 * approvals ("pam_request_approval"), and the approval permissions of users
 * and user groups deciding who may approve them.
 */
public class ApprovalRepository {

    private static final String UNIQUE_VIOLATION = "23505";

    private static final ObjectMapper JSON = new ObjectMapper();

    /**
     * Identifier of the root connection group, containing every connection.
     */
    private static final String ROOT_GROUP = "ROOT";

    private static final TypeReference<List<String>> STRING_LIST = new TypeReference<List<String>>() { };

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
            + " r.checkout_id,"
            + " (SELECT array_agg(a.approver ORDER BY a.approved) FROM pam_request_approval a"
            + "   WHERE a.request_id = r.request_id),"
            + " r.decision_reason"
            + " FROM pam_request r LEFT JOIN guacamole_connection c ON c.connection_id = r.connection_id";

    private final PamDatabase database;

    public ApprovalRepository(PamDatabase database) {
        this.database = database;
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

        try (Connection connection = database.getConnection();
             PreparedStatement statement = connection.prepareStatement(
                 "WITH RECURSIVE member_of (entity_id) AS ("
               + "   SELECT g.entity_id FROM guacamole_entity e"
               + "   JOIN guacamole_user_group_member m ON m.member_entity_id = e.entity_id"
               + "   JOIN guacamole_user_group g ON g.user_group_id = m.user_group_id"
               + "   WHERE e.type = 'USER' AND e.name = ? AND NOT g.disabled"
               + " UNION"
               + "   SELECT g.entity_id FROM member_of p"
               + "   JOIN guacamole_user_group_member m ON m.member_entity_id = p.entity_id"
               + "   JOIN guacamole_user_group g ON g.user_group_id = m.user_group_id"
               + "   WHERE NOT g.disabled"
               + " ),"
               // Approval attributes of the user...
               + " grants (entity_id, attribute_name, attribute_value) AS ("
               + "   SELECT u.entity_id, a.attribute_name, a.attribute_value FROM guacamole_user_attribute a"
               + "   JOIN guacamole_user u ON u.user_id = a.user_id"
               + "   JOIN guacamole_entity e ON e.entity_id = u.entity_id"
               + "   WHERE e.type = 'USER' AND e.name = ? AND NOT u.disabled"
               // ...and of the groups the user belongs to
               + " UNION ALL"
               + "   SELECT g.entity_id, a.attribute_name, a.attribute_value FROM guacamole_user_group_attribute a"
               + "   JOIN guacamole_user_group g ON g.user_group_id = a.user_group_id"
               + "   JOIN guacamole_entity e ON e.entity_id = g.entity_id"
               + "   WHERE NOT g.disabled"
               + "   AND (g.entity_id IN (SELECT entity_id FROM member_of) OR e.name = ANY (?))"
               + " )"
               // Connections and connection groups listed by those granting
               // the permission
               + " SELECT c.attribute_name, c.attribute_value FROM grants c"
               + " WHERE c.attribute_name IN (?, ?) AND EXISTS (SELECT 1 FROM grants f"
               + "   WHERE f.entity_id = c.entity_id AND f.attribute_name = ? AND f.attribute_value = 'true')")) {

            statement.setString(1, username);
            statement.setString(2, username);
            statement.setArray(3, connection.createArrayOf("varchar", reportedGroups.toArray()));
            statement.setString(4, PamAttributes.APPROVER_CONNECTIONS);
            statement.setString(5, PamAttributes.APPROVER_CONNECTION_GROUPS);
            statement.setString(6, PamAttributes.APPROVER);

            Set<String> groups = new HashSet<>();
            try (ResultSet results = statement.executeQuery()) {
                while (results.next()) {
                    if (PamAttributes.APPROVER_CONNECTIONS.equals(results.getString(1)))
                        connections.addAll(parseIdentifiers(results.getString(2)));
                    else
                        groups.addAll(parseIdentifiers(results.getString(2)));
                }
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
     * Returns the identifiers of every connection within the given
     * connection groups, at any depth. "ROOT" stands for every connection.
     */
    private static Set<String> getConnectionsWithin(Connection connection, Set<String> groups)
            throws SQLException {

        boolean root = groups.contains(ROOT_GROUP);

        List<Integer> ids = new ArrayList<>();
        for (String group : groups) {
            try {
                ids.add(Integer.valueOf(group));
            }
            catch (NumberFormatException e) {
                // Only ROOT is not numeric
            }
        }

        Set<String> connections = new HashSet<>();

        try (PreparedStatement statement = connection.prepareStatement(
                "WITH RECURSIVE within (connection_group_id) AS ("
              + "   SELECT connection_group_id FROM guacamole_connection_group WHERE connection_group_id = ANY (?)"
              + " UNION"
              + "   SELECT g.connection_group_id FROM guacamole_connection_group g"
              + "   JOIN within w ON g.parent_id = w.connection_group_id"
              + " )"
              + " SELECT connection_id FROM guacamole_connection"
              + " WHERE ? OR parent_id IN (SELECT connection_group_id FROM within)")) {

            statement.setArray(1, connection.createArrayOf("integer", ids.toArray()));
            statement.setBoolean(2, root);

            try (ResultSet results = statement.executeQuery()) {
                while (results.next())
                    connections.add(Integer.toString(results.getInt(1)));
            }

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
     * @throws GuacamoleClientException
     *     If the user already has a pending request for the connection.
     */
    public ApprovalRequest create(int connectionId, String username, String reason, int approvalsRequired)
            throws GuacamoleException {

        expireStale(true);

        int id;
        try (Connection connection = database.getConnection();
             PreparedStatement statement = connection.prepareStatement(
                 "INSERT INTO pam_request (connection_id, connection_name, username, reason, approvals_required)"
               + " SELECT connection_id, connection_name, ?, ?, ? FROM guacamole_connection"
               + " WHERE connection_id = ? RETURNING request_id")) {

            statement.setString(1, username);
            statement.setString(2, reason);
            statement.setInt(3, approvalsRequired);
            statement.setInt(4, connectionId);

            try (ResultSet results = statement.executeQuery()) {
                if (!results.next())
                    throw new GuacamoleResourceNotFoundException("The connection no longer exists.");
                id = results.getInt(1);
            }

        }
        catch (SQLException e) {
            if (UNIQUE_VIOLATION.equals(e.getSQLState()))
                throw new GuacamoleClientException("You already have a request for this password awaiting approval.");
            throw new GuacamoleServerException("Unable to create the request.", e);
        }

        return get(id);

    }

    public ApprovalRequest get(int requestId) throws GuacamoleException {
        List<ApprovalRequest> requests = query(SELECT + " WHERE r.request_id = ?", requestId);
        return requests.isEmpty() ? null : requests.get(0);
    }

    /**
     * Returns the user's pending request for a connection, or null.
     */
    public ApprovalRequest getPending(int connectionId, String username) throws GuacamoleException {
        expireStale(false);
        List<ApprovalRequest> requests = query(SELECT
                + " WHERE r.connection_id = ? AND r.username = ? AND r.status = 'PENDING'", connectionId, username);
        return requests.isEmpty() ? null : requests.get(0);
    }

    /**
     * Returns the user's most recent request for a connection, or null.
     */
    public ApprovalRequest getLatest(int connectionId, String username) throws GuacamoleException {
        List<ApprovalRequest> requests = query(SELECT
                + " WHERE r.connection_id = ? AND r.username = ? ORDER BY r.requested DESC LIMIT 1",
                connectionId, username);
        return requests.isEmpty() ? null : requests.get(0);
    }

    /**
     * Returns the user's pending requests, by connection id.
     */
    public Map<Integer, ApprovalRequest> listPendingOf(String username) throws GuacamoleException {
        expireStale(false);
        return byConnection(query(SELECT + " WHERE r.username = ? AND r.status = 'PENDING'"
                + " AND r.connection_id IS NOT NULL", username));
    }

    /**
     * Returns the user's most recent request for each connection, by
     * connection id.
     */
    public Map<Integer, ApprovalRequest> listLatestOf(String username) throws GuacamoleException {
        return byConnection(query(SELECT.replaceFirst("^SELECT ", "SELECT DISTINCT ON (r.connection_id) ")
                + " WHERE r.username = ? AND r.connection_id IS NOT NULL ORDER BY r.connection_id, r.requested DESC",
                username));
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
     * Searches decided requests, most recently decided first. Every term
     * must match the requester, connection, account, reason, outcome, who
     * decided, the reason for a denial, or an approver. Only requests of the
     * given connections are searched (before the limit applies), or of all
     * if null.
     */
    public List<ApprovalRequest> searchDecided(List<String> terms, int limit, Set<String> connections)
            throws GuacamoleException {

        expireStale(false);

        StringBuilder sql = new StringBuilder(SELECT).append(" WHERE r.status <> 'PENDING'");
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
            sql.append(" AND r.connection_id = ANY (?)");
            parameters.add(ids);
        }

        for (String term : terms) {
            if (term == null || term.trim().isEmpty())
                continue;
            sql.append(" AND (r.username ILIKE ? ESCAPE '\\'"
                    + " OR coalesce(c.connection_name, r.connection_name) ILIKE ? ESCAPE '\\'"
                    + " OR coalesce((SELECT parameter_value FROM guacamole_connection_parameter p"
                    + "   WHERE p.connection_id = r.connection_id AND p.parameter_name = '" + AccountProtocol.USERNAME
                    + "'), '') ILIKE ? ESCAPE '\\'"
                    + " OR r.reason ILIKE ? ESCAPE '\\' OR r.status ILIKE ? ESCAPE '\\'"
                    + " OR coalesce(r.decided_by, '') ILIKE ? ESCAPE '\\'"
                    + " OR coalesce(r.decision_reason, '') ILIKE ? ESCAPE '\\'"
                    + " OR EXISTS (SELECT 1 FROM pam_request_approval a"
                    + "   WHERE a.request_id = r.request_id AND a.approver ILIKE ? ESCAPE '\\'))");
            String pattern = SearchPattern.contains(term);
            for (int i = 0; i < 8; i++)
                parameters.add(pattern);
        }

        sql.append(" ORDER BY coalesce(r.decided, r.requested) DESC LIMIT ?");
        parameters.add(limit);

        return query(sql.toString(), parameters.toArray());

    }

    /**
     * Records an approval of a pending request, returning the request with
     * the approval included.
     *
     * @throws GuacamoleClientException
     *     If the request is no longer pending, is the approver's own, or was
     *     already approved by the approver.
     */
    public ApprovalRequest approve(int requestId, String approver) throws GuacamoleException {

        expireStale(true);

        try (Connection connection = database.getConnection()) {

            connection.setAutoCommit(false);
            try {

                requirePending(connection, requestId, approver);

                try (PreparedStatement statement = connection.prepareStatement(
                        "INSERT INTO pam_request_approval (request_id, approver) VALUES (?, ?)"
                      + " ON CONFLICT DO NOTHING")) {
                    statement.setInt(1, requestId);
                    statement.setString(2, approver);
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
                 "UPDATE pam_request SET status = 'APPROVED', decided = CURRENT_TIMESTAMP, decided_by = ?,"
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
     * Ends a pending request without a checkout: denied by an approver, or
     * cancelled by its requester.
     *
     * @throws GuacamoleClientException
     *     If the request is no longer pending.
     */
    public void decide(int requestId, String status, String decidedBy) throws GuacamoleException {
        decide(requestId, status, decidedBy, null);
    }

    /**
     * Ends a pending request without a checkout, recording why (for a
     * denial), or null.
     *
     * @throws GuacamoleClientException
     *     If the request is no longer pending.
     */
    public void decide(int requestId, String status, String decidedBy, String reason) throws GuacamoleException {

        expireStale(true);

        try (Connection connection = database.getConnection();
             PreparedStatement statement = connection.prepareStatement(
                 "UPDATE pam_request SET status = ?, decided = CURRENT_TIMESTAMP, decided_by = ?,"
               + " decision_reason = ? WHERE request_id = ? AND status = 'PENDING'")) {

            statement.setString(1, status);
            statement.setString(2, decidedBy);
            statement.setString(3, reason);
            statement.setInt(4, requestId);
            if (statement.executeUpdate() == 0)
                throw new GuacamoleClientException("This request is no longer awaiting approval.");

        }
        catch (SQLException e) {
            throw new GuacamoleServerException("Unable to update the request.", e);
        }

    }

    /**
     * Expires requests left pending for too long: always before a decision,
     * at most once a minute before a read, so reads may show a request for
     * up to a minute past its expiry.
     */
    private void expireStale(boolean always) throws GuacamoleException {

        long now = System.currentTimeMillis();
        if (!always && now - lastExpiry < EXPIRY_CHECK_MS)
            return;

        try (Connection connection = database.getConnection();
             PreparedStatement statement = connection.prepareStatement(
                 "UPDATE pam_request SET status = 'EXPIRED', decided = CURRENT_TIMESTAMP"
               + " WHERE status = 'PENDING' AND requested < CURRENT_TIMESTAMP - make_interval(hours => ?)")) {
            statement.setInt(1, PENDING_HOURS);
            statement.executeUpdate();
        }
        catch (SQLException e) {
            throw new GuacamoleServerException("Unable to expire requests.", e);
        }

        lastExpiry = now;

    }

    private static void requirePending(Connection connection, int requestId, String approver)
            throws SQLException, GuacamoleException {

        try (PreparedStatement statement = connection.prepareStatement(
                "SELECT username, status FROM pam_request WHERE request_id = ? FOR UPDATE")) {
            statement.setInt(1, requestId);
            try (ResultSet results = statement.executeQuery()) {
                if (!results.next())
                    throw new GuacamoleResourceNotFoundException("No such request.");
                if (!ApprovalRequest.PENDING.equals(results.getString(2)))
                    throw new GuacamoleClientException("This request is no longer awaiting approval.");
                if (results.getString(1).equals(approver))
                    throw new GuacamoleClientException("You cannot approve your own request.");
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
     * Runs a query of requests. Parameters are integers, strings, or
     * collections of integers (bound as an array, for "= ANY (?)").
     */
    private List<ApprovalRequest> query(String sql, Object... parameters) throws GuacamoleException {

        List<ApprovalRequest> requests = new ArrayList<>();

        try (Connection connection = database.getConnection();
             PreparedStatement statement = connection.prepareStatement(sql)) {

            for (int i = 0; i < parameters.length; i++) {
                if (parameters[i] instanceof Collection)
                    statement.setArray(i + 1, connection.createArrayOf("integer",
                            ((Collection<?>) parameters[i]).toArray()));
                else if (parameters[i] instanceof String)
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
                    request.setRequested(results.getTimestamp(7).getTime());
                    request.setApprovalsRequired(results.getInt(8));
                    request.setStatus(results.getString(9));
                    Timestamp decided = results.getTimestamp(10);
                    request.setDecided(decided == null ? null : decided.getTime());
                    request.setDecidedBy(results.getString(11));
                    int checkoutId = results.getInt(12);
                    request.setCheckoutId(results.wasNull() ? null : checkoutId);
                    Array approvers = results.getArray(13);
                    if (approvers != null)
                        request.setApprovers(new ArrayList<>(Arrays.asList((String[]) approvers.getArray())));
                    request.setDecisionReason(results.getString(14));
                    requests.add(request);
                }
            }

        }
        catch (SQLException e) {
            throw new GuacamoleServerException("Unable to read requests.", e);
        }

        return requests;

    }

}
