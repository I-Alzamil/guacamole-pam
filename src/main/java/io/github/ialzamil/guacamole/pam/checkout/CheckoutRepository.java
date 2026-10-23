package io.github.ialzamil.guacamole.pam.checkout;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Timestamp;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.apache.guacamole.GuacamoleClientException;
import org.apache.guacamole.GuacamoleException;
import org.apache.guacamole.GuacamoleResourceNotFoundException;
import org.apache.guacamole.GuacamoleServerException;

import io.github.ialzamil.guacamole.pam.approval.ApprovalRepository;
import io.github.ialzamil.guacamole.pam.approval.ApprovalRequest;
import io.github.ialzamil.guacamole.pam.db.PamDatabase;
import io.github.ialzamil.guacamole.pam.db.SearchPattern;
import io.github.ialzamil.guacamole.pam.db.SqlDialect;

/**
 * Storage of checkouts in "pam_checkout". Creating a checkout locks the row
 * of its connection for the duration of the transaction, so concurrent
 * requests cannot both get an exclusive checkout, or mix exclusive and
 * shared ones. On PostgreSQL and MySQL, unique indexes enforce the same
 * rules as a last line of defence (not on SQL Server: see
 * schema/sqlserver.sql).
 */
public class CheckoutRepository {

    /**
     * The connection's current name, or the one it had once deleted.
     */
    private static final String SELECT = "SELECT k.checkout_id, k.connection_id,"
            + " coalesce(c.connection_name, k.connection_name), k.username,"
            + " k.reason, k.checked_out, k.expires, k.released, k.release_reason, k.released_by, k.reveal_count,"
            + " k.exclusive, k.remote_host, k.released_host, k.extensions, k.max_extensions"
            + " FROM pam_checkout k LEFT JOIN guacamole_connection c ON c.connection_id = k.connection_id";

    private final PamDatabase database;

    private final SqlDialect dialect;

    public CheckoutRepository(PamDatabase database) {
        this.database = database;
        this.dialect = database.getDialect();
    }

    /**
     * Creates an active checkout whose password was shown the given number
     * of times so far: once when handed over directly, never yet when
     * started by an approval. An exclusive checkout ends when someone else's
     * reservation of the connection starts, if earlier.
     *
     * @param remoteHost
     *     Where the user requested it from, or null if unknown.
     *
     * @param minutes
     *     How long the checkout lasts, unless it ends at a given time.
     *
     * @param until
     *     When the checkout ends (that of a reservation), or null to end it
     *     after the given minutes.
     *
     * @param maxExtensions
     *     How many times the checkout may be extended.
     *
     * @throws GuacamoleClientException
     *     If the request conflicts with an active checkout: the user already
     *     holds the password, someone holds it exclusively, or an exclusive
     *     checkout is requested while anyone holds it; or if an exclusive
     *     checkout is requested during, or less than a minute before,
     *     someone else's reservation.
     */
    public Checkout create(int connectionId, String username, String remoteHost, String reason, int minutes,
            Long until, boolean exclusive, int revealCount, int maxExtensions) throws GuacamoleException {

        try (Connection connection = database.getConnection()) {

            connection.setAutoCommit(false);
            try {

                // Serializes checkouts of this connection until commit
                try (PreparedStatement statement = connection.prepareStatement(
                        "SELECT connection_id FROM " + dialect.lockingRead("guacamole_connection")
                      + " WHERE connection_id = ?" + dialect.forUpdate())) {
                    statement.setInt(1, connectionId);
                    try (ResultSet results = statement.executeQuery()) {
                        if (!results.next())
                            throw new GuacamoleResourceNotFoundException("The connection no longer exists.");
                    }
                }

                for (Checkout active : query(connection, SELECT
                        + " WHERE k.connection_id = ? AND k.released IS NULL", connectionId)) {

                    if (active.getUsername().equals(username))
                        throw new GuacamoleClientException("You already hold this password.");
                    if (active.isExclusive())
                        throw new GuacamoleClientException("This password is checked out by \""
                                + active.getUsername() + "\" until it is released or expires.");
                    if (exclusive)
                        throw new GuacamoleClientException("This password is in use by \""
                                + active.getUsername() + "\" and can only be held by one user at a time.");

                }

                // The next reservation of someone else, which an exclusive
                // checkout must leave room for
                Timestamp reservedFrom = null;
                if (exclusive) {
                    try (PreparedStatement statement = connection.prepareStatement(
                            "SELECT username, starts, CASE WHEN starts <= " + dialect.plusSeconds(dialect.now(), "60")
                          + " THEN 1 ELSE 0 END FROM pam_request WHERE connection_id = ? AND username <> ? AND "
                          + ApprovalRepository.reserved(dialect, "") + " ORDER BY starts")) {
                        statement.setInt(1, connectionId);
                        statement.setString(2, username);
                        try (ResultSet results = statement.executeQuery()) {
                            if (results.next()) {
                                if (results.getInt(3) == 1)
                                    throw new GuacamoleClientException("This is reserved by \""
                                            + results.getString(1) + "\" now.");
                                reservedFrom = SqlDialect.getTimestamp(results, 2);
                            }
                        }
                    }
                }

                int id;
                try (PreparedStatement statement = connection.prepareStatement(
                        "INSERT INTO pam_checkout (connection_id, connection_name, username, remote_host, reason,"
                      + " expires, exclusive, reveal_count, max_extensions) SELECT connection_id, connection_name, ?, ?, ?,"
                      + " " + (until == null ? dialect.plusSeconds(dialect.now(), "?") : "?") + ", ?, ?, ?"
                      + " FROM guacamole_connection WHERE connection_id = ?", new String[] { "checkout_id" })) {
                    statement.setString(1, username);
                    statement.setString(2, remoteHost);
                    statement.setString(3, reason);
                    if (until == null)
                        statement.setInt(4, minutes * 60);
                    else
                        SqlDialect.setTimestamp(statement, 4, until);
                    statement.setBoolean(5, exclusive);
                    statement.setInt(6, revealCount);
                    statement.setInt(7, maxExtensions);
                    statement.setInt(8, connectionId);
                    statement.executeUpdate();
                    try (ResultSet results = statement.getGeneratedKeys()) {
                        if (!results.next())
                            throw new GuacamoleResourceNotFoundException("The connection no longer exists.");
                        id = results.getInt(1);
                    }
                }

                if (reservedFrom != null) {
                    try (PreparedStatement statement = connection.prepareStatement(
                            "UPDATE pam_checkout SET expires = ? WHERE checkout_id = ? AND expires > ?")) {
                        SqlDialect.setTimestamp(statement, 1, reservedFrom.getTime());
                        statement.setInt(2, id);
                        SqlDialect.setTimestamp(statement, 3, reservedFrom.getTime());
                        statement.executeUpdate();
                    }
                }

                connection.commit();
                return query(connection, SELECT + " WHERE k.checkout_id = ?", id).get(0);

            }
            catch (SQLException | GuacamoleException e) {
                connection.rollback();
                throw e;
            }

        }
        catch (SQLException e) {
            if (dialect.isUniqueViolation(e))
                throw new GuacamoleClientException("This password is already checked out.");
            throw new GuacamoleServerException("Unable to create the checkout.", e);
        }

    }

    public Checkout get(int checkoutId) throws GuacamoleException {
        List<Checkout> checkouts = query(SELECT + " WHERE k.checkout_id = ?", checkoutId);
        return checkouts.isEmpty() ? null : checkouts.get(0);
    }

    /**
     * Returns every active checkout of a connection.
     */
    public List<Checkout> listActive(int connectionId) throws GuacamoleException {
        return query(SELECT + " WHERE k.connection_id = ? AND k.released IS NULL ORDER BY k.checked_out",
                connectionId);
    }

    /**
     * Returns the given user's active checkout of a connection, or null.
     * A checkout past its time limit is not active, even before it is
     * released.
     */
    public Checkout getActive(int connectionId, String username) throws GuacamoleException {

        try (Connection connection = database.getConnection();
             PreparedStatement statement = connection.prepareStatement(SELECT
                 + " WHERE k.connection_id = ? AND k.username = ? AND k.released IS NULL"
                 + " AND k.expires > " + dialect.now())) {

            statement.setInt(1, connectionId);
            statement.setString(2, username);
            List<Checkout> checkouts = read(connection, statement);
            return checkouts.isEmpty() ? null : checkouts.get(0);

        }
        catch (SQLException e) {
            throw new GuacamoleServerException("Unable to read checkouts.", e);
        }

    }

    /**
     * Returns how many users hold each Account connection right now, by
     * connection identifier. Accounts nobody holds are left out.
     */
    public Map<String, Integer> countAccountHolders(String accountProtocol) throws GuacamoleException {

        Map<String, Integer> counts = new HashMap<>();

        try (Connection connection = database.getConnection();
             PreparedStatement statement = connection.prepareStatement(
                 "SELECT k.connection_id, count(*) FROM pam_checkout k"
               + " JOIN guacamole_connection c ON c.connection_id = k.connection_id"
               + " WHERE k.released IS NULL AND c.protocol = ? GROUP BY k.connection_id")) {

            statement.setString(1, accountProtocol);
            try (ResultSet results = statement.executeQuery()) {
                while (results.next())
                    counts.put(Integer.toString(results.getInt(1)), results.getInt(2));
            }

        }
        catch (SQLException e) {
            throw new GuacamoleServerException("Unable to count checkouts.", e);
        }

        return counts;

    }

    public List<Checkout> listActive() throws GuacamoleException {
        return query(SELECT + " WHERE k.released IS NULL ORDER BY k.expires");
    }

    /**
     * Returns the newest checkouts, active or ended, matching every given
     * term. A term matches when the user, remote host, connection name,
     * reason, release reason, releasing user or an approver (or where either
     * acted from) contains it, ignoring case.
     */
    public List<Checkout> search(List<String> terms, int limit) throws GuacamoleException {

        StringBuilder sql = new StringBuilder(SELECT).append(" WHERE 1 = 1");
        List<String> patterns = new ArrayList<>();

        for (String term : terms) {
            if (term == null || term.trim().isEmpty())
                continue;
            sql.append(" AND (" + SearchPattern.matches("k.username")
                    + " OR " + SearchPattern.matches("coalesce(k.remote_host, '')")
                    + " OR " + SearchPattern.matches("coalesce(c.connection_name, k.connection_name)")
                    + " OR " + SearchPattern.matches("k.reason")
                    + " OR " + SearchPattern.matches("coalesce(k.release_reason, '')")
                    + " OR " + SearchPattern.matches("coalesce(k.released_by, '')")
                    + " OR " + SearchPattern.matches("coalesce(k.released_host, '')")
                    + " OR EXISTS (SELECT 1 FROM pam_request r JOIN pam_request_approval a ON a.request_id = r.request_id"
                    + "   WHERE r.checkout_id = k.checkout_id AND (" + SearchPattern.matches("a.approver")
                    + "   OR " + SearchPattern.matches("coalesce(a.remote_host, '')") + ")))");
            patterns.add(SearchPattern.contains(term));
        }

        sql.append(" ORDER BY k.checked_out DESC, k.checkout_id DESC").append(dialect.limit());

        try (Connection connection = database.getConnection();
             PreparedStatement statement = connection.prepareStatement(sql.toString())) {

            int index = 1;
            for (String pattern : patterns) {
                for (int i = 0; i < 9; i++)
                    statement.setString(index++, pattern);
            }
            statement.setInt(index, limit);

            return read(connection, statement);

        }
        catch (SQLException e) {
            throw new GuacamoleServerException("Unable to search checkouts.", e);
        }

    }

    /**
     * Counts one more display of the password of an active checkout.
     * Returns false if the checkout has ended, or passed its time limit: the
     * password must then not be shown.
     */
    public boolean recordReveal(int checkoutId) throws GuacamoleException {
        try (Connection connection = database.getConnection();
             PreparedStatement statement = connection.prepareStatement(
                 "UPDATE pam_checkout SET reveal_count = reveal_count + 1"
               + " WHERE checkout_id = ? AND released IS NULL AND expires > " + dialect.now())) {
            statement.setInt(1, checkoutId);
            return statement.executeUpdate() > 0;
        }
        catch (SQLException e) {
            throw new GuacamoleServerException("Unable to update the checkout.", e);
        }
    }

    /**
     * Connections other than Accounts whose password a checkout showed
     * since the password last changed through a rotation (ever, if it never
     * did). Accounts are checked out to be seen, so their rotation follows
     * their policy alone.
     */
    public Set<Integer> listShownSinceRotation(String accountProtocol) throws GuacamoleException {

        Set<Integer> shown = new HashSet<>();

        try (Connection connection = database.getConnection();
             PreparedStatement statement = connection.prepareStatement(
                 "SELECT DISTINCT k.connection_id FROM pam_checkout k"
               + " JOIN guacamole_connection c ON c.connection_id = k.connection_id"
               + " LEFT JOIN pam_rotation_state s ON s.connection_id = k.connection_id"
               + " WHERE k.reveal_count > 0 AND c.protocol <> ?"
               + " AND (s.last_success IS NULL OR k.released IS NULL OR k.released > s.last_success)")) {

            statement.setString(1, accountProtocol);
            try (ResultSet results = statement.executeQuery()) {
                while (results.next())
                    shown.add(results.getInt(1));
            }

        }
        catch (SQLException e) {
            throw new GuacamoleServerException("Unable to read checkouts.", e);
        }

        return shown;

    }

    /**
     * Extends an active checkout by the given minutes, counting one more
     * extension. An exclusive checkout then ends no later than when someone
     * else's next reservation starts.
     *
     * @return
     *     The checkout, extended.
     *
     * @throws GuacamoleClientException
     *     If the checkout ended, cannot be extended any more, or someone
     *     else's reservation starts when it ends.
     */
    public Checkout extend(int checkoutId, int minutes) throws GuacamoleException {

        try (Connection connection = database.getConnection()) {

            connection.setAutoCommit(false);
            try {

                Checkout checkout = get(connection, checkoutId);
                if (checkout == null || checkout.getConnectionIdentifier() == null || checkout.getReleased() != null)
                    throw new GuacamoleClientException("This checkout has ended.");

                // Serializes with checkouts and requests of this connection
                try (PreparedStatement statement = connection.prepareStatement(
                        "SELECT connection_id FROM " + dialect.lockingRead("guacamole_connection")
                      + " WHERE connection_id = ?" + dialect.forUpdate())) {
                    statement.setInt(1, Integer.parseInt(checkout.getConnectionIdentifier()));
                    statement.executeQuery().close();
                }

                // Read again, now that nothing else can change it
                checkout = get(connection, checkoutId);
                if (checkout.getReleased() != null || checkout.getExpires() <= System.currentTimeMillis())
                    throw new GuacamoleClientException("This checkout has ended.");
                if (checkout.getExtensions() >= checkout.getMaxExtensions())
                    throw new GuacamoleClientException("This checkout cannot be extended any more.");

                long expires = checkout.getExpires() + minutes * 60000L;
                if (checkout.isExclusive()) {
                    try (PreparedStatement statement = connection.prepareStatement(
                            "SELECT username, starts FROM pam_request WHERE connection_id = ? AND username <> ?"
                          + " AND " + ApprovalRepository.reserved(dialect, "") + " ORDER BY starts")) {
                        statement.setInt(1, Integer.parseInt(checkout.getConnectionIdentifier()));
                        statement.setString(2, checkout.getUsername());
                        try (ResultSet results = statement.executeQuery()) {
                            if (results.next()) {
                                long reserved = SqlDialect.getTimestamp(results, 2).getTime();
                                if (reserved <= checkout.getExpires())
                                    throw new GuacamoleClientException("This is reserved by \""
                                            + results.getString(1) + "\" as soon as your checkout ends.");
                                expires = Math.min(expires, reserved);
                            }
                        }
                    }
                }

                try (PreparedStatement statement = connection.prepareStatement(
                        "UPDATE pam_checkout SET expires = ?, extensions = extensions + 1"
                      + " WHERE checkout_id = ? AND released IS NULL")) {
                    SqlDialect.setTimestamp(statement, 1, expires);
                    statement.setInt(2, checkoutId);
                    statement.executeUpdate();
                }

                connection.commit();
                return get(connection, checkoutId);

            }
            catch (SQLException | GuacamoleException e) {
                connection.rollback();
                throw e;
            }

        }
        catch (SQLException e) {
            throw new GuacamoleServerException("Unable to extend the checkout.", e);
        }

    }

    private static Checkout get(Connection connection, int checkoutId) throws SQLException {
        List<Checkout> found = query(connection, SELECT + " WHERE k.checkout_id = ?", checkoutId);
        return found.isEmpty() ? null : found.get(0);
    }

    /**
     * Releases an active checkout. Returns false if it was already released.
     */
    public boolean release(int checkoutId, String releaseReason, String releasedBy) throws GuacamoleException {
        return release(checkoutId, releaseReason, releasedBy, null);
    }

    /**
     * Releases an active checkout, recording where who released it did so
     * from (or null). Returns false if it was already released.
     */
    public boolean release(int checkoutId, String releaseReason, String releasedBy, String releasedHost)
            throws GuacamoleException {

        try (Connection connection = database.getConnection();
             PreparedStatement statement = connection.prepareStatement(
                 "UPDATE pam_checkout SET released = " + dialect.now() + ", release_reason = ?, released_by = ?,"
               + " released_host = ? WHERE checkout_id = ? AND released IS NULL")) {

            statement.setString(1, releaseReason);
            statement.setString(2, releasedBy);
            statement.setString(3, releasedHost);
            statement.setInt(4, checkoutId);
            return statement.executeUpdate() > 0;

        }
        catch (SQLException e) {
            throw new GuacamoleServerException("Unable to release the checkout.", e);
        }

    }

    /**
     * Releases every active checkout past its time limit, returning them.
     */
    public List<Checkout> expireDue() throws GuacamoleException {

        List<Integer> expired = new ArrayList<>();

        try (Connection connection = database.getConnection()) {

            List<Integer> due = new ArrayList<>();
            try (PreparedStatement statement = connection.prepareStatement(
                    "SELECT checkout_id FROM pam_checkout WHERE released IS NULL AND expires <= " + dialect.now());
                 ResultSet results = statement.executeQuery()) {
                while (results.next())
                    due.add(results.getInt(1));
            }

            // Each released once, here or by another server
            try (PreparedStatement statement = connection.prepareStatement(
                    "UPDATE pam_checkout SET released = " + dialect.now() + ", release_reason = 'EXPIRED'"
                  + " WHERE checkout_id = ? AND released IS NULL")) {
                for (int id : due) {
                    statement.setInt(1, id);
                    if (statement.executeUpdate() > 0)
                        expired.add(id);
                }
            }

        }
        catch (SQLException e) {
            throw new GuacamoleServerException("Unable to expire checkouts.", e);
        }

        List<Checkout> checkouts = new ArrayList<>();
        for (int id : expired)
            checkouts.add(get(id));
        return checkouts;

    }

    /**
     * Returns the checkouts that ended within the given number of seconds,
     * on any server.
     */
    public List<Checkout> listEndedWithin(int seconds) throws GuacamoleException {
        return query(SELECT + " WHERE k.released > " + dialect.plusSeconds(dialect.now(), "?"), -seconds);
    }

    private List<Checkout> query(String sql, int... parameters) throws GuacamoleException {
        try (Connection connection = database.getConnection()) {
            return query(connection, sql, parameters);
        }
        catch (SQLException e) {
            throw new GuacamoleServerException("Unable to read checkouts.", e);
        }
    }

    private static List<Checkout> query(Connection connection, String sql, int... parameters)
            throws SQLException {

        try (PreparedStatement statement = connection.prepareStatement(sql)) {
            for (int i = 0; i < parameters.length; i++)
                statement.setInt(i + 1, parameters[i]);
            return read(connection, statement);
        }

    }

    private static List<Checkout> read(Connection connection, PreparedStatement statement) throws SQLException {

        List<Checkout> checkouts = new ArrayList<>();

        try (ResultSet results = statement.executeQuery()) {
            while (results.next()) {
                Checkout checkout = new Checkout();
                checkout.setId(results.getInt(1));
                int connectionId = results.getInt(2);
                checkout.setConnectionIdentifier(results.wasNull() ? null : Integer.toString(connectionId));
                checkout.setConnectionName(results.getString(3));
                checkout.setUsername(results.getString(4));
                checkout.setReason(results.getString(5));
                checkout.setCheckedOut(SqlDialect.getTimestamp(results, 6).getTime());
                checkout.setExpires(SqlDialect.getTimestamp(results, 7).getTime());
                Timestamp released = SqlDialect.getTimestamp(results, 8);
                checkout.setReleased(released == null ? null : released.getTime());
                checkout.setReleaseReason(results.getString(9));
                checkout.setReleasedBy(results.getString(10));
                checkout.setRevealCount(results.getInt(11));
                checkout.setExclusive(results.getBoolean(12));
                checkout.setRemoteHost(results.getString(13));
                checkout.setReleasedHost(results.getString(14));
                checkout.setExtensions(results.getInt(15));
                checkout.setMaxExtensions(results.getInt(16));
                checkouts.add(checkout);
            }
        }

        readApprovers(connection, checkouts);
        return checkouts;

    }

    /**
     * Adds who approved the request that started each checkout, in the
     * order they approved (with when and from where), to the checkouts
     * started by an approval.
     */
    private static void readApprovers(Connection connection, List<Checkout> checkouts) throws SQLException {

        Map<Integer, Checkout> byId = new HashMap<>();
        for (Checkout checkout : checkouts)
            byId.put(checkout.getId(), checkout);
        if (byId.isEmpty())
            return;

        Map<Integer, List<String>> approvers = new HashMap<>();
        Map<Integer, List<ApprovalRequest.Approval>> approvals = new HashMap<>();
        try (PreparedStatement statement = connection.prepareStatement(
                "SELECT r.checkout_id, a.approver, a.approved, a.remote_host FROM pam_request r"
              + " JOIN pam_request_approval a ON a.request_id = r.request_id"
              + " WHERE r.checkout_id IN " + SqlDialect.in(byId.keySet()) + " AND r.extends_checkout IS NULL"
              + " ORDER BY a.approved, a.approver");
             ResultSet results = statement.executeQuery()) {
            while (results.next()) {
                approvers.computeIfAbsent(results.getInt(1), id -> new ArrayList<>()).add(results.getString(2));
                approvals.computeIfAbsent(results.getInt(1), id -> new ArrayList<>()).add(new ApprovalRequest.Approval(
                        results.getString(2), SqlDialect.getTimestamp(results, 3).getTime(), results.getString(4)));
            }
        }

        for (Map.Entry<Integer, List<String>> entry : approvers.entrySet()) {
            byId.get(entry.getKey()).setApprovedBy(entry.getValue());
            byId.get(entry.getKey()).setApprovals(approvals.get(entry.getKey()));
        }

        // The extensions granted, in order, with who approved them
        Map<Integer, Checkout.Extension> extensions = new HashMap<>();
        try (PreparedStatement statement = connection.prepareStatement(
                "SELECT extends_checkout, request_id, requested, decided, extension_minutes, reason, remote_host"
              + " FROM pam_request WHERE extends_checkout IN " + SqlDialect.in(byId.keySet())
              + " AND status = 'APPROVED' ORDER BY decided, request_id");
             ResultSet results = statement.executeQuery()) {
            while (results.next()) {
                Timestamp decided = SqlDialect.getTimestamp(results, 4);
                Checkout.Extension extension = new Checkout.Extension(SqlDialect.getTimestamp(results, 3).getTime(),
                        decided == null ? null : decided.getTime(), results.getInt(5), results.getString(6),
                        results.getString(7));
                extensions.put(results.getInt(2), extension);
                byId.get(results.getInt(1)).getExtensionHistory().add(extension);
            }
        }

        if (!extensions.isEmpty()) {
            try (PreparedStatement statement = connection.prepareStatement(
                    "SELECT request_id, approver, approved, remote_host FROM pam_request_approval"
                  + " WHERE request_id IN " + SqlDialect.in(extensions.keySet()) + " ORDER BY approved, approver");
                 ResultSet results = statement.executeQuery()) {
                while (results.next())
                    extensions.get(results.getInt(1)).getApprovals().add(new ApprovalRequest.Approval(
                            results.getString(2), SqlDialect.getTimestamp(results, 3).getTime(), results.getString(4)));
            }
        }

    }

}
