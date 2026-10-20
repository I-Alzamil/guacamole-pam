package org.apache.guacamole.pam.checkout;

import java.sql.Array;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Timestamp;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.apache.guacamole.GuacamoleClientException;
import org.apache.guacamole.GuacamoleException;
import org.apache.guacamole.GuacamoleServerException;
import org.apache.guacamole.pam.db.PamDatabase;
import org.apache.guacamole.pam.db.SearchPattern;

/**
 * Storage of checkouts in "pam_checkout". Creating a checkout locks its
 * connection for the duration of the transaction, so concurrent requests
 * cannot both get an exclusive checkout, or mix exclusive and shared ones.
 * Unique indexes enforce the same rules as a last line of defence.
 */
public class CheckoutRepository {

    private static final String UNIQUE_VIOLATION = "23505";

    private static final String SELECT = "SELECT k.checkout_id, k.connection_id, c.connection_name, k.username,"
            + " k.reason, k.checked_out, k.expires, k.released, k.release_reason, k.released_by, k.reveal_count,"
            + " k.exclusive,"
            + " (SELECT array_agg(a.approver ORDER BY a.approved) FROM pam_request r"
            + "   JOIN pam_request_approval a ON a.request_id = r.request_id WHERE r.checkout_id = k.checkout_id)"
            + " FROM pam_checkout k JOIN guacamole_connection c ON c.connection_id = k.connection_id";

    private final PamDatabase database;

    public CheckoutRepository(PamDatabase database) {
        this.database = database;
    }

    /**
     * Creates an active checkout.
     *
     * @throws GuacamoleClientException
     *     If the request conflicts with an active checkout: the user already
     *     holds the password, someone holds it exclusively, or an exclusive
     *     checkout is requested while anyone holds it.
     */
    public Checkout create(int connectionId, String username, String reason, int minutes, boolean exclusive)
            throws GuacamoleException {
        return create(connectionId, username, reason, minutes, exclusive, 1);
    }

    /**
     * Creates an active checkout whose password was shown the given number
     * of times so far: once when handed over directly, never yet when
     * started by an approval.
     */
    public Checkout create(int connectionId, String username, String reason, int minutes, boolean exclusive,
            int revealCount) throws GuacamoleException {

        try (Connection connection = database.getConnection()) {

            connection.setAutoCommit(false);
            try {

                // Serializes checkouts of this connection until commit
                try (PreparedStatement statement = connection.prepareStatement(
                        "SELECT pg_advisory_xact_lock(?)")) {
                    statement.setInt(1, connectionId);
                    statement.execute();
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

                int id;
                try (PreparedStatement statement = connection.prepareStatement(
                        "INSERT INTO pam_checkout (connection_id, username, reason, expires, exclusive, reveal_count)"
                      + " VALUES (?, ?, ?, CURRENT_TIMESTAMP + make_interval(mins => ?), ?, ?) RETURNING checkout_id")) {
                    statement.setInt(1, connectionId);
                    statement.setString(2, username);
                    statement.setString(3, reason);
                    statement.setInt(4, minutes);
                    statement.setBoolean(5, exclusive);
                    statement.setInt(6, revealCount);
                    try (ResultSet results = statement.executeQuery()) {
                        results.next();
                        id = results.getInt(1);
                    }
                }

                connection.commit();
                return get(id);

            }
            catch (SQLException | GuacamoleException e) {
                connection.rollback();
                throw e;
            }

        }
        catch (SQLException e) {
            if (UNIQUE_VIOLATION.equals(e.getSQLState()))
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
     */
    public Checkout getActive(int connectionId, String username) throws GuacamoleException {
        for (Checkout checkout : listActive(connectionId)) {
            if (checkout.getUsername().equals(username))
                return checkout;
        }
        return null;
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
     * term. A term matches when the user, connection name, reason, release
     * reason, releasing user or an approver contains it, ignoring case.
     */
    public List<Checkout> search(List<String> terms, int limit) throws GuacamoleException {

        StringBuilder sql = new StringBuilder(SELECT).append(" WHERE TRUE");
        List<String> patterns = new ArrayList<>();

        for (String term : terms) {
            if (term == null || term.trim().isEmpty())
                continue;
            sql.append(" AND (k.username ILIKE ? ESCAPE '\\' OR c.connection_name ILIKE ? ESCAPE '\\'"
                    + " OR k.reason ILIKE ? ESCAPE '\\' OR coalesce(k.release_reason, '') ILIKE ? ESCAPE '\\'"
                    + " OR coalesce(k.released_by, '') ILIKE ? ESCAPE '\\'"
                    + " OR EXISTS (SELECT 1 FROM pam_request r JOIN pam_request_approval a ON a.request_id = r.request_id"
                    + "   WHERE r.checkout_id = k.checkout_id AND a.approver ILIKE ? ESCAPE '\\'))");
            patterns.add(SearchPattern.contains(term));
        }

        sql.append(" ORDER BY k.checked_out DESC LIMIT ?");

        try (Connection connection = database.getConnection();
             PreparedStatement statement = connection.prepareStatement(sql.toString())) {

            int index = 1;
            for (String pattern : patterns) {
                for (int i = 0; i < 6; i++)
                    statement.setString(index++, pattern);
            }
            statement.setInt(index, limit);

            return read(statement);

        }
        catch (SQLException e) {
            throw new GuacamoleServerException("Unable to search checkouts.", e);
        }

    }

    /**
     * Counts one more display of the password of an active checkout.
     * Returns false if the checkout has ended: the password must then not
     * be shown.
     */
    public boolean recordReveal(int checkoutId) throws GuacamoleException {
        try (Connection connection = database.getConnection();
             PreparedStatement statement = connection.prepareStatement(
                 "UPDATE pam_checkout SET reveal_count = reveal_count + 1"
               + " WHERE checkout_id = ? AND released IS NULL")) {
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
     * Releases an active checkout. Returns false if it was already released.
     */
    public boolean release(int checkoutId, String releaseReason, String releasedBy) throws GuacamoleException {

        try (Connection connection = database.getConnection();
             PreparedStatement statement = connection.prepareStatement(
                 "UPDATE pam_checkout SET released = CURRENT_TIMESTAMP, release_reason = ?, released_by = ?"
               + " WHERE checkout_id = ? AND released IS NULL")) {

            statement.setString(1, releaseReason);
            statement.setString(2, releasedBy);
            statement.setInt(3, checkoutId);
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

        try (Connection connection = database.getConnection();
             PreparedStatement statement = connection.prepareStatement(
                 "UPDATE pam_checkout SET released = CURRENT_TIMESTAMP, release_reason = 'EXPIRED'"
               + " WHERE released IS NULL AND expires <= CURRENT_TIMESTAMP RETURNING checkout_id");
             ResultSet results = statement.executeQuery()) {

            while (results.next())
                expired.add(results.getInt(1));

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
        return query(SELECT + " WHERE k.released > CURRENT_TIMESTAMP - make_interval(secs => ?)", seconds);
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
            return read(statement);
        }

    }

    private static List<Checkout> read(PreparedStatement statement) throws SQLException {

        List<Checkout> checkouts = new ArrayList<>();

        try (ResultSet results = statement.executeQuery()) {
            while (results.next()) {
                Checkout checkout = new Checkout();
                checkout.setId(results.getInt(1));
                checkout.setConnectionIdentifier(Integer.toString(results.getInt(2)));
                checkout.setConnectionName(results.getString(3));
                checkout.setUsername(results.getString(4));
                checkout.setReason(results.getString(5));
                checkout.setCheckedOut(results.getTimestamp(6).getTime());
                checkout.setExpires(results.getTimestamp(7).getTime());
                Timestamp released = results.getTimestamp(8);
                checkout.setReleased(released == null ? null : released.getTime());
                checkout.setReleaseReason(results.getString(9));
                checkout.setReleasedBy(results.getString(10));
                checkout.setRevealCount(results.getInt(11));
                checkout.setExclusive(results.getBoolean(12));
                Array approvers = results.getArray(13);
                if (approvers != null)
                    checkout.setApprovedBy(Arrays.asList((String[]) approvers.getArray()));
                checkouts.add(checkout);
            }
        }

        return checkouts;

    }

}
