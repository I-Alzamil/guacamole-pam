package org.apache.guacamole.pam.rotation;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.HashSet;
import java.util.Set;

import org.apache.guacamole.GuacamoleException;
import org.apache.guacamole.GuacamoleServerException;
import org.apache.guacamole.pam.db.PamDatabase;

/**
 * Claims of connections being rotated, as PostgreSQL advisory locks, so
 * Guacamole servers sharing the database never rotate the same connection
 * at once. A claim holds a database connection of its own, outside the pool,
 * for the rotation's duration; closing it, or its dropping, releases the
 * lock.
 *
 * Locks use the two-key form, keyed by {@link #NAMESPACE} and the connection
 * id, which never collides with the one-key locks of checkouts.
 */
class RotationLocks {

    /**
     * First key of every rotation lock ("pamr").
     */
    private static final int NAMESPACE = 0x70616d72;

    private static final String HELD = "SELECT objid FROM pg_locks WHERE locktype = 'advisory'"
            + " AND objsubid = 2 AND classid = ?::oid AND granted"
            + " AND database = (SELECT oid FROM pg_database WHERE datname = current_database())";

    private final PamDatabase database;

    RotationLocks(PamDatabase database) {
        this.database = database;
    }

    /**
     * A claim on a connection, released when closed.
     */
    static final class Claim implements AutoCloseable {

        private final Connection connection;

        private Claim(Connection connection) {
            this.connection = connection;
        }

        @Override
        public void close() {
            try {
                // Closing the session releases its advisory locks
                connection.close();
            }
            catch (SQLException ignored) {
            }
        }

    }

    /**
     * Claims the connection, or returns null if it is already claimed, here
     * or by another server.
     */
    Claim tryClaim(int connectionId) throws GuacamoleException {

        Connection connection = database.getDedicatedConnection();
        try (PreparedStatement statement = connection.prepareStatement("SELECT pg_try_advisory_lock(?, ?)")) {

            statement.setInt(1, NAMESPACE);
            statement.setInt(2, connectionId);
            try (ResultSet results = statement.executeQuery()) {
                if (results.next() && results.getBoolean(1))
                    return new Claim(connection);
            }

        }
        catch (SQLException e) {
            new Claim(connection).close();
            throw new GuacamoleServerException("Unable to claim the connection for rotation.", e);
        }

        new Claim(connection).close();
        return null;

    }

    /**
     * Whether a rotation of the connection is running, here or on another
     * server.
     */
    boolean isClaimed(int connectionId) throws GuacamoleException {
        return getClaimed(" AND objid = ?::oid", connectionId).contains(connectionId);
    }

    /**
     * Ids of every connection being rotated right now.
     */
    Set<Integer> getClaimed() throws GuacamoleException {
        return getClaimed("");
    }

    private Set<Integer> getClaimed(String condition, int... parameters) throws GuacamoleException {

        Set<Integer> claimed = new HashSet<>();

        try (Connection connection = database.getConnection();
             PreparedStatement statement = connection.prepareStatement(HELD + condition)) {

            statement.setInt(1, NAMESPACE);
            for (int i = 0; i < parameters.length; i++)
                statement.setInt(i + 2, parameters[i]);

            try (ResultSet results = statement.executeQuery()) {
                while (results.next())
                    claimed.add((int) results.getLong(1));
            }

        }
        catch (SQLException e) {
            throw new GuacamoleServerException("Unable to read which connections are being rotated.", e);
        }

        return claimed;

    }

}
