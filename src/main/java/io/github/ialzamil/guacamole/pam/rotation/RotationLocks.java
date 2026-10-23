package io.github.ialzamil.guacamole.pam.rotation;

import java.sql.Connection;
import java.sql.SQLException;
import java.util.Collection;
import java.util.Collections;
import java.util.Set;

import org.apache.guacamole.GuacamoleException;
import org.apache.guacamole.GuacamoleServerException;

import io.github.ialzamil.guacamole.pam.db.PamDatabase;

/**
 * Claims of connections being rotated, as database locks held by a session
 * (see {@link io.github.ialzamil.guacamole.pam.db.SqlDialect#tryLock}), so Guacamole
 * servers sharing the database never rotate the same connection at once. A
 * claim holds a database connection of its own, outside the pool, for the
 * rotation's duration; closing it, or its dropping, releases the lock.
 *
 * Locks are keyed by {@link #NAMESPACE} and the connection id.
 */
class RotationLocks {

    /**
     * Namespace of every rotation lock ("pamr").
     */
    private static final int NAMESPACE = 0x70616d72;

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
                // Closing the session releases its locks
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
        try {
            if (database.getDialect().tryLock(connection, NAMESPACE, connectionId))
                return new Claim(connection);
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
        return getClaimed(Collections.singleton(connectionId)).contains(connectionId);
    }

    /**
     * Ids of the given connections being rotated right now.
     */
    Set<Integer> getClaimed(Collection<Integer> connectionIds) throws GuacamoleException {
        try (Connection connection = database.getConnection()) {
            return database.getDialect().getLocked(connection, NAMESPACE, connectionIds);
        }
        catch (SQLException e) {
            throw new GuacamoleServerException("Unable to read which connections are being rotated.", e);
        }
    }

}
