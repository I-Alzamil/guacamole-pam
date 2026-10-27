package io.github.ialzamil.guacamole.pam.coordination;

import java.util.Collection;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;
import java.util.stream.IntStream;

import org.apache.guacamole.GuacamoleClientException;
import org.apache.guacamole.GuacamoleException;

/**
 * How this Guacamole server shares PAM's work with the others on its
 * database, if any. Alone ({@link SingleServer}), the default, a server
 * holds a database lock for as long as it runs: any other server starting
 * on the database without the HA module finds it held, and stays on standby
 * until it is free. With the HA module, every server works at once, and
 * coordinates through the database (see the HA module's
 * SharedCoordination).
 *
 * A server on standby is read-only for PAM: no checkouts, approvals,
 * rotations, setting changes or sessions of managed connections, which
 * another server could not know of.
 */
public interface Coordination {

    /**
     * Namespace of the lock a server holds while alone ("paml"), whose only
     * key is 0.
     */
    int SINGLE_LOCK = 0x70616d6c;

    /**
     * Namespace of the locks servers running the HA module hold ("pamh"):
     * each holds one of the keys from 0 to {@link #SHARED_SLOTS} - 1, so a
     * server without the module knows they run.
     */
    int SHARED_LOCK = 0x70616d68;

    int SHARED_SLOTS = 64;

    /**
     * Those keys, from 0 to {@link #SHARED_SLOTS} - 1.
     */
    Collection<Integer> SHARED_KEYS = IntStream.range(0, SHARED_SLOTS).boxed()
            .collect(Collectors.toUnmodifiableList());

    /**
     * A claim on a connection being rotated, released when closed.
     */
    interface Claim extends AutoCloseable {

        @Override
        void close();

    }

    /**
     * This server's sessions of managed connections, as recorded in
     * "pam_session".
     */
    interface Sessions {

        /**
         * Open sessions per connection id on this server.
         */
        Map<Integer, Integer> countLocal();

        /**
         * Records each of this server's sessions again, refreshing their
         * heartbeat.
         */
        void refresh() throws GuacamoleException;

        /**
         * Removes the rows of every other server, returning the ids of the
         * connections they were of: those servers stopped.
         */
        Set<Integer> removeOthers() throws GuacamoleException;

        /**
         * Removes the rows of every server not refreshed within the given
         * seconds, returning the ids of the connections they were of.
         */
        Set<Integer> removeStale(int seconds) throws GuacamoleException;

        /**
         * Open sessions per connection id on every server, as recorded by
         * those that refreshed their rows within the given seconds.
         */
        Map<Integer, Integer> countRecorded(int seconds) throws GuacamoleException;

    }

    /**
     * Brings this server's role up to date, as the housekeeping does every
     * few seconds: taking over once alone, or going on standby. Returns the
     * ids of connections whose sessions ended unseen, on a server that
     * stopped, and so are due an after-use rotation.
     */
    Set<Integer> check(Sessions sessions);

    /**
     * Why this server is on standby, or null if PAM works on it.
     */
    Standby getStandby();

    /**
     * Refuses a change while this server is on standby.
     *
     * @throws GuacamoleClientException
     *     If it is, saying why.
     */
    default void requireActive() throws GuacamoleClientException {
        Standby standby = getStandby();
        if (standby != null)
            throw new GuacamoleClientException(standby.getMessage());
    }

    /**
     * Whether other servers may work on the database at the same time: the
     * HA module runs.
     */
    boolean isShared();

    /**
     * Whether this server alone has worked on the database since the given
     * time, so what it read then is still what the database holds, unless
     * it changed it itself.
     */
    boolean isAloneSince(long time);

    /**
     * Claims a connection for rotation, or returns null if it is already
     * claimed, here or on another server.
     */
    Claim tryClaim(int connectionId) throws GuacamoleException;

    /**
     * The ids among the given ones of connections being rotated right now.
     */
    Set<Integer> getClaimed(Collection<Integer> connectionIds) throws GuacamoleException;

    /**
     * Open sessions per connection id on every server, leaving out
     * connections with none.
     */
    Map<Integer, Integer> countSessions(Sessions sessions) throws GuacamoleException;

    void shutdown();

}
