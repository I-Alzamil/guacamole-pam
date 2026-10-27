package io.github.ialzamil.guacamole.pam.coordination;

import java.sql.Connection;
import java.sql.SQLException;
import java.util.Collection;
import java.util.Collections;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.stream.Collectors;
import java.util.stream.IntStream;

import org.apache.guacamole.GuacamoleException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import io.github.ialzamil.guacamole.pam.db.PamDatabase;
import io.github.ialzamil.guacamole.pam.db.SqlDialect;

/**
 * A server alone on its database, without the HA module: it holds the lock
 * {@link Coordination#SINGLE_LOCK} on a database connection of its own for
 * as long as it runs, so no other server works at the same time. Rotations
 * are then claimed, and sessions counted, in memory.
 *
 * A server finding the lock held, or servers of the HA module running, is
 * on standby, trying again with every check: it takes over once the other
 * stops. The database frees the lock as soon as the server holding it, or
 * its connection, is gone, so a server that crashed never keeps another
 * from starting. Taking over, a server removes the sessions the stopped one
 * left recorded, whose connections are then rotated after use.
 */
public final class SingleServer implements Coordination {

    private static final Logger logger = LoggerFactory.getLogger(SingleServer.class);

    /**
     * Seconds to wait for the database to answer, checking the lock's
     * connection.
     */
    private static final int VALID_TIMEOUT_SECONDS = 2;

    private static final Collection<Integer> SLOTS = IntStream.range(0, SHARED_SLOTS).boxed()
            .collect(Collectors.toList());

    private final PamDatabase database;

    private final SqlDialect dialect;

    /**
     * The connection holding the lock while this server is alone, kept open
     * while on standby to try again; null once lost.
     */
    private Connection lock;

    private volatile Standby standby = Standby.STARTING;

    /**
     * When this server was last found alone.
     */
    private volatile long aloneSince = Long.MAX_VALUE;

    private final Set<Integer> claimed = ConcurrentHashMap.newKeySet();

    public SingleServer(PamDatabase database) {
        this.database = database;
        this.dialect = database.getDialect();
    }

    @Override
    public synchronized Set<Integer> check(Sessions sessions) {

        boolean wasAlone = standby == null;
        if (wasAlone && isValid(lock))
            return Collections.emptySet();

        // Taken again at once if its connection dropped, unless another
        // server took it meanwhile
        try {

            if (!isValid(lock)) {
                closeLock();
                lock = database.getDedicatedConnection();
            }

            // Looked for before taking the lock too, so servers of the HA
            // module never find it taken, however briefly
            if (!dialect.getLocked(lock, SHARED_LOCK, SLOTS).isEmpty()) {
                enter(Standby.SHARED_SERVERS, null);
                return Collections.emptySet();
            }

            if (!dialect.tryLock(lock, SINGLE_LOCK, 0)) {
                enter(Standby.OTHER_SERVER, null);
                return Collections.emptySet();
            }

            // One starting meanwhile finds the lock taken
            if (!dialect.getLocked(lock, SHARED_LOCK, SLOTS).isEmpty()) {
                closeLock();
                enter(Standby.SHARED_SERVERS, null);
                return Collections.emptySet();
            }

        }
        catch (GuacamoleException | SQLException e) {
            closeLock();
            enter(Standby.DATABASE, e.getMessage());
            return Collections.emptySet();
        }

        if (wasAlone) {
            // Another server may have held it meanwhile, and changed what
            // this one keeps, such as the settings
            aloneSince = System.currentTimeMillis();
            logger.info("This Guacamole server took its database lock again, having lost its connection.");
            return Collections.emptySet();
        }

        if (standby == Standby.STARTING)
            logger.info("PAM runs on this Guacamole server alone: other servers sharing its database without the"
                    + " HA module stay on standby while it runs.");
        else
            logger.info("PAM works on this Guacamole server again: it is alone on the database.");
        aloneSince = System.currentTimeMillis();
        standby = null;

        try {
            return sessions.removeOthers();
        }
        catch (GuacamoleException e) {
            logger.warn("Unable to remove the sessions left by a stopped server: {}", e.getMessage());
            return Collections.emptySet();
        }

    }

    /**
     * Goes on standby for the given reason, logging it once, with any
     * detail.
     */
    private void enter(Standby reason, String detail) {
        if (standby != reason)
            logger.warn("{}{}", reason.getMessage(), detail == null ? "" : " (" + SqlDialect.firstLine(detail) + ")");
        standby = reason;
        aloneSince = Long.MAX_VALUE;
    }

    private static boolean isValid(Connection connection) {
        try {
            return connection != null && connection.isValid(VALID_TIMEOUT_SECONDS);
        }
        catch (SQLException e) {
            return false;
        }
    }

    /**
     * Closes the lock's connection, releasing the lock if held.
     */
    private void closeLock() {
        if (lock == null)
            return;
        try {
            lock.close();
        }
        catch (SQLException ignored) {
        }
        lock = null;
    }

    @Override
    public Standby getStandby() {
        return standby;
    }

    @Override
    public boolean isShared() {
        return false;
    }

    @Override
    public boolean isAloneSince(long time) {
        return standby == null && time >= aloneSince;
    }

    @Override
    public Claim tryClaim(int connectionId) {
        return claimed.add(connectionId) ? () -> claimed.remove(connectionId) : null;
    }

    @Override
    public Set<Integer> getClaimed(Collection<Integer> connectionIds) {
        Set<Integer> found = new HashSet<>(connectionIds);
        found.retainAll(claimed);
        return found;
    }

    @Override
    public Map<Integer, Integer> countSessions(Sessions sessions) {
        return sessions.countLocal();
    }

    @Override
    public synchronized void shutdown() {
        closeLock();
    }

}
