package io.github.ialzamil.guacamole.pam.ha;

import java.sql.Connection;
import java.sql.SQLException;
import java.util.Collection;
import java.util.Collections;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.TimeUnit;

import org.apache.guacamole.GuacamoleException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import io.github.ialzamil.guacamole.pam.coordination.Coordination;
import io.github.ialzamil.guacamole.pam.coordination.Standby;
import io.github.ialzamil.guacamole.pam.db.PamDatabase;
import io.github.ialzamil.guacamole.pam.db.SchemaUnavailableException;
import io.github.ialzamil.guacamole.pam.db.SqlDialect;

/**
 * PAM on several Guacamole servers working at once on their database, with
 * the HA module. Rotations are claimed through database locks
 * ({@link RotationLocks}), so only one server rotates a connection at a
 * time, and sessions counted from "pam_session", so every server knows
 * whether a connection is in use. Each server refreshes the heartbeat of
 * its rows as often as the HA module's own heartbeat, every 10 seconds;
 * rows of a server that stopped without removing them are ignored once
 * stale, after 45 seconds as the module's sessions, then removed, and their
 * connections rotated after use.
 *
 * Each server holds one of the locks {@link Coordination#SHARED_LOCK}, so a
 * server without the module stays on standby while they run; one that runs
 * nevertheless, alone (see the core's SingleServer), puts these on standby
 * instead until it stops.
 */
public final class SharedCoordination implements Coordination {

    private static final Logger logger = LoggerFactory.getLogger(SharedCoordination.class);

    /**
     * Age after which a session's row is no longer trusted, as those of the
     * HA module's own sessions: over four missed heartbeats.
     */
    static final int STALE_SECONDS = SessionStore.STALE_SECONDS;

    private static final long HEARTBEAT_MS = TimeUnit.SECONDS.toMillis(SessionStore.HEARTBEAT_SECONDS);

    private static final int VALID_TIMEOUT_SECONDS = 2;

    private final PamDatabase database;

    private final SqlDialect dialect;

    private final RotationLocks locks;

    /**
     * The connection holding this server's lock, or null until taken.
     */
    private Connection slot;

    /**
     * Whether every lock was found taken, which is logged once.
     */
    private boolean noSlot = false;

    private volatile Standby standby = Standby.STARTING;

    private long lastHeartbeat = 0;

    public SharedCoordination(PamDatabase database) {
        this.database = database;
        this.dialect = database.getDialect();
        this.locks = new RotationLocks(database);
    }

    @Override
    public synchronized Set<Integer> check(Sessions sessions) {

        try {

            // Taken before looking for a server alone, which looks for
            // these before taking its own: one of the two always sees the
            // other
            if (!isValid(slot))
                takeSlot();

            if (isSingleServerRunning())
                enter(Standby.SERVER_WITHOUT_HA, null);
            else {
                if (standby == Standby.STARTING)
                    logger.info("PAM is shared with the other Guacamole servers of the HA module on this database.");
                else if (standby != null)
                    logger.info("PAM works on this Guacamole server again: no server without the HA module runs"
                            + " on the database.");
                standby = null;
            }

        }
        catch (GuacamoleException | SQLException e) {
            closeSlot();
            enter(Standby.DATABASE, e.getMessage());
        }

        // On standby too, for the sessions opened before, and when only
        // the lock failed: other servers would otherwise take this one's
        // sessions for ended, and rotate their passwords
        long now = System.currentTimeMillis();
        if (now - lastHeartbeat < HEARTBEAT_MS)
            return Collections.emptySet();
        lastHeartbeat = now;

        try {
            sessions.refresh();
            return sessions.removeStale(STALE_SECONDS);
        }
        catch (SchemaUnavailableException e) {
            logger.debug("Session heartbeat skipped: {}", e.getMessage());
            return Collections.emptySet();
        }
        catch (GuacamoleException e) {
            // Said once already, while the database cannot be reached
            if (standby == Standby.DATABASE)
                logger.debug("Session heartbeat failed: {}", e.getMessage());
            else
                logger.error("Session heartbeat failed: {}", e.getMessage());
            logger.debug("Session heartbeat failed.", e);
            return Collections.emptySet();
        }

    }

    /**
     * Takes the first free lock of {@link Coordination#SHARED_LOCK} on a
     * connection of its own, held until this server stops.
     */
    private void takeSlot() throws GuacamoleException, SQLException {

        closeSlot();
        Connection connection = database.getDedicatedConnection();

        try {
            for (int key = 0; key < SHARED_SLOTS; key++) {
                if (dialect.tryLock(connection, SHARED_LOCK, key)) {
                    slot = connection;
                    noSlot = false;
                    return;
                }
            }
        }
        catch (SQLException | RuntimeException e) {
            close(connection);
            throw e;
        }

        close(connection);
        if (!noSlot)
            logger.error("More than {} Guacamole servers run the HA module on this database: servers without it"
                    + " may not see this one.", SHARED_SLOTS);
        noSlot = true;

    }

    /**
     * Whether a server without the module holds its lock.
     */
    private boolean isSingleServerRunning() throws GuacamoleException, SQLException {
        if (slot != null)
            return !dialect.getLocked(slot, SINGLE_LOCK, Collections.singleton(0)).isEmpty();
        try (Connection connection = database.getConnection()) {
            return !dialect.getLocked(connection, SINGLE_LOCK, Collections.singleton(0)).isEmpty();
        }
    }

    private void enter(Standby reason, String detail) {
        if (standby != reason)
            logger.warn("{}{}", reason.getMessage(), detail == null ? "" : " (" + SqlDialect.firstLine(detail) + ")");
        standby = reason;
    }

    private static boolean isValid(Connection connection) {
        try {
            return connection != null && connection.isValid(VALID_TIMEOUT_SECONDS);
        }
        catch (SQLException e) {
            return false;
        }
    }

    private void closeSlot() {
        close(slot);
        slot = null;
    }

    private static void close(Connection connection) {
        if (connection == null)
            return;
        try {
            connection.close();
        }
        catch (SQLException ignored) {
        }
    }

    @Override
    public Standby getStandby() {
        return standby;
    }

    @Override
    public boolean isShared() {
        return true;
    }

    @Override
    public boolean isAloneSince(long time) {
        return false;
    }

    @Override
    public Claim tryClaim(int connectionId) throws GuacamoleException {
        return locks.tryClaim(connectionId);
    }

    @Override
    public Set<Integer> getClaimed(Collection<Integer> connectionIds) throws GuacamoleException {
        return locks.getClaimed(connectionIds);
    }

    @Override
    public Map<Integer, Integer> countSessions(Sessions sessions) throws GuacamoleException {
        return sessions.countRecorded(STALE_SECONDS);
    }

    @Override
    public synchronized void shutdown() {
        closeSlot();
    }

}
