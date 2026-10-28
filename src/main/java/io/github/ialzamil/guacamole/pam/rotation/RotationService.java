package io.github.ialzamil.guacamole.pam.rotation;

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Executors;
import java.util.concurrent.RejectedExecutionException;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

import org.apache.guacamole.GuacamoleClientException;
import org.apache.guacamole.GuacamoleException;
import org.apache.guacamole.GuacamoleResourceNotFoundException;
import org.apache.guacamole.GuacamoleSecurityException;
import org.apache.guacamole.net.GuacamoleTunnel;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import io.github.ialzamil.guacamole.pam.AccountProtocol;
import io.github.ialzamil.guacamole.pam.PamAttributes;
import io.github.ialzamil.guacamole.pam.Values;
import io.github.ialzamil.guacamole.pam.checkout.Checkout;
import io.github.ialzamil.guacamole.pam.checkout.CheckoutRepository;
import io.github.ialzamil.guacamole.pam.coordination.Coordination;
import io.github.ialzamil.guacamole.pam.coordination.Standby;
import io.github.ialzamil.guacamole.pam.db.ConnectionRepository.Target;
import io.github.ialzamil.guacamole.pam.db.ConnectionRepository;
import io.github.ialzamil.guacamole.pam.db.PamDatabase;
import io.github.ialzamil.guacamole.pam.db.SchemaUnavailableException;
import io.github.ialzamil.guacamole.pam.management.ManagementType;
import io.github.ialzamil.guacamole.pam.management.ManagementTypes;
import io.github.ialzamil.guacamole.pam.management.PasswordChanger;
import io.github.ialzamil.guacamole.pam.notification.Event;
import io.github.ialzamil.guacamole.pam.notification.EventType;
import io.github.ialzamil.guacamole.pam.notification.Events;
import io.github.ialzamil.guacamole.pam.password.PasswordGenerator;
import io.github.ialzamil.guacamole.pam.password.PasswordPolicyRepository;
import io.github.ialzamil.guacamole.pam.password.PasswordRules;
import io.github.ialzamil.guacamole.pam.platform.Platform;
import io.github.ialzamil.guacamole.pam.platform.PlatformRepository;

/**
 * Decides when connections are rotated, and performs rotations.
 *
 * A rotation sets a new password on the target, as its platform's type does it
 * (over SSH with a sequence script, LDAP, Kerberos or WinRM), then checks which
 * password the target accepts. The new password is only stored in Guacamole
 * once the target accepts it.
 *
 * A connection is "in use" while it has open sessions or an active checkout;
 * automatic rotations wait until it is no longer in use. A connection whose
 * password a checkout showed (see {@link PamAttributes#REVEAL_PASSWORD}) is
 * rotated once no longer in use, whatever its rotation mode, so the password
 * stops working outside Guacamole; a failed rotation is retried as a
 * periodic one would be.
 *
 * Rotations are claimed, and sessions counted, as the {@link Coordination}
 * of this server does it: in memory on a server alone, through the database
 * with the HA module, so only one server rotates a connection at a time,
 * and every server knows whether a connection is in use. When a checkout
 * ends, the server ending it closes its own sessions of the holder at once;
 * with the HA module, the other servers close theirs when they next look for
 * ended checkouts. Each server also closes its sessions whose user lost
 * access to their connection meanwhile (see {@link SessionAccess}). On
 * standby, a server rotates nothing.
 */
public final class RotationService {

    private static final Logger logger = LoggerFactory.getLogger(RotationService.class);

    /**
     * Delay between the last session closing and an after-use rotation,
     * letting guacd finish disconnecting.
     */
    private static final long AFTER_USE_DELAY_SECONDS = 5;

    private static final long PERIODIC_CHECK_SECONDS = 60;

    /**
     * Why an administrator's rotation runs, in logs and events.
     */
    private static final String MANUAL = "manual";

    /**
     * How often this server checks its role (see {@link Coordination#check}),
     * ends checkouts past their time limit, and with the HA module closes its
     * sessions of checkouts ended on another server: all cheap, so a revoked
     * user is cut off on every server within seconds.
     */
    private static final long ENDED_CHECK_SECONDS = 2;

    /**
     * How often this server checks that the users of its sessions may still
     * use their connection: once per session.
     */
    private static final long ACCESS_CHECK_SECONDS = 15;

    /**
     * How far back, at least, to look for ended checkouts: well over the
     * time between two looks, so no checkout is missed.
     */
    private static final long ENDED_CHECKOUT_WINDOW_MS = TimeUnit.MINUTES.toMillis(2);

    /**
     * Minimum time between automatic retries of a failed periodic rotation,
     * so a broken target is not hammered (and its account locked out).
     */
    private static final long RETRY_DELAY_MS = TimeUnit.MINUTES.toMillis(15);

    /**
     * Where the pending password can be read, in messages.
     */
    private static final String PENDING_HINT = " (encrypted if \"pam-encryption-key\" is set: see \"Reading an"
            + " encrypted secret\" in the README)";

    private final PamDatabase database;

    private final PlatformRepository platforms;

    private final PasswordPolicyRepository passwordPolicies;

    private final ConnectionRepository connections;

    private final CheckoutRepository checkouts;

    private final PasswordGenerator passwordGenerator = new PasswordGenerator();

    private final Coordination coordination;

    private final SessionRegistry sessions;

    private final Events events;

    /**
     * Why this server was on standby when last checked, or null if it
     * worked, so going on standby and back is reported once.
     */
    private Standby lastStandby = Standby.STARTING;

    private final ScheduledExecutorService scheduler = newScheduler("pam-rotation", 2);

    /**
     * Expiry, ended checkouts and access checks, kept apart so long
     * rotations never delay the end of a session.
     */
    private final ScheduledExecutorService housekeeping = newScheduler("pam-housekeeping", 1);

    /**
     * The role of this server and its sessions' heartbeat, apart again, so
     * slow checks of checkouts or access never make other servers take its
     * sessions for ended (see Coordination#check).
     */
    private final ScheduledExecutorService coordinating = newScheduler("pam-coordination", 1);

    /**
     * When ended checkouts were last looked for successfully.
     */
    private volatile long lastEndedCheck = System.currentTimeMillis();

    public RotationService(PamDatabase database, Coordination coordination, PlatformRepository platforms,
            PasswordPolicyRepository passwordPolicies, ConnectionRepository connections, CheckoutRepository checkouts,
            Events events) {
        this.database = database;
        this.platforms = platforms;
        this.passwordPolicies = passwordPolicies;
        this.connections = connections;
        this.checkouts = checkouts;
        this.coordination = coordination;
        this.events = events;
        this.sessions = new SessionRegistry(database);
        scheduler.scheduleWithFixedDelay(this::rotateDueConnections,
                PERIODIC_CHECK_SECONDS, PERIODIC_CHECK_SECONDS, TimeUnit.SECONDS);
        // At once, so this server works, or is on standby, from its start
        coordinating.scheduleWithFixedDelay(this::checkCoordination, 0, ENDED_CHECK_SECONDS, TimeUnit.SECONDS);
        housekeeping.scheduleWithFixedDelay(this::endCheckouts, ENDED_CHECK_SECONDS, ENDED_CHECK_SECONDS,
                TimeUnit.SECONDS);
        housekeeping.scheduleWithFixedDelay(this::checkAccess,
                ACCESS_CHECK_SECONDS, ACCESS_CHECK_SECONDS, TimeUnit.SECONDS);
    }

    private static ScheduledExecutorService newScheduler(String name, int threads) {
        return Executors.newScheduledThreadPool(threads, runnable -> {
            Thread thread = new Thread(runnable, name);
            thread.setDaemon(true);
            return thread;
        });
    }

    /**
     * Records a session opened on this server. Its access is checked again
     * with every look for ended checkouts, and the session closed once it
     * is no longer allowed.
     */
    public void sessionStarted(String identifier, String name, String username, GuacamoleTunnel tunnel,
            SessionAccess access) {
        sessions.started(identifier, username, tunnel, access);
        events.publish(Event.of(EventType.SESSION_STARTED).user(username).connection(identifier, name));
    }

    /**
     * Forgets a session that ended, looking for its connection's after-use
     * rotation shortly. Its row is removed only then: if this server stops
     * meanwhile, the server working next finds it, and rotates the
     * connection instead.
     */
    public void sessionEnded(String identifier, String name, GuacamoleTunnel tunnel) {
        SessionRegistry.Session session = sessions.ended(tunnel);
        if (session == null)
            return;
        events.publish(Event.of(EventType.SESSION_ENDED).user(session.getUsername()).connection(identifier, name));
        try {
            // Its row removed first, so the rotation does not count it;
            // kept while on standby, for the server working to find
            scheduler.schedule(() -> {
                if (coordination.getStandby() == null)
                    sessions.removeRow(session);
                scheduleAfterUse(identifier, 0);
            }, AFTER_USE_DELAY_SECONDS, TimeUnit.SECONDS);
        }
        catch (RejectedExecutionException e) {
            logger.debug("After-use rotation of connection {} left to the next server: shutting down.", identifier);
        }
    }

    /**
     * Refuses a session of a connection being rotated: its password is
     * about to change. Checked once the session is recorded, as a rotation
     * looks for sessions once it claimed the connection, so at least one of
     * the two backs off, on any server.
     *
     * @throws GuacamoleSecurityException
     *     If the connection is being rotated: forbidden, which the web UI
     *     explains when refusing a session.
     */
    public void requireNotRotating(String identifier) throws GuacamoleException {
        Integer id = Values.parseId(identifier);
        if (id != null && isRotating(id))
            throw new GuacamoleSecurityException("The password of this connection is being rotated. Please try"
                    + " again in a moment.");
    }

    /**
     * When each connection's after-use rotation is due, in milliseconds:
     * its sessions and checkouts ending at once, or one after another,
     * make one look for it, once the last is due.
     */
    private final Map<String, Long> afterUseDue = new ConcurrentHashMap<>();

    /**
     * Connections whose look for an after-use rotation is scheduled.
     */
    private final Set<String> afterUseLooking = ConcurrentHashMap.newKeySet();

    /**
     * Looks for the connection's after-use rotation after
     * {@link #AFTER_USE_DELAY_SECONDS}, letting guacd finish disconnecting,
     * once however many sessions and checkouts end meanwhile.
     */
    private void scheduleAfterUse(String identifier) {
        scheduleAfterUse(identifier, TimeUnit.SECONDS.toMillis(AFTER_USE_DELAY_SECONDS));
    }

    private void scheduleAfterUse(String identifier, long delayMs) {
        afterUseDue.merge(identifier, System.currentTimeMillis() + delayMs, (a, b) -> Math.max(a, b));
        if (afterUseLooking.add(identifier))
            lookForAfterUse(identifier, delayMs);
    }

    /**
     * Looks for the connection's after-use rotation once it is due, put off
     * by later ends meanwhile.
     */
    private void lookForAfterUse(String identifier, long delayMs) {
        try {
            scheduler.schedule(() -> {
                long left = afterUseDue.getOrDefault(identifier, 0L) - System.currentTimeMillis();
                if (left > 0) {
                    lookForAfterUse(identifier, left);
                    return;
                }
                afterUseLooking.remove(identifier);
                afterUseDue.remove(identifier);
                rotateAfterUse(identifier);
            }, delayMs, TimeUnit.MILLISECONDS);
        }
        catch (RejectedExecutionException e) {
            // Shutting down: the server working next rotates it, finding
            // the session's row
            afterUseLooking.remove(identifier);
            afterUseDue.remove(identifier);
            logger.debug("After-use rotation of connection {} not scheduled: shutting down.", identifier);
        }
    }

    /**
     * Called when a checkout ends, by release, revocation or expiry. The
     * holder's open sessions on the connection end with it: a time-limited
     * access window does not outlive its limit. After-use rotation follows.
     */
    public void checkoutEnded(Checkout checkout) {
        closeSessions(checkout, false);
        scheduleAfterUse(checkout.getConnectionIdentifier());
    }

    /**
     * Closes this server's sessions of the holder of an ended checkout. When
     * it ended on another server, only sessions started before it ended:
     * later ones were opened with a new checkout, or without needing one.
     */
    private void closeSessions(Checkout checkout, boolean endedElsewhere) {
        for (SessionRegistry.Session session : sessions.getLocal(checkout.getConnectionIdentifier())) {

            if (!session.getUsername().equals(checkout.getUsername()))
                continue;
            if (endedElsewhere && session.getStarted() >= checkout.getReleased())
                continue;

            close(session, "\"" + Values.forLog(checkout.getConnectionName()) + "\"",
                    "its checkout ended" + (endedElsewhere ? " on another server" : ""));

        }
    }

    /**
     * Closes a session of this server, saying why.
     *
     * @param connection
     *     The connection, as logs name it: "web01" or "connection 17".
     */
    private static void close(SessionRegistry.Session session, String connection, String why) {
        try {
            logger.info("Closing the session of \"{}\" on {}: {}.", session.getUsername(), connection, why);
            session.getTunnel().close();
        }
        catch (Exception e) {
            logger.warn("Unable to close a session of \"{}\" on {}: {}", session.getUsername(), connection,
                    e.getMessage());
        }
    }

    /**
     * Whether a rotation of the given connection is running right now, on
     * any server.
     */
    public boolean isRotating(int id) throws GuacamoleException {
        return coordination.getClaimed(Collections.singleton(id)).contains(id);
    }

    /**
     * Refuses a change while this server is on standby (see
     * {@link Coordination}).
     */
    public void requireActive() throws GuacamoleClientException {
        coordination.requireActive();
    }

    public Coordination getCoordination() {
        return coordination;
    }

    private boolean isInUse(int id) throws GuacamoleException {
        return coordination.countSessions(sessions).getOrDefault(id, 0) > 0 || !checkouts.listActive(id).isEmpty();
    }

    private void rotateAfterUse(String identifier) {
        try {

            Integer id = Values.parseId(identifier);
            if (id == null || coordination.getStandby() != null || isInUse(id))
                return;

            Target target = connections.load(id);
            if (target == null || target.getAttribute(PamAttributes.PLATFORM) == null)
                return;

            if (isShown(id))
                rotateUnlessDone(target, "password shown", current -> !isInUse(current.getId())
                        && isShown(current.getId()));
            else if (Platform.MODE_AFTER_USE.equals(policyOf(target).getMode()))
                rotateUnlessDone(target, "after use", current -> !isInUse(current.getId()));

        }
        catch (SchemaUnavailableException e) {
            logger.debug("After-use rotation skipped: {}", e.getMessage());
        }
        catch (Exception e) {
            logger.error("After-use rotation of connection {} failed: {}", identifier, e.getMessage());
            logger.debug("After-use rotation failed.", e);
        }
    }

    private void endCheckouts() {
        if (coordination.getStandby() != null)
            return;
        expireCheckouts();
        if (coordination.isShared())
            closeSessionsOfEndedCheckouts();
    }

    /**
     * Brings this server's role up to date, rotating after use the
     * connections whose sessions ended on a server that stopped.
     */
    private void checkCoordination() {
        try {
            for (int id : coordination.check(sessions))
                scheduleAfterUse(Integer.toString(id));
            Standby standby = coordination.getStandby();
            reportStandby(standby);
            if (standby != null && standby.isOtherServerWorking() && sessions.hasLocal())
                closeManagedSessions();
        }
        catch (Exception e) {
            logger.error("Unable to check the other servers: {}", e.getMessage());
            logger.debug("Unable to check the other servers.", e);
        }
    }

    /**
     * Reports this server going on standby, and working again after one.
     * Not while it starts: it works, or is on standby, from then.
     */
    private void reportStandby(Standby standby) {
        if (standby == lastStandby || standby == Standby.STARTING)
            return;
        if (standby != null)
            events.publish(Event.of(EventType.SERVER_STANDBY).detail(standby.getMessage()));
        else if (lastStandby != Standby.STARTING)
            events.publish(Event.of(EventType.SERVER_ACTIVE).detailMessage("DETAIL_SERVER_ACTIVE"));
        lastStandby = standby;
    }

    /**
     * Closes this server's sessions of managed connections, opened before it
     * went on standby: the server working instead neither counts them nor
     * knows their connections in use, and could rotate their passwords.
     */
    private void closeManagedSessions() throws GuacamoleException {
        Set<Integer> managed = connections.listManagedIds();
        for (SessionRegistry.Session session : sessions.getAllLocal()) {
            Integer id = Values.parseId(session.getIdentifier());
            if (id == null || !managed.contains(id))
                continue;
            close(session, "connection " + session.getIdentifier(), "this server is on standby");
        }
    }

    /**
     * Closes the sessions whose user may no longer use their connection,
     * after those of checkouts ended: a session whose checkout just ended or
     * expired is closed for that, and logged so, not as access revoked.
     */
    private void checkAccess() {
        endCheckouts();
        closeSessionsNoLongerAllowed();
    }

    /**
     * Closes this server's sessions whose user lost access to their
     * connection since it opened: permission to read it revoked, or (for an
     * administrator who connected without a request) no longer an
     * administrator.
     */
    private void closeSessionsNoLongerAllowed() {
        for (SessionRegistry.Session session : sessions.getAllLocal()) {

            boolean allowed;
            try {
                allowed = session.getAccess().isAllowed();
            }
            catch (Exception e) {
                logger.warn("Unable to check the access of \"{}\" to connection {}, leaving their session open: {}",
                        session.getUsername(), session.getIdentifier(), e.getMessage());
                continue;
            }

            if (allowed)
                continue;

            close(session, "connection " + session.getIdentifier(), "their access was revoked");

        }
    }

    /**
     * Ends the checkouts past their time limit now, as the periodic check
     * does: before starting one, so an expired checkout not yet ended does
     * not stand in the way.
     */
    public void expireCheckouts() {
        if (coordination.getStandby() != null)
            return;
        try {
            for (Checkout checkout : checkouts.expireDue()) {
                logger.info("Checkout {} of connection \"{}\" by user \"{}\" expired.", checkout.getId(),
                        Values.forLog(checkout.getConnectionName()), checkout.getUsername());
                events.publish(Event.of(EventType.CHECKOUT_EXPIRED).user(checkout.getUsername())
                        .connection(checkout.getConnectionIdentifier(), checkout.getConnectionName())
                        .checkout(checkout.getId()).period(checkout.getCheckedOut(), checkout.getExpires()));
                checkoutEnded(checkout);
            }
        }
        catch (SchemaUnavailableException e) {
            logger.debug("Checkout expiry check skipped: {}", e.getMessage());
        }
        catch (Exception e) {
            logger.error("Checkout expiry check failed: {}", e.getMessage());
            logger.debug("Checkout expiry check failed.", e);
        }
    }

    /**
     * Closes this server's sessions of checkouts that ended on another
     * server. Looks back over every checkout ended since the last successful
     * look, with a margin: those ended here are found again, and only their
     * sessions that are already closed would match.
     */
    private void closeSessionsOfEndedCheckouts() {

        long now = System.currentTimeMillis();

        // Sessions opened from now on need a checkout active when they open
        if (!sessions.hasLocal()) {
            lastEndedCheck = now;
            return;
        }

        try {
            long window = Math.max(ENDED_CHECKOUT_WINDOW_MS, now - lastEndedCheck + ENDED_CHECKOUT_WINDOW_MS);
            for (Checkout checkout : checkouts.listEndedWithin((int) TimeUnit.MILLISECONDS.toSeconds(window)))
                closeSessions(checkout, true);
            lastEndedCheck = now;
        }
        catch (SchemaUnavailableException e) {
            logger.debug("Ended checkout check skipped: {}", e.getMessage());
        }
        catch (Exception e) {
            logger.error("Ended checkout check failed: {}", e.getMessage());
            logger.debug("Ended checkout check failed.", e);
        }

    }

    /**
     * Whether a checkout showed the connection's password since its last
     * rotation.
     */
    private boolean isShown(int id) throws GuacamoleException {
        return checkouts.isShownSinceRotation(id, AccountProtocol.NAME);
    }

    private void rotateDueConnections() {
        if (coordination.getStandby() != null)
            return;
        try {

            Map<String, Platform> all = platforms.getAll();
            Set<Integer> shown = checkouts.listShownSinceRotation(AccountProtocol.NAME);

            // Read once for every connection; a rotation checks again for
            // checkouts once it claims its connection
            Map<Integer, Integer> sessionCounts = coordination.countSessions(sessions);
            Set<Integer> held = new HashSet<>();
            for (Checkout checkout : checkouts.listActive())
                held.add(Values.parseId(checkout.getConnectionIdentifier()));

            for (Target target : connections.listManaged()) {

                // Missed or failed after its use, such as while the server
                // was down
                boolean wasShown = shown.contains(target.getId()) && isRetryAllowed(target);
                if (!wasShown && !isDue(target, all))
                    continue;

                // Rotating while in use would break the password a user is
                // relying on; wait until the session or checkout ends
                if (sessionCounts.containsKey(target.getId()) || held.contains(target.getId()))
                    continue;

                // One connection failing, such as with secrets no key here
                // reads, keeps none of the others from rotating
                try {
                    if (wasShown)
                        rotateUnlessDone(target, "password shown", current -> isShown(current.getId())
                                && isRetryAllowed(current));
                    else
                        rotateUnlessDone(target, "periodic", current -> isDue(current, all));
                }
                catch (SchemaUnavailableException e) {
                    throw e;
                }
                catch (Exception e) {
                    logger.error("Periodic rotation of connection \"{}\" ({}) failed: {}",
                            Values.forLog(target.getName()), target.getId(), e.getMessage());
                    logger.debug("Periodic rotation failed.", e);
                }

            }

        }
        catch (SchemaUnavailableException e) {
            logger.debug("Periodic rotation check skipped: {}", e.getMessage());
        }
        catch (Exception e) {
            logger.error("Periodic rotation check failed: {}", e.getMessage());
            logger.debug("Periodic rotation check failed.", e);
        }
    }

    /**
     * Whether a periodic rotation of the connection is due, and a failed one
     * may be retried.
     */
    private boolean isDue(Target target, Map<String, Platform> all) {

        EffectivePolicy policy = EffectivePolicy.of(all.get(target.getAttribute(PamAttributes.PLATFORM)), target);
        if (!Platform.MODE_PERIODIC.equals(policy.getMode()))
            return false;

        Integer hours = policy.getIntervalHours();
        if (hours == null || hours <= 0)
            return false;

        ConnectionRepository.State state = target.getState();
        long lastSuccess = state.getLastSuccess() == null ? 0 : state.getLastSuccess().getTime();
        return database.now() >= lastSuccess + TimeUnit.HOURS.toMillis(hours) && isRetryAllowed(target);

    }

    /**
     * Whether an automatic rotation may be tried now: the last attempt
     * succeeded, or failed long enough ago. Its times are the database's.
     */
    private boolean isRetryAllowed(Target target) {
        ConnectionRepository.State state = target.getState();
        long lastSuccess = state.getLastSuccess() == null ? 0 : state.getLastSuccess().getTime();
        long lastAttempt = state.getLastAttempt() == null ? 0 : state.getLastAttempt().getTime();
        return database.now() >= lastAttempt + RETRY_DELAY_MS || lastAttempt <= lastSuccess;
    }

    /**
     * Rotates the given connection now, on request of an administrator.
     * Refused while the password is checked out.
     */
    public RotationResult rotateNow(String identifier) throws GuacamoleException {

        Integer id = Values.parseId(identifier);
        if (id == null)
            throw new GuacamoleResourceNotFoundException("No such connection.");

        Target target = connections.load(id);
        if (target == null)
            throw new GuacamoleResourceNotFoundException("No such connection.");

        requireNotCheckedOut(id);
        return rotate(target, MANUAL, current -> true);

    }

    /**
     * Lists every connection with rotation configured.
     */
    public List<ManagedConnection> listManaged() throws GuacamoleException {

        Map<String, Platform> all = platforms.getAll();
        Map<Integer, Integer> counts = coordination.countSessions(sessions);
        List<Target> targets = connections.listManaged();

        List<Integer> ids = new ArrayList<>();
        for (Target target : targets)
            ids.add(target.getId());
        Set<Integer> rotating = coordination.getClaimed(ids);

        List<ManagedConnection> managed = new ArrayList<>();
        for (Target target : targets) {
            Platform platform = all.get(target.getAttribute(PamAttributes.PLATFORM));
            managed.add(new ManagedConnection(target, platform, EffectivePolicy.of(platform, target),
                    counts.getOrDefault(target.getId(), 0), rotating.contains(target.getId())));
        }

        return managed;

    }

    /**
     * Refuses to rotate a password while anyone holds it.
     */
    private void requireNotCheckedOut(int id) throws GuacamoleException {

        List<String> holders = new ArrayList<>();
        for (Checkout checkout : checkouts.listActive(id))
            holders.add("\"" + checkout.getUsername() + "\"");

        if (!holders.isEmpty())
            throw new GuacamoleClientException("The password is checked out by " + String.join(", ", holders)
                    + ". Revoke the checkout before rotating.");

    }

    /**
     * Whether a rotation is still wanted, given the connection as loaded
     * once claimed.
     */
    @FunctionalInterface
    private interface Wanted {
        boolean test(Target current) throws GuacamoleException;
    }

    /**
     * An automatic rotation: skipped if another server is running it, or
     * ran it meanwhile.
     */
    private void rotateUnlessDone(Target target, String reason, Wanted wanted) throws GuacamoleException {
        try {
            if (rotate(target, reason, wanted) == null)
                logger.debug("Rotation ({}) of connection {} skipped: no longer needed.", reason, target.getId());
        }
        catch (GuacamoleClientException e) {
            // Running elsewhere, or just checked out: not a failure
            logger.debug("Rotation ({}) of connection {} skipped: {}", reason, target.getId(), e.getMessage());
        }
    }

    /**
     * Claims the connection, then rotates it if still wanted, returning null
     * if not.
     *
     * @throws GuacamoleClientException
     *     If a rotation of the connection is running, here or on another
     *     server, it is checked out, or this server is on standby.
     */
    private RotationResult rotate(Target target, String reason, Wanted wanted) throws GuacamoleException {

        coordination.requireActive();
        try (Coordination.Claim claim = coordination.tryClaim(target.getId())) {

            if (claim == null)
                throw new GuacamoleClientException("A rotation of this connection is already running.");

            // Checked only after claiming the connection; see CheckoutService
            // and requireNotRotating. Automatic rotations wait for sessions
            // to end; administrators rotating by hand decide
            requireNotCheckedOut(target.getId());
            if (!MANUAL.equals(reason) && coordination.countSessions(sessions).getOrDefault(target.getId(), 0) > 0)
                return null;

            // Loaded again: another server may have rotated it since
            Target current = connections.load(target.getId());
            if (current == null)
                throw new GuacamoleResourceNotFoundException("No such connection.");
            if (!wanted.test(current))
                return null;

            RotationResult result = performRotation(current);
            logger.info("Rotation ({}) of connection \"{}\" ({}): {} {}", reason, Values.forLog(current.getName()),
                    current.getId(), result.getStatus(),
                    result.getMessage() == null ? "" : Values.forLog(result.getMessage()));
            boolean succeeded = RotationResult.SUCCESS.equals(result.getStatus());
            events.publish(Event.of(succeeded ? EventType.ROTATION_SUCCEEDED : EventType.ROTATION_FAILED)
                    .connection(Integer.toString(current.getId()), current.getName())
                    .detail("Rotation (" + reason + "): " + result.getStatus()
                            + (result.getMessage() == null ? "" : ": " + result.getMessage())));
            return result;

        }

    }

    /**
     * Builds the changer for a connection.
     *
     * @throws IllegalArgumentException
     *     If the connection is not configured well enough to rotate.
     */
    private PasswordChanger createChanger(Target target) throws GuacamoleException {

        // Never try a target with a password that is not its own
        if (target.getSecretError() != null)
            throw new IllegalArgumentException("The stored secrets cannot be read: " + target.getSecretError());

        String platformId = target.getAttribute(PamAttributes.PLATFORM);
        if (platformId == null)
            throw new IllegalArgumentException("This connection is stored only, not managed, so its password"
                    + " is never rotated. Choose a platform to manage it.");

        Platform platform = platforms.getWithSecrets(platformId);
        if (platform == null)
            throw new IllegalArgumentException("The platform of this connection no longer exists.");

        ManagementType type = ManagementTypes.get(platform.getType());
        if (type == null)
            throw new IllegalArgumentException("Platform \"" + platform.getName() + "\" has an unknown type \""
                    + platform.getType() + "\".");

        return type.createChanger(platform, target);

    }

    /**
     * The policy applying to a connection, given its platform.
     */
    private EffectivePolicy policyOf(Target target) throws GuacamoleException {
        return EffectivePolicy.of(platforms.get(target.getAttribute(PamAttributes.PLATFORM)), target);
    }

    private RotationResult performRotation(Target target) throws GuacamoleException {

        int id = target.getId();

        // Configuration problems are reported before anything is attempted
        PasswordChanger changer;
        try {
            changer = createChanger(target);
        }
        catch (IllegalArgumentException e) {
            return configurationError(id, e.getMessage());
        }

        // An earlier rotation could not be confirmed: find out which password
        // the target uses before its pending password gets overwritten
        String recovered = null;
        String pending = connections.getPendingPassword(id);
        if (pending != null) {
            try {
                if (changer.accepts(pending)) {
                    recovered = "Recovered the password set by an earlier unconfirmed rotation.";
                    connections.recordSuccess(id, pending, recovered, null);
                    changer = changer.withCurrentPassword(pending);
                }
                else if (!changer.accepts(changer.getCurrentPassword()))
                    return configurationError(id, "An earlier rotation could not be confirmed, and the target"
                            + " accepts neither the stored nor the pending password. Resolve this manually"
                            + " using pam_rotation_state.pending_password" + PENDING_HINT + ".");
            }
            catch (Exception e) {
                return configurationError(id, "Could not reach the target to resolve an earlier unconfirmed"
                        + " rotation: " + e.getMessage());
            }
        }

        PasswordRules rules;
        try {
            rules = passwordPolicies.rulesOf(policyOf(target).getPasswordPolicy());
        }
        catch (GuacamoleClientException e) {
            return configurationError(id, e.getMessage());
        }

        String newPassword = passwordGenerator.generate(rules);
        String oldPassword = changer.getCurrentPassword();

        // Store the new password before touching the target, so it can be
        // recovered even if Guacamole stops mid-rotation
        connections.recordStart(id, newPassword);

        ChangeOutcome outcome;
        try {
            outcome = changer.change(newPassword);
        }
        catch (RuntimeException e) {
            // Whether it reached the target is unknown: kept as pending
            String message = "The change failed unexpectedly (" + e.getMessage() + "). The new password was kept"
                    + " in pam_rotation_state.pending_password" + PENDING_HINT + ", in case the target took it.";
            logger.debug("The change failed unexpectedly.", e);
            connections.recordFailure(id, RotationResult.UNKNOWN, message, null, true);
            return new RotationResult(RotationResult.UNKNOWN, message);
        }
        String detail = outcome.isCompleted() ? null : outcome.getError();
        if (recovered != null)
            detail = detail == null ? recovered : recovered + " " + detail;

        if (!outcome.isNewPasswordSent())
            return fail(id, RotationResult.FAILED, "Password unchanged. " + detail, outcome, false);

        // The target, not the change itself, decides whether it happened
        try {

            if (changer.accepts(newPassword)) {
                String message = outcome.isCompleted() ? recovered
                        : "The change reported a problem, but the target accepts the new password. " + detail;
                connections.recordSuccess(id, newPassword, message, outcome.getHostKey());
                return new RotationResult(RotationResult.SUCCESS, message);
            }

            if (changer.accepts(oldPassword))
                return fail(id, RotationResult.FAILED, "Password unchanged: the target still accepts the old password. "
                        + (detail == null ? "Check the profile against the transcript." : detail), outcome, false);

            return fail(id, RotationResult.UNKNOWN, "The target accepts neither the old nor the new password."
                    + " The new password was kept in pam_rotation_state.pending_password" + PENDING_HINT + ". "
                    + (detail == null ? "" : detail), outcome, true);

        }
        catch (Exception e) {
            return fail(id, RotationResult.UNKNOWN, "Could not verify the new password (" + e.getMessage()
                    + "). It was kept in pam_rotation_state.pending_password" + PENDING_HINT + ". "
                    + (detail == null ? "" : detail), outcome, true);
        }

    }

    /**
     * Records a failure that happened before anything was sent to the
     * target, leaving any pending password untouched.
     */
    private RotationResult configurationError(int id, String message) throws GuacamoleException {
        connections.recordFailure(id, RotationResult.FAILED, message, null, true);
        return new RotationResult(RotationResult.FAILED, message);
    }

    private RotationResult fail(int id, String status, String message, ChangeOutcome outcome,
            boolean keepPendingPassword) throws GuacamoleException {

        String full = message.trim();
        if (outcome.getTranscript() != null && !outcome.getTranscript().isEmpty())
            full += "\n\nTranscript:\n" + outcome.getTranscript();

        connections.recordFailure(id, status, full, outcome.getHostKey(), keepPendingPassword);
        return new RotationResult(status, full);

    }

    public void shutdown() {
        coordinating.shutdownNow();
        housekeeping.shutdownNow();
        scheduler.shutdownNow();
        coordination.shutdown();
    }

}
