package io.github.ialzamil.guacamole.pam.rotation;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.Executors;
import java.util.concurrent.RejectedExecutionException;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

import org.apache.guacamole.GuacamoleClientException;
import org.apache.guacamole.GuacamoleException;
import org.apache.guacamole.GuacamoleResourceNotFoundException;
import org.apache.guacamole.net.GuacamoleTunnel;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import io.github.ialzamil.guacamole.pam.AccountProtocol;
import io.github.ialzamil.guacamole.pam.PamAttributes;
import io.github.ialzamil.guacamole.pam.Values;
import io.github.ialzamil.guacamole.pam.checkout.Checkout;
import io.github.ialzamil.guacamole.pam.checkout.CheckoutRepository;
import io.github.ialzamil.guacamole.pam.db.ConnectionRepository.Target;
import io.github.ialzamil.guacamole.pam.db.ConnectionRepository;
import io.github.ialzamil.guacamole.pam.db.PamDatabase;
import io.github.ialzamil.guacamole.pam.db.SchemaUnavailableException;
import io.github.ialzamil.guacamole.pam.management.ManagementType;
import io.github.ialzamil.guacamole.pam.management.ManagementTypes;
import io.github.ialzamil.guacamole.pam.management.PasswordChanger;
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
 * Several Guacamole servers may share the database: rotations are claimed
 * through the database ({@link RotationLocks}), so only one server rotates a
 * connection at a time, and sessions are recorded there
 * ({@link SessionRegistry}), so every server knows whether a connection is in
 * use. When a checkout ends, the server ending it closes its own sessions of
 * the holder at once; the other servers close theirs when they next look for
 * ended checkouts. Each server then also closes its sessions whose user lost
 * access to their connection meanwhile (see {@link SessionAccess}).
 */
public final class RotationService {

    private static final Logger logger = LoggerFactory.getLogger(RotationService.class);

    /**
     * Delay between the last session closing and an after-use rotation,
     * letting guacd finish disconnecting.
     */
    private static final long AFTER_USE_DELAY_SECONDS = 5;

    private static final long PERIODIC_CHECK_SECONDS = 60;

    private static final long EXPIRY_CHECK_SECONDS = 15;

    private static final long HEARTBEAT_SECONDS = 60;

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

    private final PlatformRepository platforms;

    private final PasswordPolicyRepository passwordPolicies;

    private final ConnectionRepository connections;

    private final CheckoutRepository checkouts;

    private final PasswordGenerator passwordGenerator = new PasswordGenerator();

    private final RotationLocks locks;

    private final SessionRegistry sessions;

    private final ScheduledExecutorService scheduler = newScheduler("pam-rotation", 2);

    /**
     * Expiry, ended checkouts and heartbeats, kept apart so long rotations
     * never delay the end of a session.
     */
    private final ScheduledExecutorService housekeeping = newScheduler("pam-housekeeping", 1);

    /**
     * When ended checkouts were last looked for successfully.
     */
    private volatile long lastEndedCheck = System.currentTimeMillis();

    public RotationService(PamDatabase database, PlatformRepository platforms,
            PasswordPolicyRepository passwordPolicies, ConnectionRepository connections, CheckoutRepository checkouts) {
        this.platforms = platforms;
        this.passwordPolicies = passwordPolicies;
        this.connections = connections;
        this.checkouts = checkouts;
        this.locks = new RotationLocks(database);
        this.sessions = new SessionRegistry(database);
        scheduler.scheduleWithFixedDelay(this::rotateDueConnections,
                PERIODIC_CHECK_SECONDS, PERIODIC_CHECK_SECONDS, TimeUnit.SECONDS);
        housekeeping.scheduleWithFixedDelay(this::endCheckouts,
                EXPIRY_CHECK_SECONDS, EXPIRY_CHECK_SECONDS, TimeUnit.SECONDS);
        housekeeping.scheduleWithFixedDelay(this::heartbeat,
                HEARTBEAT_SECONDS, HEARTBEAT_SECONDS, TimeUnit.SECONDS);
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
    public void sessionStarted(String identifier, String username, GuacamoleTunnel tunnel, SessionAccess access) {
        sessions.started(identifier, username, tunnel, access);
    }

    public void sessionEnded(String identifier, GuacamoleTunnel tunnel) {
        if (!sessions.ended(tunnel))
            scheduleAfterUse(identifier);
    }

    private void scheduleAfterUse(String identifier) {
        try {
            scheduler.schedule(() -> rotateAfterUse(identifier), AFTER_USE_DELAY_SECONDS, TimeUnit.SECONDS);
        }
        catch (RejectedExecutionException e) {
            // Shutting down: another server, or this one once restarted,
            // rotates it when the session's row goes stale
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
        scheduler.execute(() -> rotateAfterUse(checkout.getConnectionIdentifier()));
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

            try {
                logger.info("Closing the session of \"{}\" on \"{}\": its checkout ended{}.",
                        checkout.getUsername(), Values.forLog(checkout.getConnectionName()),
                        endedElsewhere ? " on another server" : "");
                session.getTunnel().close();
            }
            catch (Exception e) {
                logger.warn("Unable to close a session of \"{}\" on \"{}\": {}", checkout.getUsername(),
                        Values.forLog(checkout.getConnectionName()), e.getMessage());
            }

        }
    }

    /**
     * Whether a rotation of the given connection is running right now, on
     * any server.
     */
    public boolean isRotating(int id) throws GuacamoleException {
        return locks.isClaimed(id);
    }

    private boolean isInUse(int id) throws GuacamoleException {
        return sessions.count(id) > 0 || !checkouts.listActive(id).isEmpty();
    }

    private void rotateAfterUse(String identifier) {
        try {

            Integer id = Values.parseId(identifier);
            if (id == null || isInUse(id))
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
        expireCheckouts();
        closeSessionsOfEndedCheckouts();
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

            try {
                logger.info("Closing the session of \"{}\" on connection {}: their access was revoked.",
                        session.getUsername(), session.getIdentifier());
                session.getTunnel().close();
            }
            catch (Exception e) {
                logger.warn("Unable to close a session of \"{}\" on connection {}: {}", session.getUsername(),
                        session.getIdentifier(), e.getMessage());
            }

        }
    }

    /**
     * Ends the checkouts past their time limit now, as the periodic check
     * does: before starting one, so an expired checkout not yet ended does
     * not stand in the way.
     */
    public void expireCheckouts() {
        try {
            for (Checkout checkout : checkouts.expireDue()) {
                logger.info("Checkout {} of connection \"{}\" by user \"{}\" expired.", checkout.getId(),
                        Values.forLog(checkout.getConnectionName()), checkout.getUsername());
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

    private void heartbeat() {
        try {
            for (int id : sessions.heartbeat())
                scheduleAfterUse(Integer.toString(id));
        }
        catch (SchemaUnavailableException e) {
            logger.debug("Session heartbeat skipped: {}", e.getMessage());
        }
        catch (Exception e) {
            logger.error("Session heartbeat failed: {}", e.getMessage());
            logger.debug("Session heartbeat failed.", e);
        }
    }

    /**
     * Whether a checkout showed the connection's password since its last
     * rotation.
     */
    private boolean isShown(int id) throws GuacamoleException {
        return checkouts.listShownSinceRotation(AccountProtocol.NAME).contains(id);
    }

    private void rotateDueConnections() {
        try {

            Map<String, Platform> all = platforms.getAll();
            Set<Integer> shown = checkouts.listShownSinceRotation(AccountProtocol.NAME);

            // Read once for every connection; a rotation checks again for
            // checkouts once it claims its connection
            Map<Integer, Integer> sessionCounts = sessions.countAll();
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

                if (wasShown)
                    rotateUnlessDone(target, "password shown", current -> isShown(current.getId())
                            && isRetryAllowed(current));
                else
                    rotateUnlessDone(target, "periodic", current -> isDue(current, platforms.getAll()));

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
    private static boolean isDue(Target target, Map<String, Platform> all) {

        EffectivePolicy policy = EffectivePolicy.of(all.get(target.getAttribute(PamAttributes.PLATFORM)), target);
        if (!Platform.MODE_PERIODIC.equals(policy.getMode()))
            return false;

        Integer hours = policy.getIntervalHours();
        if (hours == null || hours <= 0)
            return false;

        ConnectionRepository.State state = target.getState();
        long lastSuccess = state.getLastSuccess() == null ? 0 : state.getLastSuccess().getTime();
        return System.currentTimeMillis() >= lastSuccess + TimeUnit.HOURS.toMillis(hours) && isRetryAllowed(target);

    }

    /**
     * Whether an automatic rotation may be tried now: the last attempt
     * succeeded, or failed long enough ago.
     */
    private static boolean isRetryAllowed(Target target) {
        ConnectionRepository.State state = target.getState();
        long lastSuccess = state.getLastSuccess() == null ? 0 : state.getLastSuccess().getTime();
        long lastAttempt = state.getLastAttempt() == null ? 0 : state.getLastAttempt().getTime();
        return System.currentTimeMillis() >= lastAttempt + RETRY_DELAY_MS || lastAttempt <= lastSuccess;
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
        return rotate(target, "manual", current -> true);

    }

    /**
     * Lists every connection with rotation configured.
     */
    public List<ManagedConnection> listManaged() throws GuacamoleException {

        Map<String, Platform> all = platforms.getAll();
        Map<Integer, Integer> counts = sessions.countAll();
        List<Target> targets = connections.listManaged();

        List<Integer> ids = new ArrayList<>();
        for (Target target : targets)
            ids.add(target.getId());
        Set<Integer> rotating = locks.getClaimed(ids);

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
     *     server, or it is checked out.
     */
    private RotationResult rotate(Target target, String reason, Wanted wanted) throws GuacamoleException {

        try (RotationLocks.Claim claim = locks.tryClaim(target.getId())) {

            if (claim == null)
                throw new GuacamoleClientException("A rotation of this connection is already running.");

            // Checked only after claiming the connection; see CheckoutService
            requireNotCheckedOut(target.getId());

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

        ChangeOutcome outcome = changer.change(newPassword);
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
        housekeeping.shutdownNow();
        scheduler.shutdownNow();
    }

}
