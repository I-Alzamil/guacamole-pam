package org.apache.guacamole.pam.rotation;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

import org.apache.guacamole.GuacamoleClientException;
import org.apache.guacamole.GuacamoleException;
import org.apache.guacamole.GuacamoleResourceNotFoundException;
import org.apache.guacamole.net.GuacamoleTunnel;
import org.apache.guacamole.pam.PamAttributes;
import org.apache.guacamole.pam.checkout.Checkout;
import org.apache.guacamole.pam.checkout.CheckoutRepository;
import org.apache.guacamole.pam.db.ConnectionRepository;
import org.apache.guacamole.pam.db.ConnectionRepository.Target;
import org.apache.guacamole.pam.management.ManagementType;
import org.apache.guacamole.pam.management.ManagementTypes;
import org.apache.guacamole.pam.management.PasswordChanger;
import org.apache.guacamole.pam.platform.Platform;
import org.apache.guacamole.pam.platform.PlatformRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Decides when connections are rotated, and performs rotations.
 *
 * A rotation sets a new password on the target (over SSH with a sequence
 * profile, or over LDAP for managed "pam-account" connections), then checks which
 * password the target accepts. The new password is only stored in Guacamole
 * once the target accepts it.
 *
 * A connection is "in use" while it has open sessions or an active checkout;
 * automatic rotations wait until it is no longer in use.
 */
public class RotationService {

    private static final Logger logger = LoggerFactory.getLogger(RotationService.class);

    /**
     * Delay between the last session closing and an after-use rotation,
     * letting guacd finish disconnecting.
     */
    private static final long AFTER_USE_DELAY_SECONDS = 5;

    private static final long PERIODIC_CHECK_SECONDS = 60;

    private static final long EXPIRY_CHECK_SECONDS = 15;

    /**
     * Minimum time between automatic retries of a failed periodic rotation,
     * so a broken target is not hammered (and its account locked out).
     */
    private static final long RETRY_DELAY_MS = TimeUnit.MINUTES.toMillis(15);

    private final PlatformRepository platforms;

    private final ConnectionRepository connections;

    private final CheckoutRepository checkouts;

    private final PasswordGenerator passwordGenerator = new PasswordGenerator();

    private final ScheduledExecutorService scheduler = Executors.newScheduledThreadPool(2, runnable -> {
        Thread thread = new Thread(runnable, "pam-rotation");
        thread.setDaemon(true);
        return thread;
    });

    /**
     * Open tunnels per connection identifier, with the user of each.
     */
    private final ConcurrentMap<String, Map<GuacamoleTunnel, String>> activeSessions = new ConcurrentHashMap<>();

    /**
     * Connections currently being rotated.
     */
    private final Set<Integer> inProgress = ConcurrentHashMap.newKeySet();

    public RotationService(PlatformRepository platforms, ConnectionRepository connections,
            CheckoutRepository checkouts) {
        this.platforms = platforms;
        this.connections = connections;
        this.checkouts = checkouts;
        scheduler.scheduleWithFixedDelay(this::rotateDueConnections,
                PERIODIC_CHECK_SECONDS, PERIODIC_CHECK_SECONDS, TimeUnit.SECONDS);
        scheduler.scheduleWithFixedDelay(this::expireCheckouts,
                EXPIRY_CHECK_SECONDS, EXPIRY_CHECK_SECONDS, TimeUnit.SECONDS);
    }

    public void sessionStarted(String identifier, String username, GuacamoleTunnel tunnel) {
        activeSessions.computeIfAbsent(identifier, id -> new ConcurrentHashMap<>()).put(tunnel, username);
    }

    public void sessionEnded(String identifier, GuacamoleTunnel tunnel) {

        Map<GuacamoleTunnel, String> sessions = activeSessions.get(identifier);
        if (sessions == null)
            return;

        sessions.remove(tunnel);
        if (!sessions.isEmpty())
            return;

        activeSessions.remove(identifier, sessions);
        scheduler.schedule(() -> rotateAfterUse(identifier), AFTER_USE_DELAY_SECONDS, TimeUnit.SECONDS);

    }

    /**
     * Called when a checkout ends, by release, revocation or expiry. The
     * holder's open sessions on the connection end with it: a time-limited
     * access window does not outlive its limit. After-use rotation follows.
     */
    public void checkoutEnded(Checkout checkout) {

        String identifier = checkout.getConnectionIdentifier();
        Map<GuacamoleTunnel, String> sessions = activeSessions.get(identifier);

        if (sessions != null) {
            for (Map.Entry<GuacamoleTunnel, String> session : sessions.entrySet()) {
                if (!session.getValue().equals(checkout.getUsername()))
                    continue;
                try {
                    logger.info("Closing the session of \"{}\" on \"{}\": its checkout ended.",
                            checkout.getUsername(), checkout.getConnectionName());
                    session.getKey().close();
                }
                catch (Exception e) {
                    logger.warn("Unable to close a session of \"{}\" on \"{}\": {}", checkout.getUsername(),
                            checkout.getConnectionName(), e.getMessage());
                }
            }
        }

        scheduler.execute(() -> rotateAfterUse(identifier));

    }

    /**
     * Whether a rotation of the given connection is running right now.
     */
    public boolean isRotating(int id) {
        return inProgress.contains(id);
    }

    private int getActiveSessions(String identifier) {
        Map<GuacamoleTunnel, String> sessions = activeSessions.get(identifier);
        return sessions == null ? 0 : sessions.size();
    }

    private boolean isInUse(int id) throws GuacamoleException {
        return getActiveSessions(Integer.toString(id)) > 0 || !checkouts.listActive(id).isEmpty();
    }

    private void rotateAfterUse(String identifier) {
        try {

            Integer id = parseInt(identifier);
            if (id == null || isInUse(id))
                return;

            Target target = connections.load(id);
            if (target != null && Platform.MODE_AFTER_USE.equals(policyOf(target).getMode()))
                rotate(target, "after use");

        }
        catch (Exception e) {
            logger.error("After-use rotation of connection {} failed: {}", identifier, e.getMessage());
            logger.debug("After-use rotation failed.", e);
        }
    }

    private void expireCheckouts() {
        try {
            for (Checkout checkout : checkouts.expireDue()) {
                logger.info("Checkout {} of connection \"{}\" by user \"{}\" expired.", checkout.getId(),
                        checkout.getConnectionName(), checkout.getUsername());
                checkoutEnded(checkout);
            }
        }
        catch (Exception e) {
            logger.error("Checkout expiry check failed: {}", e.getMessage());
            logger.debug("Checkout expiry check failed.", e);
        }
    }

    private void rotateDueConnections() {
        try {

            long now = System.currentTimeMillis();
            Map<String, Platform> all = platforms.getAll();
            for (Target target : connections.listManaged()) {

                EffectivePolicy policy = EffectivePolicy.of(all.get(target.getAttribute(PamAttributes.PLATFORM)), target);
                if (!Platform.MODE_PERIODIC.equals(policy.getMode()))
                    continue;

                Integer hours = policy.getIntervalHours();
                if (hours == null || hours <= 0)
                    continue;

                ConnectionRepository.State state = target.getState();
                long lastSuccess = state.getLastSuccess() == null ? 0 : state.getLastSuccess().getTime();
                long lastAttempt = state.getLastAttempt() == null ? 0 : state.getLastAttempt().getTime();

                boolean due = now >= lastSuccess + TimeUnit.HOURS.toMillis(hours);
                boolean retryAllowed = now >= lastAttempt + RETRY_DELAY_MS || lastAttempt <= lastSuccess;

                // Rotating while in use would break the password a user is
                // relying on; wait until the session or checkout ends
                if (due && retryAllowed && !isInUse(target.getId()))
                    rotate(connections.load(target.getId()), "periodic");

            }

        }
        catch (Exception e) {
            logger.error("Periodic rotation check failed: {}", e.getMessage());
            logger.debug("Periodic rotation check failed.", e);
        }
    }

    /**
     * Rotates the given connection now, on request of an administrator.
     * Refused while the password is checked out.
     */
    public RotationResult rotateNow(String identifier) throws GuacamoleException {

        Integer id = parseInt(identifier);
        Target target = id == null ? null : connections.load(id);
        if (target == null)
            throw new GuacamoleResourceNotFoundException("No such connection.");

        requireNotCheckedOut(id);
        return rotate(target, "manual");

    }

    /**
     * Lists every connection with rotation configured.
     */
    public List<ManagedConnection> listManaged() throws GuacamoleException {

        Map<String, Platform> all = platforms.getAll();

        List<ManagedConnection> managed = new ArrayList<>();
        for (Target target : connections.listManaged()) {
            Platform platform = all.get(target.getAttribute(PamAttributes.PLATFORM));
            managed.add(new ManagedConnection(target, platform, EffectivePolicy.of(platform, target),
                    getActiveSessions(Integer.toString(target.getId())), inProgress.contains(target.getId())));
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

    private RotationResult rotate(Target target, String reason) throws GuacamoleException {

        if (!inProgress.add(target.getId()))
            throw new GuacamoleClientException("A rotation of this connection is already running.");

        try {

            // Checked only after claiming the connection; see CheckoutService
            requireNotCheckedOut(target.getId());

            RotationResult result = performRotation(target);
            logger.info("Rotation ({}) of connection \"{}\" ({}): {} {}", reason, target.getName(),
                    target.getId(), result.getStatus(), result.getMessage() == null ? "" : result.getMessage());
            return result;
        }
        finally {
            inProgress.remove(target.getId());
        }

    }

    /**
     * Builds the changer for a connection.
     *
     * @throws IllegalArgumentException
     *     If the connection is not configured well enough to rotate.
     */
    private PasswordChanger createChanger(Target target) throws GuacamoleException {

        String platformId = target.getAttribute(PamAttributes.PLATFORM);
        if (platformId == null)
            throw new IllegalArgumentException("This connection is stored only, not managed, so its password"
                    + " is never rotated. Choose a platform to manage it.");

        Platform platform = platforms.get(platformId);
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
                            + " using pam_rotation_state.pending_password.");
            }
            catch (Exception e) {
                return configurationError(id, "Could not reach the target to resolve an earlier unconfirmed"
                        + " rotation: " + e.getMessage());
            }
        }

        String newPassword = passwordGenerator.generate(policyOf(target).getPasswordLength());
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
                    + " The new password was kept in pam_rotation_state.pending_password. "
                    + (detail == null ? "" : detail), outcome, true);

        }
        catch (Exception e) {
            return fail(id, RotationResult.UNKNOWN, "Could not verify the new password (" + e.getMessage()
                    + "). It was kept in pam_rotation_state.pending_password. "
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

    static Integer parseInt(String value) {
        if (value == null)
            return null;
        try {
            return Integer.valueOf(value.trim());
        }
        catch (NumberFormatException e) {
            return null;
        }
    }

    public void shutdown() {
        scheduler.shutdownNow();
    }

}
