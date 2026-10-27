package io.github.ialzamil.guacamole.pam.checkout;

import java.util.Collections;
import java.util.List;
import java.util.Map;

import org.apache.guacamole.GuacamoleClientException;
import org.apache.guacamole.GuacamoleException;
import org.apache.guacamole.GuacamoleResourceNotFoundException;
import org.apache.guacamole.GuacamoleSecurityException;
import org.apache.guacamole.net.auth.UserContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import io.github.ialzamil.guacamole.pam.AccountProtocol;
import io.github.ialzamil.guacamole.pam.Values;
import io.github.ialzamil.guacamole.pam.approval.ApprovalRepository;
import io.github.ialzamil.guacamole.pam.approval.ApprovalRequest;
import io.github.ialzamil.guacamole.pam.coordination.Standby;
import io.github.ialzamil.guacamole.pam.db.ConnectionRepository.Target;
import io.github.ialzamil.guacamole.pam.db.ConnectionRepository;
import io.github.ialzamil.guacamole.pam.notification.Event;
import io.github.ialzamil.guacamole.pam.notification.EventType;
import io.github.ialzamil.guacamole.pam.notification.Events;
import io.github.ialzamil.guacamole.pam.platform.PlatformRepository;
import io.github.ialzamil.guacamole.pam.rotation.RotationService;
import io.github.ialzamil.guacamole.pam.settings.PamSettings;

/**
 * Checkouts: their start and end, and what holding one allows. Account
 * connections are checked out to see their password; any other connection
 * can require a checkout before connecting (an access window, which reveals
 * no password unless the connection allows its holder to see it). Every
 * checkout has a time limit. Exclusive checkouts allow a single holder,
 * which managed connections use by default, as ending a checkout may rotate
 * the password. Checkouts start from requests (see {@link RequestService}).
 */
public class CheckoutService {

    private static final Logger logger = LoggerFactory.getLogger(CheckoutService.class);

    private final ConnectionRepository connections;

    private final CheckoutRepository checkouts;

    private final ApprovalRepository approvals;

    private final RotationService rotationService;

    private final CheckoutRules rules;

    private final Events events;

    public CheckoutService(ConnectionRepository connections, CheckoutRepository checkouts,
            PlatformRepository platforms, ApprovalRepository approvals, RotationService rotationService,
            PamSettings settings, Events events) {
        this.events = events;
        this.connections = connections;
        this.checkouts = checkouts;
        this.approvals = approvals;
        this.rotationService = rotationService;
        this.rules = new CheckoutRules(platforms, settings);
    }

    /**
     * What each connection allows of requests and checkouts.
     */
    public CheckoutRules getRules() {
        return rules;
    }

    private static final String USERNAME_PARAMETER = "username";

    /**
     * Shows the password of a connection other than an Account to the
     * holder of its checkout, if the connection allows it. Each display is
     * recorded; a managed password is then rotated once the connection is
     * no longer in use (see {@link RotationService}).
     *
     * @throws GuacamoleClientException
     *     If the user holds no checkout of the connection, or it has no
     *     password of its own to show.
     */
    public PasswordGrant revealPassword(UserContext context, String username, String identifier)
            throws GuacamoleException {

        rotationService.requireActive();
        Target target = requireRequestable(context, identifier);
        if (!CheckoutRules.revealsPassword(target))
            throw new GuacamoleSecurityException("The password of this connection is not shown.");

        Checkout checkout = checkouts.getActive(target.getId(), username);
        if (checkout == null)
            throw new GuacamoleClientException("You do not hold this connection.");

        // A Guacamole token, such as ${GUAC_PASSWORD}, is the user's own
        String password = target.getPassword();
        if (password == null || password.isEmpty() || Values.hasGuacamoleToken(password))
            throw new GuacamoleClientException("This connection has no stored password to show.");

        if (!checkouts.recordReveal(checkout.getId()))
            throw new GuacamoleClientException("Your access has ended.");
        logger.info("User \"{}\" viewed the password of \"{}\" (checkout {}).",
                username, Values.forLog(target.getName()), checkout.getId());
        passwordRevealed(checkout, target);

        String user = Values.trimToNull(target.getParameters().get(USERNAME_PARAMETER));
        return new PasswordGrant(checkout, user == null || Values.hasGuacamoleToken(user) ? null : user, null, password);

    }

    /**
     * Reports the holder of a checkout seeing its password.
     */
    void passwordRevealed(Checkout checkout, Target target) {
        events.publish(Event.of(EventType.PASSWORD_REVEALED).user(checkout.getUsername())
                .connection(Integer.toString(target.getId()), target.getName()).checkout(checkout.getId()));
    }

    /**
     * Refuses a session on a connection requiring a request unless the user
     * holds an active checkout of it, or is an administrator while
     * administrators bypass requests (which is logged). The same applies to
     * Accounts, through {@link RequestService#request}.
     *
     * @throws GuacamoleSecurityException
     *     If the user must request access first, or the connection is
     *     managed or needs a request while this server is on standby:
     *     forbidden, which the web UI explains when refusing a session.
     */
    public void requireAccess(String identifier, String username, boolean administrator)
            throws GuacamoleException {

        Integer id = Values.parseId(identifier);
        if (id == null)
            return;

        Target target = connections.load(id);
        if (target == null)
            return;

        // Its sessions are counted by the server working, and rotated after
        Standby standby = rotationService.getCoordination().getStandby();
        if (standby != null && (CheckoutRules.isManaged(target) || CheckoutRules.requiresRequest(target)))
            throw new GuacamoleSecurityException(standby.getMessage());
        if (!CheckoutRules.requiresRequest(target))
            return;

        if (checkouts.getActive(id, username) != null)
            return;

        if (rules.bypassesRequests(administrator)) {
            logger.info("Administrator \"{}\" connects to \"{}\" without a request.", username,
                    Values.forLog(target.getName()));
            return;
        }

        throw new GuacamoleSecurityException("You must request access to this connection, and have it approved"
                    + " if needed, before connecting.");

    }

    /**
     * Whether a session opened on a connection may stay open: as
     * {@link #requireAccess} decides, but on standby too (sessions of
     * managed connections are closed apart, once another server works),
     * and without logging an administrator bypassing requests again.
     */
    public boolean mayKeepSession(String identifier, String username, boolean administrator)
            throws GuacamoleException {

        Integer id = Values.parseId(identifier);
        if (id == null)
            return true;

        Target target = connections.load(id);
        if (target == null || !CheckoutRules.requiresRequest(target))
            return true;

        return checkouts.getActive(id, username) != null || rules.bypassesRequests(administrator);

    }

    /**
     * Whether any connection within the connection group, at any depth,
     * requires approvals.
     */
    public boolean anyNeedsApprovalWithin(String groupIdentifier) throws GuacamoleException {
        Integer id = Values.parseId(groupIdentifier);
        return id != null && connections.anyNeedsApprovalWithin(id);
    }

    /**
     * The identifiers of the connections a balancing group may open: all
     * within it, whatever the user may read, as Guacamole balances over
     * them all.
     */
    public List<String> listBalanced(String groupIdentifier) throws GuacamoleException {
        Integer id = Values.parseId(groupIdentifier);
        return id == null ? Collections.<String>emptyList() : connections.listWithin(id);
    }

    /**
     * Refuses connecting through a balancing connection group if any of its
     * connections is an Account, requires a request, or is managed: the
     * connection Guacamole picks would be opened without its checks, and its
     * session would not be tracked for rotation.
     *
     * @throws GuacamoleSecurityException
     *     If the group contains such a connection.
     */
    public void requireBalanceable(String groupName, Iterable<String> connectionIdentifiers)
            throws GuacamoleException {

        for (String identifier : connectionIdentifiers) {
            Integer id = Values.parseId(identifier);
            Target target = id == null ? null : connections.load(id);
            if (target != null && (CheckoutRules.isRequestable(target) || CheckoutRules.isManaged(target)))
                throw new GuacamoleSecurityException("Connection group \"" + groupName + "\" balances over \""
                        + target.getName() + "\", which requires a request or has its password managed."
                        + " Open that connection directly instead.");
        }

    }

    /**
     * What deleting a connection ends: its active checkouts, and the
     * requests awaiting approval for it, or reserving it. Read before the deletion, as their
     * rows then no longer name the connection, and ended once it succeeded.
     */
    public final class Deletion {

        private final List<Checkout> active;

        private final List<ApprovalRequest> pending;

        private final List<ApprovalRequest> reservations;

        private Deletion(List<Checkout> active, List<ApprovalRequest> pending, List<ApprovalRequest> reservations) {
            this.active = active;
            this.pending = pending;
            this.reservations = reservations;
        }

        /**
         * Ends them, once the connection was deleted by the given user. The
         * holders' sessions close with their checkouts.
         */
        public void complete(String username) throws GuacamoleException {
            for (Checkout checkout : active)
                end(checkout, Checkout.DELETED, username, null);
            for (ApprovalRequest request : pending) {
                try {
                    approvals.decide(request.getId(), ApprovalRequest.CANCELLED, username, null);
                    events.publish(Event.of(EventType.REQUEST_CANCELLED).user(request.getUsername()).actor(username)
                            .connection(request.getConnectionIdentifier(), request.getConnectionName())
                            .request(request.getId()).detail("The connection was deleted."));
                }
                catch (GuacamoleClientException e) {
                    // Decided meanwhile
                }
            }
            for (ApprovalRequest request : reservations) {
                try {
                    approvals.cancelReservation(request.getId(), username, null);
                    events.publish(Event.of(EventType.REQUEST_CANCELLED).user(request.getUsername()).actor(username)
                            .connection(request.getConnectionIdentifier(), request.getConnectionName())
                            .request(request.getId()).period(request.getStarts(), request.getEnds())
                            .detail("The connection was deleted."));
                }
                catch (GuacamoleClientException e) {
                    // Used or over meanwhile
                }
            }
        }

    }

    /**
     * Prepares ending what deleting the given connection ends.
     */
    public Deletion prepareDeletion(String identifier) throws GuacamoleException {
        Integer id = Values.parseId(identifier);
        if (id == null)
            return new Deletion(Collections.<Checkout>emptyList(), Collections.<ApprovalRequest>emptyList(),
                    Collections.<ApprovalRequest>emptyList());
        return new Deletion(checkouts.listActive(id), approvals.listPending(id), approvals.listReservations(id));
    }

    /**
     * Starts a checkout, for the given number of times the connection's time
     * limit, or until the given time (that of a reservation) if not null.
     * Periods beyond the first use up extensions.
     */
    Checkout startCheckout(Target target, String username, String remoteHost, String reason,
            int revealCount, Long until, int periods) throws GuacamoleException {

        int id = target.getId();
        Checkout checkout = checkouts.create(id, username, remoteHost, reason, CheckoutRules.getDuration(target) * periods, until,
                CheckoutRules.isExclusive(target), revealCount, Math.max(0, rules.getMaxExtensions(target) - (periods - 1)));
        holderCounts = null;

        // A rotation claims the connection before checking for checkouts,
        // and a checkout is created before checking for rotations, so at
        // least one of the two always backs off, on any server
        boolean rotating;
        try {
            rotating = rotationService.isRotating(id);
        }
        catch (GuacamoleException e) {
            checkouts.release(checkout.getId(), Checkout.CANCELLED, null);
            throw e;
        }
        if (rotating) {
            checkouts.release(checkout.getId(), Checkout.CANCELLED, null);
            throw new GuacamoleClientException("The password is being rotated. Please try again in a moment.");
        }

        logger.info("User \"{}\" checked out \"{}\" (checkout {}{}). Reason: {}",
                username, Values.forLog(target.getName()), checkout.getId(),
                checkout.isExclusive() ? ", exclusive" : "",
                Values.forLog(reason));
        events.publish(Event.of(EventType.CHECKOUT_STARTED).user(username)
                .connection(Integer.toString(id), target.getName()).checkout(checkout.getId())
                .period(checkout.getCheckedOut(), checkout.getExpires()).reason(reason).remoteHost(remoteHost)
                .detail(revealCount > 0 ? "The password was shown." : null));

        return checkout;

    }

    /**
     * What the holder of a checkout receives: the password of an Account,
     * nothing secret for any other connection.
     */
    PasswordGrant toGrant(Checkout checkout, Target target) throws GuacamoleException {
        if (!CheckoutRules.isAccount(target))
            return new PasswordGrant(checkout, null, null, null);
        return new PasswordGrant(checkout, CheckoutRules.accountName(target), CheckoutRules.accountDetail(target, rules.platformOf(target)),
                target.getPassword());
    }

    /**
     * Releases the user's own checkout, before its time limit.
     *
     * @param remoteHost
     *     Where the user releases it from, or null if unknown.
     */
    public void release(UserContext context, String username, String remoteHost, String identifier)
            throws GuacamoleException {

        rotationService.requireActive();
        Target target = requireRequestable(context, identifier);
        Checkout checkout = checkouts.getActive(target.getId(), username);
        if (checkout == null)
            throw new GuacamoleClientException("You do not hold this connection.");

        end(checkout, Checkout.RELEASED, username, remoteHost);

    }

    /**
     * Ends any active checkout, on request of an administrator.
     *
     * @param remoteHost
     *     Where the administrator revokes it from, or null if unknown.
     */
    public void revoke(int checkoutId, String administrator, String remoteHost) throws GuacamoleException {

        rotationService.requireActive();
        Checkout checkout = checkouts.get(checkoutId);
        if (checkout == null)
            throw new GuacamoleResourceNotFoundException("No such checkout.");
        if (checkout.getReleased() != null)
            throw new GuacamoleClientException("This checkout has already ended.");

        end(checkout, Checkout.REVOKED, administrator, remoteHost);

    }

    public List<Checkout> listActive() throws GuacamoleException {
        return checkouts.listCurrent();
    }

    /**
     * How long the number of holders of each Account is cached, in
     * milliseconds. Guacamole asks for every connection when listing them.
     */
    private static final long HOLDER_COUNT_TTL_MS = 5000;

    private volatile Map<String, Integer> holderCounts = null;

    private volatile long holderCountsTime = 0;

    /**
     * Returns how many users hold the given Account right now, or null if
     * it is not an Account held by anyone (or the count is unavailable).
     */
    public Integer getAccountHolders(String identifier) {

        long now = System.currentTimeMillis();
        Map<String, Integer> counts = holderCounts;

        if (counts == null || now - holderCountsTime > HOLDER_COUNT_TTL_MS) {
            try {
                counts = checkouts.countAccountHolders(AccountProtocol.NAME);
                holderCounts = counts;
                holderCountsTime = now;
            }
            catch (GuacamoleException e) {
                logger.warn("Unable to count Account holders: {}", e.getMessage());
                return null;
            }
        }

        return counts.get(identifier);

    }

    /**
     * Searches the checkout history, newest first.
     */
    public List<Checkout> search(List<String> terms, int limit) throws GuacamoleException {
        return checkouts.search(terms, limit);
    }

    /**
     * Ends a checkout, recording why, by whom, and from where (or null).
     */
    private void end(Checkout checkout, String releaseReason, String releasedBy, String releasedHost)
            throws GuacamoleException {
        boolean released = checkouts.release(checkout.getId(), releaseReason, releasedBy, releasedHost);
        // After the release, so a count made meanwhile is not kept
        holderCounts = null;
        if (released) {
            logger.info("Checkout {} of \"{}\" by user \"{}\" ended: {} by \"{}\".", checkout.getId(),
                    Values.forLog(checkout.getConnectionName()), checkout.getUsername(), releaseReason, releasedBy);
            events.publish(Event.of(Checkout.RELEASED.equals(releaseReason) ? EventType.CHECKOUT_RELEASED
                    : EventType.CHECKOUT_REVOKED).user(checkout.getUsername()).actor(releasedBy)
                    .connection(checkout.getConnectionIdentifier(), checkout.getConnectionName())
                    .checkout(checkout.getId()).remoteHost(releasedHost)
                    .detail(Checkout.DELETED.equals(releaseReason) ? "The connection was deleted." : null));
            rotationService.checkoutEnded(checkout);
        }
    }

    /**
     * Loads a connection needing a request, failing the same way whether it
     * does not exist, needs no request, or the user may not read it, so its
     * existence is not revealed.
     */
    Target requireRequestable(UserContext context, String identifier) throws GuacamoleException {

        Integer id = Values.parseId(identifier);
        if (id == null || context.getConnectionDirectory().get(identifier) == null)
            throw new GuacamoleSecurityException("Permission denied.");

        Target target = connections.load(id);
        if (target == null || !CheckoutRules.isRequestable(target))
            throw new GuacamoleSecurityException("Permission denied.");

        return target;

    }

}
