package org.apache.guacamole.pam.checkout;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.apache.guacamole.GuacamoleClientException;
import org.apache.guacamole.GuacamoleException;
import org.apache.guacamole.GuacamoleResourceNotFoundException;
import org.apache.guacamole.GuacamoleSecurityException;
import org.apache.guacamole.net.auth.UserContext;
import org.apache.guacamole.pam.AccountProtocol;
import org.apache.guacamole.pam.PamAttributes;
import org.apache.guacamole.pam.approval.ApprovalRepository;
import org.apache.guacamole.pam.approval.ApprovalRequest;
import org.apache.guacamole.pam.db.ConnectionRepository;
import org.apache.guacamole.pam.db.ConnectionRepository.Target;
import org.apache.guacamole.pam.management.ManagementType;
import org.apache.guacamole.pam.management.ManagementTypes;
import org.apache.guacamole.pam.platform.Platform;
import org.apache.guacamole.pam.platform.PlatformRepository;
import org.apache.guacamole.pam.rotation.RotationService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Requests and checkouts. Account connections are checked out to see their
 * password; any other connection can require a checkout before connecting
 * (an access window, which reveals no password unless the connection allows
 * its holder to see it).
 *
 * Who may request is decided by Guacamole itself: a user may request any
 * connection they can read, checked through their own UserContext of the
 * managed data source. Every checkout has a time limit. Exclusive checkouts
 * allow a single holder, which managed connections use by default because
 * ending a checkout rotates the password. Connections may require approval:
 * requests then wait for enough distinct approvers, and the checkout starts
 * at the final approval.
 */
public class CheckoutService {

    private static final Logger logger = LoggerFactory.getLogger(CheckoutService.class);

    public static final int DEFAULT_MINUTES = 60;

    public static final int MAX_MINUTES = 7 * 24 * 60;

    private static final int MAX_REASON_LENGTH = 500;

    /**
     * Reason recorded for checkouts of Accounts allowing access without a
     * request, so the history shows why there is no reason.
     */
    private static final String NO_REQUEST_REASON = "Access without a request";

    /**
     * Reason recorded for checkouts of administrators bypassing requests.
     */
    private static final String ADMIN_BYPASS_REASON = "Administrator access without a request";

    /**
     * Upper bound of the approvals a connection can require.
     */
    private static final int MAX_APPROVALS = 10;

    /**
     * Parameters of Account connections safe to read when listing requests;
     * secrets are excluded. Other connections expose no parameters at all.
     */
    private static final List<String> PUBLIC_PARAMETERS = Arrays.asList(
            AccountProtocol.USERNAME, AccountProtocol.URL, AccountProtocol.NOTES);

    private static final String USERNAME_PARAMETER = "username";

    private final ConnectionRepository connections;

    private final CheckoutRepository checkouts;

    private final PlatformRepository platforms;

    private final ApprovalRepository approvals;

    private final RotationService rotationService;

    /**
     * Whether administrators bypass requests entirely. Otherwise they only
     * skip approvals, and give a reason like anyone else.
     */
    private final boolean adminBypass;

    public CheckoutService(ConnectionRepository connections, CheckoutRepository checkouts,
            PlatformRepository platforms, ApprovalRepository approvals, RotationService rotationService,
            boolean adminBypass) {
        this.adminBypass = adminBypass;
        this.connections = connections;
        this.approvals = approvals;
        this.platforms = platforms;
        this.checkouts = checkouts;
        this.rotationService = rotationService;
    }

    /**
     * Lists the connections the user can read that need a request.
     */
    public List<PasswordRequest> listRequests(UserContext context, String username, boolean administrator)
            throws GuacamoleException {

        Set<String> readable = context.getConnectionDirectory().getIdentifiers();
        Map<String, Platform> all = platforms.getAll();

        List<PasswordRequest> requests = new ArrayList<>();
        for (Target target : connections.listRequestCandidates(AccountProtocol.NAME, PUBLIC_PARAMETERS)) {
            if (isRequestable(target) && readable.contains(Integer.toString(target.getId())))
                requests.add(toRequest(target, all.get(target.getAttribute(PamAttributes.PLATFORM)), username,
                        administrator));
        }

        return requests;

    }

    public PasswordRequest getRequest(UserContext context, String username, String identifier,
            boolean administrator) throws GuacamoleException {
        Target target = requireRequestable(context, identifier);
        return toRequest(target, platformOf(target), username, administrator);
    }

    /**
     * Checks out the connection for the user: an Account's password, or
     * access to any other connection. If the user already holds it, the
     * existing checkout is returned (with the password, for an Account). If
     * the connection needs approval, a new request instead awaits approval
     * (or the user's pending request is returned), unless the user is an
     * administrator: administrators bypass approval, and also the reason
     * when they bypass requests.
     *
     * @throws GuacamoleClientException
     *     If the reason is missing, or the connection cannot be held now.
     */
    public RequestOutcome request(UserContext context, String username, String identifier, String reason,
            boolean administrator) throws GuacamoleException {

        Target target = requireRequestable(context, identifier);
        int id = target.getId();
        boolean account = isAccount(target);

        if (account) {
            String password = target.getPassword();
            if (password == null || password.isEmpty())
                throw new GuacamoleClientException("No password is stored for this account yet.");
        }

        Checkout checkout = checkouts.getActive(id, username);
        if (checkout != null) {
            if (account) {
                if (!checkouts.recordReveal(checkout.getId()))
                    throw new GuacamoleClientException("This checkout has ended.");
                logger.info("User \"{}\" viewed the password of \"{}\" (checkout {}).",
                        username, target.getName(), checkout.getId());
            }
            return RequestOutcome.granted(toGrant(checkout, target));
        }

        int approvalsRequired = administrator ? 0 : getApprovalsRequired(target);
        if (administrator && getApprovalsRequired(target) > 0)
            logger.info("Administrator \"{}\" bypasses the approval of \"{}\".", username, target.getName());

        if (approvalsRequired > 0 && approvals.getPending(id, username) == null) {

            String trimmed = validateReason(reason);
            requireAvailable(target);

            ApprovalRequest pending = approvals.create(id, username, trimmed, approvalsRequired);
            logger.info("User \"{}\" requested \"{}\" (request {}, {} approvals needed). Reason: {}",
                    username, target.getName(), pending.getId(), approvalsRequired,
                    trimmed.replaceAll("[\\r\\n]+", " "));

        }

        if (approvalsRequired > 0)
            return RequestOutcome.pending(toRequest(target, platformOf(target), username, administrator));

        String checkoutReason;
        if (!requiresRequest(target))
            checkoutReason = NO_REQUEST_REASON;
        else if (bypassesRequests(administrator)) {
            checkoutReason = ADMIN_BYPASS_REASON;
            logger.info("Administrator \"{}\" checks out \"{}\" without a request.", username, target.getName());
        }
        else
            checkoutReason = validateReason(reason);


        checkout = startCheckout(target, username, checkoutReason, account ? 1 : 0);
        return RequestOutcome.granted(toGrant(checkout, connections.load(id)));

    }

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

        Target target = requireRequestable(context, identifier);
        if (!revealsPassword(target))
            throw new GuacamoleSecurityException("The password of this connection is not shown.");

        Checkout checkout = checkouts.getActive(target.getId(), username);
        if (checkout == null)
            throw new GuacamoleClientException("You do not hold this connection.");

        // A Guacamole token, such as ${GUAC_PASSWORD}, is the user's own
        String password = target.getPassword();
        if (password == null || password.isEmpty() || password.contains("${"))
            throw new GuacamoleClientException("This connection has no stored password to show.");

        if (!checkouts.recordReveal(checkout.getId()))
            throw new GuacamoleClientException("Your access has ended.");
        logger.info("User \"{}\" viewed the password of \"{}\" (checkout {}).",
                username, target.getName(), checkout.getId());

        String user = blankToNull(target.getParameters().get(USERNAME_PARAMETER));
        return new PasswordGrant(checkout, user == null || user.contains("${") ? null : user, null, password);

    }

    /**
     * Refuses a session on a connection requiring a request unless the user
     * holds an active checkout of it, or is an administrator while
     * administrators bypass requests (which is logged). The same applies to
     * Accounts, through {@link #request}.
     *
     * @throws GuacamoleClientException
     *     If the user must request access first.
     */
    public void requireAccess(String identifier, String username, boolean administrator)
            throws GuacamoleException {

        Integer id = parseId(identifier);
        if (id == null)
            return;

        Target target = connections.load(id);
        if (target == null || !requiresRequest(target))
            return;

        if (checkouts.getActive(id, username) != null)
            return;

        if (bypassesRequests(administrator)) {
            logger.info("Administrator \"{}\" connects to \"{}\" without a request.", username, target.getName());
            return;
        }

        throw new GuacamoleClientException("You must request access to this connection, and have it approved"
                    + " if needed, before connecting.");

    }

    /**
     * Refuses connecting through a balancing connection group if any of its
     * connections is an Account, requires a request, or is managed: the
     * connection Guacamole picks would be opened without its checks, and its
     * session would not be tracked for rotation.
     *
     * @throws GuacamoleClientException
     *     If the group contains such a connection.
     */
    public void requireBalanceable(String groupName, Iterable<String> connectionIdentifiers)
            throws GuacamoleException {

        for (String identifier : connectionIdentifiers) {
            Integer id = parseId(identifier);
            Target target = id == null ? null : connections.load(id);
            if (target != null && (isRequestable(target) || isManaged(target)))
                throw new GuacamoleClientException("Connection group \"" + groupName + "\" balances over \""
                        + target.getName() + "\", which requires a request or has its password managed."
                        + " Open that connection directly instead.");
        }

    }

    /**
     * Starts the checkout of an approved request. The requester sees the
     * password, or connects, by opening the connection again.
     */
    public Checkout startApprovedCheckout(ApprovalRequest request) throws GuacamoleException {
        Target target = connections.load(Integer.parseInt(request.getConnectionIdentifier()));
        if (target == null)
            throw new GuacamoleResourceNotFoundException("The connection no longer exists.");
        return startCheckout(target, request.getUsername(), request.getReason(), 0);
    }

    /**
     * Cancels the user's own request awaiting approval.
     */
    public void cancelRequest(UserContext context, String username, String identifier) throws GuacamoleException {

        Target target = requireRequestable(context, identifier);
        ApprovalRequest pending = approvals.getPending(target.getId(), username);
        if (pending == null)
            throw new GuacamoleClientException("You have no request for this connection awaiting approval.");

        approvals.decide(pending.getId(), ApprovalRequest.CANCELLED, username);
        logger.info("User \"{}\" cancelled request {} for \"{}\".", username, pending.getId(), target.getName());

    }

    private Checkout startCheckout(Target target, String username, String reason, int revealCount)
            throws GuacamoleException {

        int id = target.getId();
        Checkout checkout = checkouts.create(id, username, reason, getDuration(target), isExclusive(target),
                revealCount);
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
                username, target.getName(), checkout.getId(), checkout.isExclusive() ? ", exclusive" : "",
                reason.replaceAll("[\\r\\n]+", " "));

        return checkout;

    }

    /**
     * What the holder of a checkout receives: the password of an Account,
     * nothing secret for any other connection.
     */
    private PasswordGrant toGrant(Checkout checkout, Target target) throws GuacamoleException {
        if (!isAccount(target))
            return new PasswordGrant(checkout, null, null, null);
        return new PasswordGrant(checkout, accountName(target), accountDetail(target, platformOf(target)),
                target.getPassword());
    }

    private static String validateReason(String reason) throws GuacamoleClientException {
        String trimmed = reason == null ? "" : reason.trim();
        if (trimmed.isEmpty())
            throw new GuacamoleClientException("Please give a reason for your request.");
        if (trimmed.length() > MAX_REASON_LENGTH)
            throw new GuacamoleClientException("The reason is limited to " + MAX_REASON_LENGTH + " characters.");
        return trimmed;
    }

    /**
     * Refuses a request that could not be granted anyway because someone
     * holds the connection exclusively, or an exclusive checkout is wanted
     * while anyone holds it.
     */
    private void requireAvailable(Target target) throws GuacamoleException {
        for (Checkout active : checkouts.listActive(target.getId())) {
            if (active.isExclusive())
                throw new GuacamoleClientException("This is checked out by \""
                        + active.getUsername() + "\" until it is released or expires.");
            if (isExclusive(target))
                throw new GuacamoleClientException("This is in use by \""
                        + active.getUsername() + "\" and can only be held by one user at a time.");
        }
    }

    /**
     * Releases the user's own checkout, before its time limit.
     */
    public void release(UserContext context, String username, String identifier) throws GuacamoleException {

        Target target = requireRequestable(context, identifier);
        Checkout checkout = checkouts.getActive(target.getId(), username);
        if (checkout == null)
            throw new GuacamoleClientException("You do not hold this connection.");

        end(checkout, Checkout.RELEASED, username);

    }

    /**
     * Ends any active checkout, on request of an administrator.
     */
    public void revoke(int checkoutId, String administrator) throws GuacamoleException {

        Checkout checkout = checkouts.get(checkoutId);
        if (checkout == null)
            throw new GuacamoleResourceNotFoundException("No such checkout.");
        if (checkout.getReleased() != null)
            throw new GuacamoleClientException("This checkout has already ended.");

        end(checkout, Checkout.REVOKED, administrator);

    }

    public List<Checkout> listActive() throws GuacamoleException {
        return checkouts.listActive();
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

    private void end(Checkout checkout, String releaseReason, String releasedBy) throws GuacamoleException {
        holderCounts = null;
        if (checkouts.release(checkout.getId(), releaseReason, releasedBy)) {
            logger.info("Checkout {} of \"{}\" by user \"{}\" ended: {} by \"{}\".", checkout.getId(),
                    checkout.getConnectionName(), checkout.getUsername(), releaseReason, releasedBy);
            rotationService.checkoutEnded(checkout);
        }
    }

    /**
     * Loads a connection needing a request, failing the same way whether it
     * does not exist, needs no request, or the user may not read it, so its
     * existence is not revealed.
     */
    private Target requireRequestable(UserContext context, String identifier) throws GuacamoleException {

        Integer id = parseId(identifier);
        if (id == null || context.getConnectionDirectory().get(identifier) == null)
            throw new GuacamoleSecurityException("Permission denied.");

        Target target = connections.load(id);
        if (target == null || !isRequestable(target))
            throw new GuacamoleSecurityException("Permission denied.");

        return target;

    }

    private PasswordRequest toRequest(Target target, Platform platform, String username, boolean administrator)
            throws GuacamoleException {

        int approvalsRequired = administrator ? 0 : getApprovalsRequired(target);
        boolean account = isAccount(target);

        return new PasswordRequest(Integer.toString(target.getId()), target.getName(),
                account ? accountName(target) : null,
                account ? accountDetail(target, platform) : null,
                account ? blankToNull(target.getParameters().get(AccountProtocol.URL)) : null,
                account ? blankToNull(target.getParameters().get(AccountProtocol.NOTES)) : null,
                isManaged(target), isExclusive(target), getDuration(target),
                checkouts.listActive(target.getId()), username)
            .withAccount(account)
            .withPasswordShown(revealsPassword(target))
            .withBypass(bypassesRequests(administrator))
            .withNoRequest(!requiresRequest(target) || bypassesRequests(administrator))
            .withApproval(approvalsRequired,
                approvalsRequired > 0 ? approvals.getPending(target.getId(), username) : null,
                approvalsRequired > 0 ? approvals.getLatest(target.getId(), username) : null);

    }

    /**
     * Whether the user, an administrator or not, connects and checks out
     * without a request.
     */
    private boolean bypassesRequests(boolean administrator) {
        return administrator && adminBypass;
    }

    /**
     * Whether the connection is an Account, checked out for its password.
     */
    public static boolean isAccount(Target target) {
        return AccountProtocol.NAME.equals(target.getProtocol());
    }

    /**
     * Whether the holder of a checkout of the connection, not an Account,
     * may see its password.
     */
    public static boolean revealsPassword(Target target) {
        return !isAccount(target) && "true".equals(target.getAttribute(PamAttributes.REVEAL_PASSWORD));
    }

    /**
     * Whether users must request the connection, with a reason: always,
     * unless it allows access without a request. Connections requiring
     * approvals always require a request. The same applies to Accounts and
     * to other connections.
     */
    public static boolean requiresRequest(Target target) {
        return !"true".equals(target.getAttribute(PamAttributes.REQUEST_EXEMPT))
            || getApprovalsRequired(target) > 0;
    }

    /**
     * Whether the connection goes through checkouts: when it requires a
     * request, and always for Accounts, whose password is only ever shown
     * through a checkout (without a request, one is started as soon as the
     * Account is opened).
     */
    public static boolean isRequestable(Target target) {
        return isAccount(target) || requiresRequest(target);
    }

    /**
     * How many distinct approvers must approve a request for the connection.
     */
    private static int getApprovalsRequired(Target target) {
        try {
            return Math.max(0, Math.min(MAX_APPROVALS, Integer.parseInt(target.getAttribute(PamAttributes.APPROVALS_REQUIRED))));
        }
        catch (NumberFormatException | NullPointerException e) {
            return 0;
        }
    }

    private Platform platformOf(Target target) throws GuacamoleException {
        return platforms.get(target.getAttribute(PamAttributes.PLATFORM));
    }

    /**
     * Extra identification of the account given by its platform's type,
     * such as its LDAP DN, or null.
     */
    private static String accountDetail(Target target, Platform platform) {
        ManagementType type = platform == null ? null : ManagementTypes.get(platform.getType());
        return type == null ? null : type.getAccountDetail(target);
    }

    /**
     * Whether this extension manages (rotates) the password of the connection.
     */
    public static boolean isManaged(Target target) {
        return target.getAttribute(PamAttributes.PLATFORM) != null;
    }

    /**
     * Whether checkouts of the connection exclude other holders. Defaults to
     * exclusive for managed connections, whose password changes on release.
     */
    public static boolean isExclusive(Target target) {
        String value = target.getAttribute(PamAttributes.CHECKOUT_EXCLUSIVE);
        if (PamAttributes.EXCLUSIVE_YES.equals(value))
            return true;
        if (PamAttributes.EXCLUSIVE_NO.equals(value))
            return false;
        return isManaged(target);
    }

    private static String accountName(Target target) {
        return target.getParameters().get(AccountProtocol.USERNAME);
    }

    private static int getDuration(Target target) {
        try {
            int minutes = Integer.parseInt(target.getAttribute(PamAttributes.CHECKOUT_DURATION));
            return Math.max(1, Math.min(MAX_MINUTES, minutes));
        }
        catch (NumberFormatException | NullPointerException e) {
            return DEFAULT_MINUTES;
        }
    }

    private static Integer parseId(String identifier) {
        try {
            return identifier == null ? null : Integer.valueOf(identifier);
        }
        catch (NumberFormatException e) {
            return null;
        }
    }

    private static String blankToNull(String value) {
        return value == null || value.trim().isEmpty() ? null : value;
    }

}
