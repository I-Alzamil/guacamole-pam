package io.github.ialzamil.guacamole.pam.checkout;

import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.apache.guacamole.GuacamoleClientException;
import org.apache.guacamole.GuacamoleException;
import org.apache.guacamole.GuacamoleResourceNotFoundException;
import org.apache.guacamole.GuacamoleSecurityException;
import org.apache.guacamole.net.auth.UserContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import io.github.ialzamil.guacamole.pam.AccountProtocol;
import io.github.ialzamil.guacamole.pam.PamAttributes;
import io.github.ialzamil.guacamole.pam.Values;
import io.github.ialzamil.guacamole.pam.approval.ApprovalRepository;
import io.github.ialzamil.guacamole.pam.approval.ApprovalRequest;
import io.github.ialzamil.guacamole.pam.db.ConnectionRepository.Target;
import io.github.ialzamil.guacamole.pam.db.ConnectionRepository;
import io.github.ialzamil.guacamole.pam.management.ManagementType;
import io.github.ialzamil.guacamole.pam.management.ManagementTypes;
import io.github.ialzamil.guacamole.pam.platform.Platform;
import io.github.ialzamil.guacamole.pam.platform.PlatformRepository;
import io.github.ialzamil.guacamole.pam.rotation.RotationService;
import io.github.ialzamil.guacamole.pam.settings.PamSettings;

/**
 * Requests and checkouts. Account connections are checked out to see their
 * password; any other connection can require a checkout before connecting
 * (an access window, which reveals no password unless the connection allows
 * its holder to see it).
 *
 * Who may request is decided by Guacamole itself: a user may request any
 * connection they can read, checked through their own UserContext of the
 * managed data source. Every checkout has a time limit. Exclusive checkouts
 * allow a single holder, which managed connections use by default, as ending a
 * checkout may rotate the password. Connections may require approval: requests
 * then wait for enough distinct approvers, and the checkout starts at the final
 * approval. Those can also be requested ahead of time, for a given start: once
 * approved, the request reserves the connection from then until its time
 * limit, and the requester checks out with it during that time. Reservations
 * of a connection checked out alone never overlap, and keep others from
 * checking it out during them.
 */
public class CheckoutService {

    private static final Logger logger = LoggerFactory.getLogger(CheckoutService.class);

    public static final int DEFAULT_MINUTES = 60;

    public static final int MAX_MINUTES = 7 * 24 * 60;

    /**
     * Upper bound of the extensions a connection can allow, as of the
     * setting {@link PamSettings#MAX_EXTENSIONS}.
     */
    private static final int MAX_EXTENSIONS = PamSettings.MAX_EXTENSIONS.getMaximum();

    private static final int MAX_REASON_LENGTH = 500;

    /**
     * How far ahead access can be requested, in days.
     */
    public static final int MAX_DAYS_AHEAD = 30;

    /**
     * How long before now a start of access requested ahead of time may be,
     * in milliseconds, so a start picked in the current minute is accepted.
     */
    private static final long START_TOLERANCE_MS = 60000;

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
     * Settings shared by every server: whether administrators bypass
     * requests, and how checkouts may be extended unless a connection says
     * otherwise.
     */
    private final PamSettings settings;

    public CheckoutService(ConnectionRepository connections, CheckoutRepository checkouts,
            PlatformRepository platforms, ApprovalRepository approvals, RotationService rotationService,
            PamSettings settings) {
        this.settings = settings;
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

        // Read once for every connection, not once per connection
        Map<Integer, List<Checkout>> active = new HashMap<>();
        for (Checkout checkout : checkouts.listActive()) {
            Integer id = Values.parseId(checkout.getConnectionIdentifier());
            if (id != null)
                active.computeIfAbsent(id, key -> new ArrayList<>()).add(checkout);
        }
        Map<Integer, ApprovalRequest> pending = approvals.listPendingOf(username);
        Map<Integer, ApprovalRequest> latest = approvals.listLatestOf(username);
        Map<Integer, List<ApprovalRequest>> reservations = approvals.listReservations();

        List<PasswordRequest> requests = new ArrayList<>();
        for (Target target : connections.listRequestCandidates(AccountProtocol.NAME, PUBLIC_PARAMETERS)) {
            int id = target.getId();
            if (isRequestable(target) && readable.contains(Integer.toString(id)))
                requests.add(toRequest(target, all.get(target.getAttribute(PamAttributes.PLATFORM)), username,
                        administrator, active.getOrDefault(id, Collections.<Checkout>emptyList()),
                        pending.get(id), latest.get(id),
                        reservations.getOrDefault(id, Collections.<ApprovalRequest>emptyList())));
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
     * when they bypass requests. During the user's own reservation, its
     * checkout starts instead, until the reservation ends.
     *
     * @param remoteHost
     *     Where the user requests from, kept with the request and the
     *     checkout, or null if unknown.
     *
     * @param starts
     *     When the access starts, for a request made ahead of time, or null
     *     for access as soon as possible.
     *
     * @param periods
     *     How many times the connection's time limit the access lasts: 1, or
     *     up to one more than the extensions it allows, which this uses up.
     *
     * @throws GuacamoleClientException
     *     If the reason is missing, the start or periods are not allowed, or
     *     the connection cannot be held now (or then).
     */
    public RequestOutcome request(UserContext context, String username, String remoteHost, String identifier,
            String reason, Long starts, int periods, boolean administrator) throws GuacamoleException {

        Target target = requireRequestable(context, identifier);
        int id = target.getId();

        int maxPeriods = getMaxPeriods(target);
        if (periods < 1 || periods > maxPeriods)
            throw new GuacamoleClientException(maxPeriods == 1
                    ? "This access cannot be asked for longer than its time limit."
                    : "This access can be asked for up to " + maxPeriods + " times its time limit.");

        // Expired checkouts not ended yet would refuse the request
        rotationService.expireCheckouts();

        if (isAccount(target)) {
            String password = target.getPassword();
            if (password == null || password.isEmpty())
                throw new GuacamoleClientException("No password is stored for this account yet.");
        }

        Checkout checkout = checkouts.getActive(id, username);
        if (checkout != null)
            return showAgain(target, username, checkout);

        // The user's reservation, once it started
        ApprovalRequest reservation = starts == null ? approvals.getReservation(id, username) : null;
        if (reservation != null && reservation.getStarts() <= System.currentTimeMillis())
            return useReservation(target, username, remoteHost, reservation);

        int approvalsRequired = administrator ? 0 : getApprovalsRequired(target);
        if (starts != null && approvalsRequired == 0)
            throw new GuacamoleClientException("Only access needing approval is requested ahead of time.");
        if (administrator && getApprovalsRequired(target) > 0)
            logger.info("Administrator \"{}\" bypasses the approval of \"{}\".", username,
                    Values.forLog(target.getName()));

        if (approvalsRequired > 0) {
            if (approvals.getPending(id, username) == null)
                askApproval(target, username, remoteHost, reason, approvalsRequired, starts, periods);
            return RequestOutcome.pending(toRequest(target, platformOf(target), username, administrator));
        }

        return checkOutNow(target, username, remoteHost, reason, periods, administrator);

    }

    /**
     * The user's own active checkout, shown again: an Account's password
     * again, which is recorded.
     */
    private RequestOutcome showAgain(Target target, String username, Checkout checkout) throws GuacamoleException {
        if (isAccount(target)) {
            if (!checkouts.recordReveal(checkout.getId()))
                throw new GuacamoleClientException("This checkout has ended.");
            logger.info("User \"{}\" viewed the password of \"{}\" (checkout {}).",
                    username, Values.forLog(target.getName()), checkout.getId());
        }
        return RequestOutcome.granted(toGrant(checkout, target));
    }

    /**
     * Starts the checkout of the user's reservation, which started: until
     * it ends, with its reason.
     */
    private RequestOutcome useReservation(Target target, String username, String remoteHost,
            ApprovalRequest reservation) throws GuacamoleException {
        Checkout checkout = startCheckout(target, username, remoteHost, reservation.getReason(),
                isAccount(target) ? 1 : 0, reservation.getEnds(), reservation.getPeriods());
        approvals.markUsed(reservation.getId(), checkout.getId());
        logger.info("User \"{}\" used request {} for \"{}\" (checkout {}).", username, reservation.getId(),
                Values.forLog(target.getName()), checkout.getId());
        return RequestOutcome.granted(toGrant(checkout, connections.load(target.getId())));
    }

    /**
     * Asks for approval of access now, if the connection could be held now,
     * or from a start ahead of time.
     */
    private void askApproval(Target target, String username, String remoteHost, String reason,
            int approvalsRequired, Long starts, int periods) throws GuacamoleException {

        String trimmed = validateReason(reason);
        Long ends = null;
        String when = "";
        if (starts == null)
            requireAvailable(target, username);
        else {
            validateStart(starts);
            long end = starts + getDuration(target) * 60000L * periods;
            ends = end;
            when = ", from " + Instant.ofEpochMilli(starts) + " to " + Instant.ofEpochMilli(end);
        }

        ApprovalRequest pending = approvals.create(target.getId(), username, remoteHost, trimmed, approvalsRequired,
                starts, ends, isExclusive(target), periods);
        logger.info("User \"{}\" requested \"{}\" (request {}, {} approvals needed{}{}). Reason: {}",
                username, Values.forLog(target.getName()), pending.getId(), approvalsRequired, when,
                periods == 1 ? "" : ", " + periods + " times its time limit", Values.forLog(trimmed));

    }

    /**
     * Checks out a connection needing no approval: with the user's reason,
     * unless it needs no request or the user is an administrator bypassing
     * requests.
     */
    private RequestOutcome checkOutNow(Target target, String username, String remoteHost, String reason,
            int periods, boolean administrator) throws GuacamoleException {

        String checkoutReason;
        if (!requiresRequest(target))
            checkoutReason = NO_REQUEST_REASON;
        else if (bypassesRequests(administrator)) {
            checkoutReason = ADMIN_BYPASS_REASON;
            logger.info("Administrator \"{}\" checks out \"{}\" without a request.", username,
                    Values.forLog(target.getName()));
        }
        else
            checkoutReason = validateReason(reason);

        Checkout checkout = startCheckout(target, username, remoteHost, checkoutReason, isAccount(target) ? 1 : 0,
                null, periods);
        return RequestOutcome.granted(toGrant(checkout, connections.load(target.getId())));

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
                username, Values.forLog(target.getName()), checkout.getId());

        String user = Values.trimToNull(target.getParameters().get(USERNAME_PARAMETER));
        return new PasswordGrant(checkout, user == null || user.contains("${") ? null : user, null, password);

    }

    /**
     * Refuses a session on a connection requiring a request unless the user
     * holds an active checkout of it, or is an administrator while
     * administrators bypass requests (which is logged). The same applies to
     * Accounts, through {@link #request}.
     *
     * @throws GuacamoleSecurityException
     *     If the user must request access first: forbidden, which the web
     *     UI explains when refusing a session.
     */
    public void requireAccess(String identifier, String username, boolean administrator)
            throws GuacamoleException {

        Integer id = Values.parseId(identifier);
        if (id == null)
            return;

        Target target = connections.load(id);
        if (target == null || !requiresRequest(target))
            return;

        if (checkouts.getActive(id, username) != null)
            return;

        if (bypassesRequests(administrator)) {
            logger.info("Administrator \"{}\" connects to \"{}\" without a request.", username,
                    Values.forLog(target.getName()));
            return;
        }

        throw new GuacamoleSecurityException("You must request access to this connection, and have it approved"
                    + " if needed, before connecting.");

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
            if (target != null && (isRequestable(target) || isManaged(target)))
                throw new GuacamoleSecurityException("Connection group \"" + groupName + "\" balances over \""
                        + target.getName() + "\", which requires a request or has its password managed."
                        + " Open that connection directly instead.");
        }

    }

    /**
     * Starts the checkout of an approved request. The requester sees the
     * password, or connects, by opening the connection again.
     */
    public Checkout startApprovedCheckout(ApprovalRequest request) throws GuacamoleException {
        Integer id = Values.parseId(request.getConnectionIdentifier());
        Target target = id == null ? null : connections.load(id);
        if (target == null)
            throw new GuacamoleResourceNotFoundException("The connection no longer exists.");
        rotationService.expireCheckouts();
        return startCheckout(target, request.getUsername(), request.getRemoteHost(), request.getReason(), 0, null,
                request.getPeriods());
    }

    /**
     * Approves a request made ahead of time: it then reserves the
     * connection, for its requester to check out during its time. Others'
     * pending requests that overlap it, on a connection checked out alone,
     * are rejected.
     *
     * @throws GuacamoleClientException
     *     If its time is no longer free, as the connection is checked out
     *     alone and someone else holds or reserved it then.
     */
    public void reserve(ApprovalRequest request, String approver) throws GuacamoleException {
        Integer id = Values.parseId(request.getConnectionIdentifier());
        Target target = id == null ? null : connections.load(id);
        if (target == null)
            throw new GuacamoleResourceNotFoundException("The connection no longer exists.");
        rotationService.expireCheckouts();
        for (Integer rejected : approvals.markReserved(request, approver, isExclusive(target)))
            logger.info("Request {} for \"{}\" was rejected: it overlaps request {} of \"{}\", approved by \"{}\".",
                    rejected, Values.forLog(target.getName()), request.getId(), request.getUsername(), approver);
    }

    /**
     * Extends the user's checkout of a connection allowing it, by the
     * connection's extension length, with a reason (unless the connection
     * needs no request). If the connection needs approval, a request to
     * extend it instead awaits approval, by as many approvers as a request
     * (administrators skip it). Extensions end no later than someone else's
     * next reservation of a connection held alone.
     *
     * @param remoteHost
     *     Where the user asks from, or null if unknown.
     *
     * @return
     *     The connection as now shown to the user.
     *
     * @throws GuacamoleClientException
     *     If the user holds no checkout of it, the checkout cannot be
     *     extended any more, the reason is missing, or the extension cannot
     *     be granted.
     */
    public PasswordRequest extend(UserContext context, String username, String remoteHost, String identifier,
            String reason, boolean administrator) throws GuacamoleException {

        Target target = requireRequestable(context, identifier);
        if (!allowsExtensions(target))
            throw new GuacamoleClientException("This access cannot be extended.");

        rotationService.expireCheckouts();
        Checkout checkout = checkouts.getActive(target.getId(), username);
        if (checkout == null)
            throw new GuacamoleClientException("You do not hold this connection.");
        if (checkout.getExtensions() >= checkout.getMaxExtensions())
            throw new GuacamoleClientException("This checkout cannot be extended any more.");

        // A reason, as for the checkout itself
        String trimmed;
        if (reason != null && !reason.trim().isEmpty())
            trimmed = validateReason(reason);
        else if (!requiresRequest(target))
            trimmed = NO_REQUEST_REASON;
        else if (bypassesRequests(administrator))
            trimmed = ADMIN_BYPASS_REASON;
        else
            trimmed = validateReason(reason);
        int approvalsRequired = administrator ? 0 : getApprovalsRequired(target);
        int minutes = getExtensionMinutes(target);

        ApprovalRequest request = approvals.createExtension(checkout, username, remoteHost, trimmed,
                approvalsRequired, minutes);
        logger.info("User \"{}\" asked to extend checkout {} of \"{}\" by {} minutes (request {}, {} approvals"
                + " needed). Reason: {}", username, checkout.getId(), Values.forLog(target.getName()), minutes,
                request.getId(), approvalsRequired, Values.forLog(trimmed));

        if (approvalsRequired == 0) {
            try {
                grantExtension(request, username);
            }
            catch (GuacamoleClientException e) {
                approvals.decide(request.getId(), ApprovalRequest.CANCELLED, username, remoteHost);
                throw e;
            }
            approvals.markApproved(request.getId(), checkout.getId(), username);
        }

        return toRequest(target, platformOf(target), username, administrator);

    }

    /**
     * Grants an extension once approved, extending its checkout.
     *
     * @throws GuacamoleClientException
     *     If the checkout ended, cannot be extended any more, or someone
     *     else's reservation starts as it ends.
     */
    public Checkout grantExtension(ApprovalRequest request, String approver) throws GuacamoleException {
        rotationService.expireCheckouts();
        Checkout checkout = checkouts.extend(request.getExtendsCheckout(), request.getExtensionMinutes());
        logger.info("Checkout {} of \"{}\" by user \"{}\" was extended by {} minutes, until {} (request {},"
                + " approved by \"{}\").", checkout.getId(), Values.forLog(checkout.getConnectionName()),
                checkout.getUsername(), request.getExtensionMinutes(), Instant.ofEpochMilli(checkout.getExpires()),
                request.getId(), approver);
        return checkout;
    }

    /**
     * Cancels the user's request to extend their checkout, awaiting
     * approval.
     *
     * @param remoteHost
     *     Where the user cancels from, or null if unknown.
     */
    public void cancelExtension(UserContext context, String username, String remoteHost, String identifier)
            throws GuacamoleException {

        Target target = requireRequestable(context, identifier);
        Checkout checkout = checkouts.getActive(target.getId(), username);
        if (checkout == null)
            throw new GuacamoleClientException("No extension of your checkout awaits approval.");
        ApprovalRequest extension = approvals.getLatestExtension(checkout.getId());
        if (extension == null || !ApprovalRequest.PENDING.equals(extension.getStatus()))
            throw new GuacamoleClientException("No extension of your checkout awaits approval.");

        approvals.decide(extension.getId(), ApprovalRequest.CANCELLED, username, remoteHost);
        logger.info("User \"{}\" cancelled request {} to extend checkout {}.", username, extension.getId(),
                checkout.getId());

    }

    /**
     * Cancels the user's own request awaiting approval.
     *
     * @param remoteHost
     *     Where the user cancels from, or null if unknown.
     */
    public void cancelRequest(UserContext context, String username, String remoteHost, String identifier)
            throws GuacamoleException {

        Target target = requireRequestable(context, identifier);
        ApprovalRequest pending = approvals.getPending(target.getId(), username);
        if (pending == null)
            throw new GuacamoleClientException("You have no request for this connection awaiting approval.");

        approvals.decide(pending.getId(), ApprovalRequest.CANCELLED, username, remoteHost);
        logger.info("User \"{}\" cancelled request {} for \"{}\".", username, pending.getId(),
                Values.forLog(target.getName()));

    }

    /**
     * Cancels the user's own next reservation, approved but not used yet.
     *
     * @param remoteHost
     *     Where the user cancels from, or null if unknown.
     */
    public void cancelReservation(UserContext context, String username, String remoteHost, String identifier)
            throws GuacamoleException {

        Target target = requireRequestable(context, identifier);
        ApprovalRequest reservation = approvals.getReservation(target.getId(), username);
        if (reservation == null)
            throw new GuacamoleClientException("You have no approved access to this ahead.");

        approvals.cancelReservation(reservation.getId(), username, remoteHost);
        logger.info("User \"{}\" cancelled their reservation {} of \"{}\".", username, reservation.getId(),
                Values.forLog(target.getName()));

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
                }
                catch (GuacamoleClientException e) {
                    // Decided meanwhile
                }
            }
            for (ApprovalRequest request : reservations) {
                try {
                    approvals.cancelReservation(request.getId(), username, null);
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
    private Checkout startCheckout(Target target, String username, String remoteHost, String reason,
            int revealCount, Long until, int periods) throws GuacamoleException {

        int id = target.getId();
        Checkout checkout = checkouts.create(id, username, remoteHost, reason, getDuration(target) * periods, until,
                isExclusive(target), revealCount, Math.max(0, getMaxExtensions(target) - (periods - 1)));
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
     * Refuses a start of access requested ahead of time that is past, or too
     * far ahead.
     */
    private static void validateStart(long starts) throws GuacamoleClientException {
        long now = System.currentTimeMillis();
        if (starts < now - START_TOLERANCE_MS)
            throw new GuacamoleClientException("Please choose a start in the future.");
        if (starts > now + MAX_DAYS_AHEAD * 24L * 3600000L)
            throw new GuacamoleClientException("Access can be requested up to " + MAX_DAYS_AHEAD + " days ahead.");
    }

    /**
     * Refuses a request that could not be granted anyway because someone
     * holds the connection exclusively, or an exclusive checkout is wanted
     * while anyone holds it, or while someone else's reservation lasts.
     */
    private void requireAvailable(Target target, String username) throws GuacamoleException {
        if (isExclusive(target)) {
            long now = System.currentTimeMillis();
            for (ApprovalRequest reservation : approvals.listReservations(target.getId())) {
                if (!reservation.getUsername().equals(username) && reservation.getStarts() <= now)
                    throw new GuacamoleClientException("This is reserved by \"" + reservation.getUsername()
                            + "\" now.");
            }
        }
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
     *
     * @param remoteHost
     *     Where the user releases it from, or null if unknown.
     */
    public void release(UserContext context, String username, String remoteHost, String identifier)
            throws GuacamoleException {

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

        Checkout checkout = checkouts.get(checkoutId);
        if (checkout == null)
            throw new GuacamoleResourceNotFoundException("No such checkout.");
        if (checkout.getReleased() != null)
            throw new GuacamoleClientException("This checkout has already ended.");

        end(checkout, Checkout.REVOKED, administrator, remoteHost);

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

    /**
     * Ends a checkout, recording why, by whom, and from where (or null).
     */
    private void end(Checkout checkout, String releaseReason, String releasedBy, String releasedHost)
            throws GuacamoleException {
        holderCounts = null;
        if (checkouts.release(checkout.getId(), releaseReason, releasedBy, releasedHost)) {
            logger.info("Checkout {} of \"{}\" by user \"{}\" ended: {} by \"{}\".", checkout.getId(),
                    Values.forLog(checkout.getConnectionName()), checkout.getUsername(), releaseReason, releasedBy);
            rotationService.checkoutEnded(checkout);
        }
    }

    /**
     * Loads a connection needing a request, failing the same way whether it
     * does not exist, needs no request, or the user may not read it, so its
     * existence is not revealed.
     */
    private Target requireRequestable(UserContext context, String identifier) throws GuacamoleException {

        Integer id = Values.parseId(identifier);
        if (id == null || context.getConnectionDirectory().get(identifier) == null)
            throw new GuacamoleSecurityException("Permission denied.");

        Target target = connections.load(id);
        if (target == null || !isRequestable(target))
            throw new GuacamoleSecurityException("Permission denied.");

        return target;

    }

    private PasswordRequest toRequest(Target target, Platform platform, String username, boolean administrator)
            throws GuacamoleException {
        int id = target.getId();
        boolean approval = !administrator && getApprovalsRequired(target) > 0;
        return toRequest(target, platform, username, administrator, checkouts.listActive(id),
                approval ? approvals.getPending(id, username) : null,
                approval ? approvals.getLatest(id, username) : null, approvals.listReservations(id));
    }

    /**
     * The connection as shown to the user, given its active checkouts, the
     * user's pending and latest requests for it (or null), and its
     * reservations.
     */
    private PasswordRequest toRequest(Target target, Platform platform, String username, boolean administrator,
            List<Checkout> active, ApprovalRequest pending, ApprovalRequest latest,
            List<ApprovalRequest> reservations) throws GuacamoleException {

        int approvalsRequired = administrator ? 0 : getApprovalsRequired(target);
        boolean account = isAccount(target);

        Checkout own = null;
        for (Checkout checkout : active) {
            if (checkout.getUsername().equals(username))
                own = checkout;
        }

        return new PasswordRequest(Integer.toString(target.getId()), target.getName(),
                account ? accountName(target) : null,
                account ? accountDetail(target, platform) : null,
                account ? Values.trimToNull(target.getParameters().get(AccountProtocol.URL)) : null,
                account ? Values.trimToNull(target.getParameters().get(AccountProtocol.NOTES)) : null,
                isManaged(target), isExclusive(target), getDuration(target), active, username)
            .withAccount(account)
            .withPasswordShown(revealsPassword(target))
            .withBypass(bypassesRequests(administrator))
            .withNoRequest(!requiresRequest(target) || bypassesRequests(administrator))
            .withApproval(approvalsRequired, approvalsRequired > 0 ? pending : null,
                approvalsRequired > 0 ? latest : null)
            .withReservations(reservations, username)
            .withExtensions(getMaxPeriods(target), getExtensionMinutes(target), own,
                own == null ? null : approvals.getLatestExtension(own.getId()));

    }

    /**
     * Whether the user, an administrator or not, connects and checks out
     * without a request.
     */
    private boolean bypassesRequests(boolean administrator) throws GuacamoleException {
        return administrator && settings.isAdminBypassRequests();
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

    /**
     * Whether holders may extend their checkouts of the connection: as it
     * says, or as "pam-extensions-enabled" says.
     */
    private boolean allowsExtensions(Target target) throws GuacamoleException {
        String value = target.getAttribute(PamAttributes.EXTENSIONS);
        if (PamAttributes.EXTENSIONS_YES.equals(value))
            return true;
        if (PamAttributes.EXTENSIONS_NO.equals(value))
            return false;
        return settings.isExtensionsEnabled();
    }

    /**
     * How many times a checkout of the connection may be extended in all: 0
     * if it allows no extensions.
     */
    private int getMaxExtensions(Target target) throws GuacamoleException {
        if (!allowsExtensions(target))
            return 0;
        try {
            return Math.max(0, Math.min(MAX_EXTENSIONS, Integer.parseInt(target.getAttribute(PamAttributes.MAX_EXTENSIONS))));
        }
        catch (NumberFormatException | NullPointerException e) {
            return settings.getMaxExtensions();
        }
    }

    /**
     * How many times its time limit a request for the connection may ask
     * for at once: one more than the extensions it allows.
     */
    private int getMaxPeriods(Target target) throws GuacamoleException {
        return 1 + getMaxExtensions(target);
    }

    /**
     * By how many minutes an extension extends a checkout of the connection.
     */
    private static int getExtensionMinutes(Target target) {
        try {
            int minutes = Integer.parseInt(target.getAttribute(PamAttributes.EXTENSION_DURATION));
            return Math.max(1, Math.min(MAX_MINUTES, minutes));
        }
        catch (NumberFormatException | NullPointerException e) {
            return getDuration(target);
        }
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

}
