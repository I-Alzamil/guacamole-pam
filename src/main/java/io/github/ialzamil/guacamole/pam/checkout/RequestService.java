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
import io.github.ialzamil.guacamole.pam.platform.Platform;
import io.github.ialzamil.guacamole.pam.platform.PlatformRepository;
import io.github.ialzamil.guacamole.pam.rotation.RotationService;

/**
 * Requests for connections, what users see of them, and the checkouts they
 * lead to. Who may request is decided by Guacamole itself: a user may
 * request any connection they can read, checked through their own
 * UserContext of the managed data source. Connections may require approval:
 * requests then wait for enough distinct approvers, and the checkout starts
 * at the final approval. Those can also be requested ahead of time, for a
 * given start: once approved, the request reserves the connection from then
 * until its time limit, and the requester checks out with it during that
 * time. Reservations of a connection checked out alone never overlap, and
 * keep others from checking it out during them. Holders may ask to extend
 * their checkouts, with the same approvals, where the connection allows it
 * (see {@link CheckoutRules}).
 */
public class RequestService {

    private static final Logger logger = LoggerFactory.getLogger(RequestService.class);

    private final ConnectionRepository connections;

    private final PlatformRepository platforms;

    private final CheckoutRepository checkouts;

    private final ApprovalRepository approvals;

    private final RotationService rotationService;

    private final CheckoutService checkoutService;

    private final CheckoutRules rules;

    public RequestService(ConnectionRepository connections, PlatformRepository platforms,
            CheckoutRepository checkouts, ApprovalRepository approvals, RotationService rotationService,
            CheckoutService checkoutService) {
        this.connections = connections;
        this.platforms = platforms;
        this.checkouts = checkouts;
        this.approvals = approvals;
        this.rotationService = rotationService;
        this.checkoutService = checkoutService;
        this.rules = checkoutService.getRules();
    }

    /**
     * Refuses a change while this server is on standby (see
     * {@link RotationService#requireActive}).
     */
    public void requireActive() throws GuacamoleClientException {
        rotationService.requireActive();
    }

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
     * Parameters of Account connections safe to read when listing requests;
     * secrets are excluded. Other connections expose no parameters at all.
     */
    private static final List<String> PUBLIC_PARAMETERS = Arrays.asList(
            AccountProtocol.USERNAME, AccountProtocol.URL, AccountProtocol.NOTES);

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
            if (CheckoutRules.isRequestable(target) && readable.contains(Integer.toString(id)))
                requests.add(toRequest(target, all.get(target.getAttribute(PamAttributes.PLATFORM)), username,
                        administrator, active.getOrDefault(id, Collections.<Checkout>emptyList()),
                        pending.get(id), latest.get(id),
                        reservations.getOrDefault(id, Collections.<ApprovalRequest>emptyList())));
        }

        return requests;

    }

    public PasswordRequest getRequest(UserContext context, String username, String identifier,
            boolean administrator) throws GuacamoleException {
        Target target = checkoutService.requireRequestable(context, identifier);
        return toRequest(target, rules.platformOf(target), username, administrator);
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

        rotationService.requireActive();
        Target target = checkoutService.requireRequestable(context, identifier);
        int id = target.getId();

        int maxPeriods = rules.getMaxPeriods(target);
        if (periods < 1 || periods > maxPeriods)
            throw new GuacamoleClientException(maxPeriods == 1
                    ? "This access cannot be asked for longer than its time limit."
                    : "This access can be asked for up to " + maxPeriods + " times its time limit.");

        // Expired checkouts not ended yet would refuse the request
        rotationService.expireCheckouts();

        if (CheckoutRules.isAccount(target)) {
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

        int approvalsRequired = administrator ? 0 : CheckoutRules.getApprovalsRequired(target);
        if (starts != null && approvalsRequired == 0)
            throw new GuacamoleClientException("Only access needing approval is requested ahead of time.");
        if (administrator && CheckoutRules.getApprovalsRequired(target) > 0)
            logger.info("Administrator \"{}\" bypasses the approval of \"{}\".", username,
                    Values.forLog(target.getName()));

        if (approvalsRequired > 0) {
            if (approvals.getPending(id, username) == null)
                askApproval(target, username, remoteHost, reason, approvalsRequired, starts, periods);
            return RequestOutcome.pending(toRequest(target, rules.platformOf(target), username, administrator));
        }

        return checkOutNow(target, username, remoteHost, reason, periods, administrator);

    }

    /**
     * The user's own active checkout, shown again: an Account's password
     * again, which is recorded.
     */
    private RequestOutcome showAgain(Target target, String username, Checkout checkout) throws GuacamoleException {
        if (CheckoutRules.isAccount(target)) {
            if (!checkouts.recordReveal(checkout.getId()))
                throw new GuacamoleClientException("This checkout has ended.");
            logger.info("User \"{}\" viewed the password of \"{}\" (checkout {}).",
                    username, Values.forLog(target.getName()), checkout.getId());
        }
        return RequestOutcome.granted(checkoutService.toGrant(checkout, target));
    }

    /**
     * Starts the checkout of the user's reservation, which started: until
     * it ends, with its reason.
     */
    private RequestOutcome useReservation(Target target, String username, String remoteHost,
            ApprovalRequest reservation) throws GuacamoleException {
        Checkout checkout = checkoutService.startCheckout(target, username, remoteHost, reservation.getReason(),
                CheckoutRules.isAccount(target) ? 1 : 0, reservation.getEnds(), reservation.getPeriods());
        approvals.markUsed(reservation.getId(), checkout.getId());
        logger.info("User \"{}\" used request {} for \"{}\" (checkout {}).", username, reservation.getId(),
                Values.forLog(target.getName()), checkout.getId());
        return RequestOutcome.granted(checkoutService.toGrant(checkout, connections.load(target.getId())));
    }

    /**
     * Asks for approval of access now, if the connection could be held now,
     * or from a start ahead of time.
     */
    private void askApproval(Target target, String username, String remoteHost, String reason,
            int approvalsRequired, Long starts, int periods) throws GuacamoleException {

        String trimmed = CheckoutRules.validateReason(reason);
        Long ends = null;
        String when = "";
        if (starts == null)
            requireAvailable(target, username);
        else {
            CheckoutRules.validateStart(starts);
            long end = starts + CheckoutRules.getDuration(target) * 60000L * periods;
            ends = end;
            when = ", from " + Instant.ofEpochMilli(starts) + " to " + Instant.ofEpochMilli(end);
        }

        ApprovalRequest pending = approvals.create(target.getId(), username, remoteHost, trimmed, approvalsRequired,
                starts, ends, CheckoutRules.isExclusive(target), periods);
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
        if (!CheckoutRules.requiresRequest(target))
            checkoutReason = NO_REQUEST_REASON;
        else if (rules.bypassesRequests(administrator)) {
            checkoutReason = ADMIN_BYPASS_REASON;
            logger.info("Administrator \"{}\" checks out \"{}\" without a request.", username,
                    Values.forLog(target.getName()));
        }
        else
            checkoutReason = CheckoutRules.validateReason(reason);

        Checkout checkout = checkoutService.startCheckout(target, username, remoteHost, checkoutReason, CheckoutRules.isAccount(target) ? 1 : 0,
                null, periods);
        return RequestOutcome.granted(checkoutService.toGrant(checkout, connections.load(target.getId())));

    }

    /**
     * Starts the checkout of an approved request. The requester sees the
     * password, or connects, by opening the connection again.
     */
    public Checkout startApprovedCheckout(ApprovalRequest request) throws GuacamoleException {
        rotationService.requireActive();
        Integer id = Values.parseId(request.getConnectionIdentifier());
        Target target = id == null ? null : connections.load(id);
        if (target == null)
            throw new GuacamoleResourceNotFoundException("The connection no longer exists.");
        rotationService.expireCheckouts();
        return checkoutService.startCheckout(target, request.getUsername(), request.getRemoteHost(), request.getReason(), 0, null,
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
        rotationService.requireActive();
        Integer id = Values.parseId(request.getConnectionIdentifier());
        Target target = id == null ? null : connections.load(id);
        if (target == null)
            throw new GuacamoleResourceNotFoundException("The connection no longer exists.");
        rotationService.expireCheckouts();
        for (Integer rejected : approvals.markReserved(request, approver, CheckoutRules.isExclusive(target)))
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

        rotationService.requireActive();
        Target target = checkoutService.requireRequestable(context, identifier);
        if (!rules.allowsExtensions(target))
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
            trimmed = CheckoutRules.validateReason(reason);
        else if (!CheckoutRules.requiresRequest(target))
            trimmed = NO_REQUEST_REASON;
        else if (rules.bypassesRequests(administrator))
            trimmed = ADMIN_BYPASS_REASON;
        else
            trimmed = CheckoutRules.validateReason(reason);
        int approvalsRequired = administrator ? 0 : CheckoutRules.getApprovalsRequired(target);
        int minutes = CheckoutRules.getExtensionMinutes(target);

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

        return toRequest(target, rules.platformOf(target), username, administrator);

    }

    /**
     * Grants an extension once approved, extending its checkout.
     *
     * @throws GuacamoleClientException
     *     If the checkout ended, cannot be extended any more, or someone
     *     else's reservation starts as it ends.
     */
    public Checkout grantExtension(ApprovalRequest request, String approver) throws GuacamoleException {
        rotationService.requireActive();
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

        rotationService.requireActive();
        Target target = checkoutService.requireRequestable(context, identifier);
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

        rotationService.requireActive();
        Target target = checkoutService.requireRequestable(context, identifier);
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

        rotationService.requireActive();
        Target target = checkoutService.requireRequestable(context, identifier);
        ApprovalRequest reservation = approvals.getReservation(target.getId(), username);
        if (reservation == null)
            throw new GuacamoleClientException("You have no approved access to this ahead.");

        approvals.cancelReservation(reservation.getId(), username, remoteHost);
        logger.info("User \"{}\" cancelled their reservation {} of \"{}\".", username, reservation.getId(),
                Values.forLog(target.getName()));

    }

    /**
     * Refuses a request that could not be granted anyway because someone
     * holds the connection exclusively, or an exclusive checkout is wanted
     * while anyone holds it, or while someone else's reservation lasts.
     */
    private void requireAvailable(Target target, String username) throws GuacamoleException {
        if (CheckoutRules.isExclusive(target)) {
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
            if (CheckoutRules.isExclusive(target))
                throw new GuacamoleClientException("This is in use by \""
                        + active.getUsername() + "\" and can only be held by one user at a time.");
        }
    }

    private PasswordRequest toRequest(Target target, Platform platform, String username, boolean administrator)
            throws GuacamoleException {
        int id = target.getId();
        boolean approval = !administrator && CheckoutRules.getApprovalsRequired(target) > 0;
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

        int approvalsRequired = administrator ? 0 : CheckoutRules.getApprovalsRequired(target);
        boolean account = CheckoutRules.isAccount(target);

        Checkout own = null;
        for (Checkout checkout : active) {
            if (checkout.getUsername().equals(username))
                own = checkout;
        }

        return new PasswordRequest(Integer.toString(target.getId()), target.getName(),
                account ? CheckoutRules.accountName(target) : null,
                account ? CheckoutRules.accountDetail(target, platform) : null,
                account ? Values.trimToNull(target.getParameters().get(AccountProtocol.URL)) : null,
                account ? Values.trimToNull(target.getParameters().get(AccountProtocol.NOTES)) : null,
                CheckoutRules.isManaged(target), CheckoutRules.isExclusive(target), CheckoutRules.getDuration(target), active, username)
            .withAccount(account)
            .withPasswordShown(CheckoutRules.revealsPassword(target))
            .withBypass(rules.bypassesRequests(administrator))
            .withNoRequest(!CheckoutRules.requiresRequest(target) || rules.bypassesRequests(administrator))
            .withApproval(approvalsRequired, approvalsRequired > 0 ? pending : null,
                approvalsRequired > 0 ? latest : null)
            .withReservations(reservations, username)
            .withExtensions(rules.getMaxPeriods(target), CheckoutRules.getExtensionMinutes(target), own,
                own == null ? null : approvals.getLatestExtension(own.getId()));

    }

}
