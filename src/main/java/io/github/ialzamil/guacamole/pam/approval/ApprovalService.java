package io.github.ialzamil.guacamole.pam.approval;

import java.util.ArrayList;
import java.util.List;

import org.apache.guacamole.GuacamoleClientException;
import org.apache.guacamole.GuacamoleException;
import org.apache.guacamole.GuacamoleResourceNotFoundException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import io.github.ialzamil.guacamole.pam.Values;
import io.github.ialzamil.guacamole.pam.checkout.Checkout;
import io.github.ialzamil.guacamole.pam.checkout.RequestService;

/**
 * Decisions on requests by approvers: users whose approval
 * permission, of their own or of one of their groups, covers the request's
 * connection. Administrators may decide on any. A request needs as many
 * distinct approvers as its connection requires, none of them the requester; a
 * single denial rejects it. The final approval starts the checkout or, for a
 * request made ahead of time, reserves the connection for it; for a request
 * to extend a checkout, it extends it.
 */
public class ApprovalService {

    private static final Logger logger = LoggerFactory.getLogger(ApprovalService.class);

    /**
     * Most decided requests a history search returns.
     */
    private static final int HISTORY_LIMIT = 1000;

    private final ApprovalRepository approvals;

    private final RequestService requestService;

    public ApprovalService(ApprovalRepository approvals, RequestService requestService) {
        this.approvals = approvals;
        this.requestService = requestService;
    }

    /**
     * Requests awaiting approval that the approver may decide on.
     */
    public List<ApprovalRequest> listPending(Approver approver) throws GuacamoleException {
        return visibleTo(approver, approvals.listPending());
    }

    /**
     * Number of requests awaiting a decision of the approver: pending
     * requests they may decide on, except their own and those they already
     * approved.
     */
    public int countAwaitingDecision(Approver approver) throws GuacamoleException {
        int count = 0;
        for (ApprovalRequest request : listPending(approver)) {
            if (!request.getUsername().equals(approver.getUsername())
                    && !request.getApprovers().contains(approver.getUsername()))
                count++;
        }
        return count;
    }

    /**
     * Searches decided requests of connections the approver may decide on,
     * most recently decided first.
     */
    public List<ApprovalRequest> searchDecided(Approver approver, List<String> terms) throws GuacamoleException {
        return approvals.searchDecided(terms, HISTORY_LIMIT,
                approver.isAdministrator() ? null : approver.getConnections());
    }

    /**
     * Approves a request. If this is the last approval needed, the
     * requester's checkout starts now, or the connection is reserved for
     * the time they asked for.
     *
     * @param remoteHost
     *     Where the approver decides from, kept with the decision, or null
     *     if unknown.
     *
     * @throws GuacamoleClientException
     *     If the request is the approver's own, or cannot be approved now.
     */
    public ApprovalRequest approve(int requestId, Approver approver, String remoteHost) throws GuacamoleException {

        requestService.requireActive();
        ApprovalRequest pending = requireQualified(requestId, approver);
        if (pending.getUsername().equals(approver.getUsername()))
            throw new GuacamoleClientException("You cannot approve your own request.");

        ApprovalRequest request = approvals.approve(requestId, approver.getUsername(), remoteHost);
        logger.info("User \"{}\" approved request {} of \"{}\" for \"{}\" ({}/{}).", approver.getUsername(),
                requestId, request.getUsername(), Values.forLog(request.getConnectionName()),
                request.getApprovers().size(), request.getApprovalsRequired());

        if (request.getApprovers().size() < request.getApprovalsRequired())
            return request;

        // Another approver completing it at the same time does the rest;
        // this approval stays
        if (!approvals.claimCompletion(requestId, approver.getUsername()))
            return approvals.get(requestId);

        Checkout checkout = null;
        try {
            if (request.getExtendsCheckout() != null)
                checkout = requestService.grantExtension(request, approver.getUsername());
            else if (request.getStarts() == null)
                checkout = requestService.startApprovedCheckout(request);
            else
                requestService.reserve(request, approver.getUsername());
        }
        catch (GuacamoleClientException e) {
            approvals.releaseCompletion(requestId, approver.getUsername());
            approvals.withdrawApproval(requestId, approver.getUsername());
            throw new GuacamoleClientException((request.getExtendsCheckout() != null ? "The checkout cannot be extended: "
                    : request.getStarts() != null ? "The access cannot be reserved: "
                    : "The checkout cannot start now: ") + e.getMessage());
        }
        catch (GuacamoleException e) {
            approvals.releaseCompletion(requestId, approver.getUsername());
            throw e;
        }

        if (checkout != null)
            approvals.markApproved(requestId, checkout.getId(), approver.getUsername());
        return approvals.get(requestId);

    }

    /**
     * Longest reason for a denial, as for requests.
     */
    private static final int MAX_REASON_LENGTH = 500;

    /**
     * Denies a request, with the reason shown to its requester. One denial
     * is enough to reject it.
     *
     * @param remoteHost
     *     Where the approver decides from, kept with the decision, or null
     *     if unknown.
     *
     * @throws GuacamoleClientException
     *     If the reason is missing or too long.
     */
    public void deny(int requestId, Approver approver, String reason, String remoteHost) throws GuacamoleException {

        requestService.requireActive();
        String trimmed = reason == null ? "" : reason.trim();
        if (trimmed.isEmpty())
            throw new GuacamoleClientException("Please give a reason for the denial.");
        if (trimmed.length() > MAX_REASON_LENGTH)
            throw new GuacamoleClientException("The reason is limited to " + MAX_REASON_LENGTH + " characters.");

        ApprovalRequest request = requireQualified(requestId, approver);
        if (request.getUsername().equals(approver.getUsername()))
            throw new GuacamoleClientException("You cannot decide on your own request. Cancel it instead.");

        approvals.decide(requestId, ApprovalRequest.DENIED, approver.getUsername(), remoteHost, trimmed);
        logger.info("User \"{}\" denied request {} of \"{}\" for \"{}\".", approver.getUsername(), requestId,
                request.getUsername(), Values.forLog(request.getConnectionName()));

    }

    /**
     * Loads a request, refusing approvers not qualified for its connection
     * the same way as a missing request, so they learn nothing about it.
     */
    private ApprovalRequest requireQualified(int requestId, Approver approver) throws GuacamoleException {

        ApprovalRequest request = approvals.get(requestId);
        if (request == null || !approver.qualifiesFor(request.getConnectionIdentifier()))
            throw new GuacamoleResourceNotFoundException("No such request.");

        return request;

    }

    /**
     * Keeps the requests of connections the approver may decide on.
     */
    private static List<ApprovalRequest> visibleTo(Approver approver, List<ApprovalRequest> requests) {
        List<ApprovalRequest> visible = new ArrayList<>();
        for (ApprovalRequest request : requests) {
            if (approver.qualifiesFor(request.getConnectionIdentifier()))
                visible.add(request);
        }
        return visible;
    }

}
