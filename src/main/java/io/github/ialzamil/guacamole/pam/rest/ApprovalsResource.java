package io.github.ialzamil.guacamole.pam.rest;

import java.util.Collections;
import java.util.List;
import java.util.Map;

import javax.ws.rs.Consumes;
import javax.ws.rs.GET;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.PathParam;
import javax.ws.rs.Produces;
import javax.ws.rs.QueryParam;
import javax.ws.rs.core.MediaType;

import org.apache.guacamole.GuacamoleException;
import org.apache.guacamole.net.auth.AuthenticatedUser;

import io.github.ialzamil.guacamole.pam.PamAuthenticationProvider;
import io.github.ialzamil.guacamole.pam.approval.ApprovalRequest;
import io.github.ialzamil.guacamole.pam.approval.Approver;

/**
 * Approvals, at "approvals": for approvers, of the connections their
 * permission covers (see {@link io.github.ialzamil.guacamole.pam.approval.ApprovalService}).
 */
@Produces(MediaType.APPLICATION_JSON)
@Consumes(MediaType.APPLICATION_JSON)
public class ApprovalsResource extends PamResource {

    ApprovalsResource(PamAuthenticationProvider provider, AuthenticatedUser user) {
        super(provider, user);
    }

    /**
     * Returns the current user as an approver. Which requests they may see
     * and decide on depends on the approver groups of each connection.
     */
    private Approver approver() throws GuacamoleException {
        return provider.getApprover(user);
    }

    /**
     * Requests awaiting approval that the user may decide on, oldest first.
     */
    @GET
    @Path("pending")
    public List<ApprovalRequest> listPendingApprovals() throws GuacamoleException {
        return provider.getApprovalService().listPending(approver());
    }

    /**
     * Number of requests awaiting a decision of the user, for the badge of
     * approvers: not their own, nor already approved by them. Zero for
     * anyone else.
     */
    @GET
    @Path("count")
    public Map<String, Integer> countPendingApprovals() throws GuacamoleException {
        Approver approver = approver();
        int pending = approver.isApprover() ? provider.getApprovalService().countAwaitingDecision(approver) : 0;
        return Collections.singletonMap("pending", pending);
    }

    /**
     * Decided requests of connections the user may decide on, newest first.
     * Every "contains" term must match the requester, connection, account,
     * reason, outcome, who decided, the reason for a denial, or an approver.
     */
    @GET
    @Path("history")
    public List<ApprovalRequest> searchApprovals(@QueryParam("contains") List<String> contains)
            throws GuacamoleException {
        return provider.getApprovalService().searchDecided(approver(),
                contains == null ? Collections.<String>emptyList() : contains);
    }

    @POST
    @Path("{id}/approve")
    public ApprovalRequest approve(@PathParam("id") String id) throws GuacamoleException {
        return provider.getApprovalService().approve(parseId(id), approver(), remoteHost());
    }

    @POST
    @Path("{id}/deny")
    public void deny(@PathParam("id") String id, Map<String, String> body) throws GuacamoleException {
        provider.getApprovalService().deny(parseId(id), approver(), body == null ? null : body.get("reason"),
                remoteHost());
    }

}
