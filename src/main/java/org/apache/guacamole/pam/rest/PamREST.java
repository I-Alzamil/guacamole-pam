package org.apache.guacamole.pam.rest;

import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import javax.ws.rs.Consumes;
import javax.ws.rs.DELETE;
import javax.ws.rs.GET;
import javax.ws.rs.POST;
import javax.ws.rs.PUT;
import javax.ws.rs.Path;
import javax.ws.rs.PathParam;
import javax.ws.rs.Produces;
import javax.ws.rs.QueryParam;
import javax.ws.rs.core.CacheControl;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;

import org.apache.guacamole.GuacamoleException;
import org.apache.guacamole.GuacamoleResourceNotFoundException;
import org.apache.guacamole.GuacamoleSecurityException;
import org.apache.guacamole.net.auth.AuthenticatedUser;
import org.apache.guacamole.pam.PamAuthenticationProvider;
import org.apache.guacamole.pam.approval.ApprovalRequest;
import org.apache.guacamole.pam.approval.Approver;
import org.apache.guacamole.pam.checkout.Checkout;
import org.apache.guacamole.pam.checkout.RequestOutcome;
import org.apache.guacamole.pam.checkout.PasswordGrant;
import org.apache.guacamole.pam.checkout.PasswordRequest;
import org.apache.guacamole.pam.management.ManagementType;
import org.apache.guacamole.pam.management.ManagementTypes;
import org.apache.guacamole.pam.platform.Platform;
import org.apache.guacamole.pam.ssh.SequenceScript;
import org.apache.guacamole.pam.ssh.ValidationResult;
import org.apache.guacamole.pam.rotation.ManagedConnection;
import org.apache.guacamole.pam.rotation.RotationResult;

/**
 * REST API at "api/session/ext/pam". Requests (for an Account's password,
 * or access to a connection) are available to any user, subject to
 * Guacamole's connection permissions; approvals to approvers, for the
 * connections their permission covers. Platform names and types are readable
 * by any user, so the connection editor can list them. Everything else is
 * limited to administrators.
 */
@Produces(MediaType.APPLICATION_JSON)
@Consumes(MediaType.APPLICATION_JSON)
public class PamREST {

    /**
     * Most checkouts returned by one history search, as for Guacamole's own
     * connection history.
     */
    private static final int CHECKOUT_HISTORY_LIMIT = 1000;

    private final PamAuthenticationProvider provider;

    private final AuthenticatedUser user;

    public PamREST(PamAuthenticationProvider provider, AuthenticatedUser user) {
        this.provider = provider;
        this.user = user;
    }

    private void requireAdministrator() throws GuacamoleException {
        if (!provider.isAdministrator(user))
            throw new GuacamoleSecurityException("Permission denied.");
    }

    /**
     * Whether the current user may manage platforms and rotations, whether
     * they are an approver, and which notification badges they want
     * ("badges", by name).
     */
    @GET
    @Path("access")
    public Map<String, Object> getAccess() throws GuacamoleException {
        Map<String, Object> access = new LinkedHashMap<>();
        access.put("administrator", provider.isAdministrator(user));
        access.put("approver", provider.getApprover(user).isApprover());
        access.put("badges", provider.getBadgePreferences().get(user.getIdentifier()));
        return access;
    }

    /**
     * Turns one notification badge of the current user ("approvals" or
     * "rotations") on or off.
     */
    @PUT
    @Path("preferences/badges/{badge}")
    public void setBadgeShown(@PathParam("badge") String badge, Map<String, Boolean> body)
            throws GuacamoleException {
        provider.getBadgePreferences().set(user.getIdentifier(), badge,
                body == null || !Boolean.FALSE.equals(body.get("shown")));
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
    @Path("approvals/pending")
    public List<ApprovalRequest> listPendingApprovals() throws GuacamoleException {
        return provider.getApprovalService().listPending(approver());
    }

    /**
     * Number of requests awaiting a decision of the user, for the badge of
     * approvers: not their own, nor already approved by them. Zero for
     * anyone else.
     */
    @GET
    @Path("approvals/count")
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
    @Path("approvals/history")
    public List<ApprovalRequest> searchApprovals(@QueryParam("contains") List<String> contains)
            throws GuacamoleException {
        return provider.getApprovalService().searchDecided(approver(),
                contains == null ? Collections.<String>emptyList() : contains);
    }

    @POST
    @Path("approvals/{id}/approve")
    public ApprovalRequest approve(@PathParam("id") String id) throws GuacamoleException {
        return provider.getApprovalService().approve(parseId(id), approver());
    }

    @POST
    @Path("approvals/{id}/deny")
    public void deny(@PathParam("id") String id, Map<String, String> body) throws GuacamoleException {
        provider.getApprovalService().deny(parseId(id), approver(), body == null ? null : body.get("reason"));
    }

    /**
     * The management types platforms can have, with the forms of their
     * settings, so the web UI can render them without knowing each type.
     */
    @GET
    @Path("platform-types")
    public List<Map<String, Object>> listPlatformTypes() throws GuacamoleException {

        List<Map<String, Object>> types = new ArrayList<>();
        for (ManagementType type : ManagementTypes.all()) {
            Map<String, Object> description = new LinkedHashMap<>();
            description.put("name", type.getName());
            description.put("forms", type.getPlatformForms());
            description.put("secretFields", type.getSecretFields());
            types.add(description);
        }

        return types;

    }

    /**
     * All platforms. Any user gets names and types, for the connection
     * editor; administrators also get settings and policy. Secrets are never
     * returned, only which ones are stored.
     */
    @GET
    @Path("platforms")
    public List<Platform> listPlatforms() throws GuacamoleException {
        return provider.getPlatforms().list(provider.isAdministrator(user));
    }

    @GET
    @Path("platforms/{id}")
    public Platform getPlatform(@PathParam("id") String id) throws GuacamoleException {
        requireAdministrator();
        Platform platform = provider.getPlatforms().getWithSecrets(parseId(id));
        if (platform == null)
            throw new GuacamoleResourceNotFoundException("No such platform.");
        return platform;
    }

    @POST
    @Path("platforms")
    public Platform createPlatform(Platform platform) throws GuacamoleException {
        requireAdministrator();
        return provider.getPlatforms().create(platform);
    }

    @PUT
    @Path("platforms/{id}")
    public Platform updatePlatform(@PathParam("id") String id, Platform platform) throws GuacamoleException {
        requireAdministrator();
        return provider.getPlatforms().update(parseId(id), platform);
    }

    @DELETE
    @Path("platforms/{id}")
    public void deletePlatform(@PathParam("id") String id) throws GuacamoleException {
        requireAdministrator();
        provider.getPlatforms().delete(parseId(id));
    }

    /**
     * Parses a sequence script without saving it, for live feedback in the
     * editor of SSH platforms.
     */
    @POST
    @Path("validate")
    public ValidationResult validate(Map<String, String> body) throws GuacamoleException {
        requireAdministrator();
        return new ValidationResult(SequenceScript.parse(body == null ? null : body.get("script")));
    }

    @GET
    @Path("connections")
    public List<ManagedConnection> listConnections() throws GuacamoleException {
        requireAdministrator();
        return provider.getRotationService().listManaged();
    }

    /**
     * Number of managed connections whose last rotation failed or could not
     * be confirmed, for the badge of administrators. Zero for anyone else.
     */
    @GET
    @Path("connections/failures/count")
    public Map<String, Integer> countRotationFailures() throws GuacamoleException {
        int failed = 0;
        if (provider.isAdministrator(user)) {
            for (ManagedConnection connection : provider.getRotationService().listManaged()) {
                if (RotationResult.FAILED.equals(connection.getStatus())
                        || RotationResult.UNKNOWN.equals(connection.getStatus()))
                    failed++;
            }
        }
        return Collections.singletonMap("failed", failed);
    }

    @POST
    @Path("connections/{id}/rotate")
    public RotationResult rotate(@PathParam("id") String id) throws GuacamoleException {
        requireAdministrator();
        return provider.getRotationService().rotateNow(id);
    }

    /**
     * Connections needing a request, and Accounts, that the current user
     * can read.
     */
    @GET
    @Path("requests")
    public List<PasswordRequest> listRequests() throws GuacamoleException {
        return provider.getCheckoutService().listRequests(provider.getDataSourceContext(user), user.getIdentifier(),
                provider.isAdministrator(user));
    }

    @GET
    @Path("requests/{id}")
    public PasswordRequest getRequest(@PathParam("id") String id) throws GuacamoleException {
        return provider.getCheckoutService().getRequest(provider.getDataSourceContext(user), user.getIdentifier(), id,
                provider.isAdministrator(user));
    }

    /**
     * Checks out the password, or shows it again to its current holder. The
     * response must never be cached.
     */
    @POST
    @Path("requests/{id}")
    public Response requestPassword(@PathParam("id") String id, Map<String, String> body)
            throws GuacamoleException {

        RequestOutcome outcome = provider.getCheckoutService().request(provider.getDataSourceContext(user),
                user.getIdentifier(), id, body == null ? null : body.get("reason"), provider.isAdministrator(user));

        // Awaiting approval: no password yet
        if (outcome.getGrant() == null)
            return Response.status(Response.Status.ACCEPTED).entity(outcome.getPending()).build();

        return uncached(outcome.getGrant());

    }

    /**
     * Shows the password of a connection to the holder of its checkout,
     * where the connection allows it. The response must never be cached.
     */
    @POST
    @Path("requests/{id}/password")
    public Response revealPassword(@PathParam("id") String id) throws GuacamoleException {
        return uncached(provider.getCheckoutService().revealPassword(provider.getDataSourceContext(user),
                user.getIdentifier(), id));
    }

    private static Response uncached(PasswordGrant grant) {

        CacheControl noStore = new CacheControl();
        noStore.setNoStore(true);
        noStore.setNoCache(true);
        noStore.setPrivate(true);

        return Response.ok(grant).cacheControl(noStore).header("Pragma", "no-cache").build();

    }

    /**
     * Cancels the user's own request awaiting approval.
     */
    @DELETE
    @Path("requests/{id}/pending")
    public void cancelRequest(@PathParam("id") String id) throws GuacamoleException {
        provider.getCheckoutService().cancelRequest(provider.getDataSourceContext(user), user.getIdentifier(), id);
    }

    @POST
    @Path("requests/{id}/release")
    public void releasePassword(@PathParam("id") String id) throws GuacamoleException {
        provider.getCheckoutService().release(provider.getDataSourceContext(user), user.getIdentifier(), id);
    }

    @GET
    @Path("checkouts/active")
    public List<Checkout> listActiveCheckouts() throws GuacamoleException {
        requireAdministrator();
        return provider.getCheckoutService().listActive();
    }

    /**
     * Searches the checkout history, newest first. Every "contains" term must
     * match the user, connection, reason, or how and by whom it ended.
     */
    @GET
    @Path("checkouts/history")
    public List<Checkout> searchCheckouts(@QueryParam("contains") List<String> contains)
            throws GuacamoleException {
        requireAdministrator();
        return provider.getCheckoutService().search(
                contains == null ? Collections.<String>emptyList() : contains, CHECKOUT_HISTORY_LIMIT);
    }

    @POST
    @Path("checkouts/{id}/revoke")
    public void revokeCheckout(@PathParam("id") String id) throws GuacamoleException {
        requireAdministrator();
        provider.getCheckoutService().revoke(parseId(id), user.getIdentifier());
    }

    private static int parseId(String id) throws GuacamoleResourceNotFoundException {
        try {
            return Integer.parseInt(id);
        }
        catch (NumberFormatException e) {
            throw new GuacamoleResourceNotFoundException("Not found.");
        }
    }

}
