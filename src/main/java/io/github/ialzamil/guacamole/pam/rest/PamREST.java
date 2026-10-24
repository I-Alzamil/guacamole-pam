package io.github.ialzamil.guacamole.pam.rest;

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

import org.apache.guacamole.GuacamoleClientException;
import org.apache.guacamole.GuacamoleException;
import org.apache.guacamole.GuacamoleResourceNotFoundException;
import org.apache.guacamole.GuacamoleSecurityException;
import org.apache.guacamole.net.auth.AuthenticatedUser;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import io.github.ialzamil.guacamole.pam.PamAuthenticationProvider;
import io.github.ialzamil.guacamole.pam.Values;
import io.github.ialzamil.guacamole.pam.approval.ApprovalRequest;
import io.github.ialzamil.guacamole.pam.approval.Approver;
import io.github.ialzamil.guacamole.pam.checkout.Checkout;
import io.github.ialzamil.guacamole.pam.checkout.PasswordGrant;
import io.github.ialzamil.guacamole.pam.checkout.PasswordRequest;
import io.github.ialzamil.guacamole.pam.checkout.RequestOutcome;
import io.github.ialzamil.guacamole.pam.management.ManagementType;
import io.github.ialzamil.guacamole.pam.management.ManagementTypes;
import io.github.ialzamil.guacamole.pam.management.PlatformTestResult;
import io.github.ialzamil.guacamole.pam.password.PasswordGenerator;
import io.github.ialzamil.guacamole.pam.password.PasswordPolicy;
import io.github.ialzamil.guacamole.pam.password.PasswordRules;
import io.github.ialzamil.guacamole.pam.platform.Platform;
import io.github.ialzamil.guacamole.pam.platform.PlatformImport;
import io.github.ialzamil.guacamole.pam.rotation.ManagedConnection;
import io.github.ialzamil.guacamole.pam.rotation.RotationResult;
import io.github.ialzamil.guacamole.pam.settings.PamSettings;
import io.github.ialzamil.guacamole.pam.ssh.SequenceScript;
import io.github.ialzamil.guacamole.pam.ssh.ValidationResult;

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

    private static final Logger logger = LoggerFactory.getLogger(PamREST.class);

    /**
     * Most checkouts returned by one history search, as for Guacamole's own
     * connection history.
     */
    private static final int CHECKOUT_HISTORY_LIMIT = 1000;

    /**
     * How many example passwords the password policy editor shows.
     */
    private static final int EXAMPLE_PASSWORDS = 3;

    private final PasswordGenerator passwordGenerator = new PasswordGenerator();

    private final PamAuthenticationProvider provider;

    private final AuthenticatedUser user;

    public PamREST(PamAuthenticationProvider provider, AuthenticatedUser user) {
        this.provider = provider;
        this.user = user;
    }

    /**
     * The current user's username in the managed data source (see
     * {@link PamAuthenticationProvider#getUsername}).
     */
    private String username() throws GuacamoleException {
        return provider.getUsername(user);
    }

    private void requireAdministrator() throws GuacamoleException {
        if (!provider.isAdministrator(user))
            throw new GuacamoleSecurityException("Permission denied.");
    }

    /**
     * Identifier of the data source whose connections are managed
     * ("identifier"), such as "mysql".
     */
    @GET
    @Path("data-source")
    public Map<String, String> getDataSource() {
        return Collections.singletonMap("identifier", provider.getManagedDataSource());
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
        access.put("badges", provider.getBadgePreferences().get(username()));
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
        provider.getBadgePreferences().set(username(), badge,
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
     * The settings shared by every server.
     */
    @GET
    @Path("settings")
    public List<PamSettings.Entry> getSettings() throws GuacamoleException {
        requireAdministrator();
        return provider.getSettings().list();
    }

    /**
     * Changes shared settings, all or none: each by name, to a value, or to
     * null for its default. Returns the settings as then.
     */
    @PUT
    @Path("settings")
    public List<PamSettings.Entry> updateSettings(Map<String, Object> values) throws GuacamoleException {
        requireAdministrator();
        provider.getSettings().update(values, username());
        return getSettings();
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
        return provider.getApprovalService().approve(parseId(id), approver(), remoteHost());
    }

    @POST
    @Path("approvals/{id}/deny")
    public void deny(@PathParam("id") String id, Map<String, String> body) throws GuacamoleException {
        provider.getApprovalService().deny(parseId(id), approver(), body == null ? null : body.get("reason"),
                remoteHost());
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
            description.put("testable", type.isTestable());
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

    /**
     * Imports platforms, all or none: those named as existing ones fail the
     * import unless asked to update them.
     */
    @POST
    @Path("platforms/import")
    public PlatformImport.Report importPlatforms(PlatformImport.Request request) throws GuacamoleException {
        requireAdministrator();
        if (request == null)
            throw new GuacamoleClientException("There is no platform to import.");
        return provider.getPlatformImport().run(request.getPlatforms(),
                request.isUpdate() ? PlatformImport.Existing.UPDATE : PlatformImport.Existing.REFUSE);
    }

    /**
     * Adds back the default platforms missing by name, leaving those that
     * exist as they are.
     */
    @POST
    @Path("platforms/defaults")
    public PlatformImport.Report restoreDefaultPlatforms() throws GuacamoleException {
        requireAdministrator();
        return provider.getPlatformImport().restoreDefaults();
    }

    /**
     * Tests a platform as edited, saved or not, changing nothing. Its
     * secrets left empty are those stored, as when saving.
     */
    @POST
    @Path("platforms/test")
    public PlatformTestResult testPlatform(Platform platform) throws GuacamoleException {

        requireAdministrator();
        Platform prepared = provider.getPlatforms().prepare(platform);
        ManagementType type = ManagementTypes.get(prepared.getType());
        if (type == null || !type.isTestable())
            throw new GuacamoleClientException("Platforms of this type cannot be tested.");

        PlatformTestResult result = type.test(prepared);
        logger.info("User \"{}\" tested platform \"{}\": {}.", username(), Values.forLog(prepared.getName()),
                result.isSuccess() ? "passed" : "failed");
        return result;

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
     * All password policies. Any user gets names, for the connection editor;
     * administrators also get rules, and what uses each.
     */
    @GET
    @Path("password-policies")
    public List<PasswordPolicy> listPasswordPolicies() throws GuacamoleException {
        List<PasswordPolicy> policies = provider.getPasswordPolicies().list();
        if (!provider.isAdministrator(user)) {
            for (PasswordPolicy policy : policies) {
                policy.setRules(null);
                policy.setPlatforms(null);
                policy.setConnections(null);
                policy.setDescription(null);
            }
        }
        return policies;
    }

    /**
     * The rules of passwords without a password policy, as the editor shows
     * them.
     */
    @GET
    @Path("password-policies/default")
    public PasswordRules getDefaultPasswordRules() throws GuacamoleException {
        requireAdministrator();
        return PasswordRules.defaults().validate();
    }

    @POST
    @Path("password-policies")
    public PasswordPolicy createPasswordPolicy(PasswordPolicy policy) throws GuacamoleException {
        requireAdministrator();
        PasswordPolicy created = provider.getPasswordPolicies().create(policy);
        logger.info("User \"{}\" created password policy \"{}\".", username(), Values.forLog(created.getName()));
        return created;
    }

    @PUT
    @Path("password-policies/{id}")
    public PasswordPolicy updatePasswordPolicy(@PathParam("id") String id, PasswordPolicy policy)
            throws GuacamoleException {
        requireAdministrator();
        PasswordPolicy updated = provider.getPasswordPolicies().update(parseId(id), policy);
        logger.info("User \"{}\" updated password policy \"{}\".", username(), Values.forLog(updated.getName()));
        return updated;
    }

    @DELETE
    @Path("password-policies/{id}")
    public void deletePasswordPolicy(@PathParam("id") String id) throws GuacamoleException {
        requireAdministrator();
        PasswordPolicy policy = provider.getPasswordPolicies().get(parseId(id));
        if (policy == null)
            throw new GuacamoleResourceNotFoundException("No such password policy.");
        provider.getPasswordPolicies().delete(policy.getId());
        logger.info("User \"{}\" deleted password policy \"{}\".", username(), Values.forLog(policy.getName()));
    }

    /**
     * Examples of passwords the given rules make, saved or not, and their
     * strength: bits of randomness, from how many characters each is drawn
     * from.
     */
    @POST
    @Path("password-policies/examples")
    public Map<String, Object> examplePasswords(PasswordRules rules) throws GuacamoleException {
        requireAdministrator();
        if (rules == null)
            throw new GuacamoleClientException("There are no rules.");
        rules.validate();
        List<String> examples = new ArrayList<>();
        for (int i = 0; i < EXAMPLE_PASSWORDS; i++)
            examples.add(passwordGenerator.generate(rules));
        Map<String, Object> result = new LinkedHashMap<>();
        result.put("examples", examples);
        result.put("bits", PasswordGenerator.strengthBits(rules));
        return result;
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
        return provider.getCheckoutService().listRequests(provider.getDataSourceContext(user), username(),
                provider.isAdministrator(user));
    }

    @GET
    @Path("requests/{id}")
    public PasswordRequest getRequest(@PathParam("id") String id) throws GuacamoleException {
        return provider.getCheckoutService().getRequest(provider.getDataSourceContext(user), username(), id,
                provider.isAdministrator(user));
    }

    /**
     * Checks out the password, or shows it again to its current holder. The
     * body gives the "reason", "starts" (milliseconds since the epoch) for
     * access requested ahead of time, and "periods" for access lasting more
     * than one time limit. The response must never be cached.
     */
    @POST
    @Path("requests/{id}")
    public Response requestPassword(@PathParam("id") String id, Map<String, String> body)
            throws GuacamoleException {

        Long starts = null;
        String start = body == null ? null : Values.trimToNull(body.get("starts"));
        if (start != null) {
            try {
                starts = Long.valueOf(start);
            }
            catch (NumberFormatException e) {
                throw new GuacamoleClientException("Invalid start.");
            }
        }

        int periods = 1;
        String period = body == null ? null : Values.trimToNull(body.get("periods"));
        if (period != null) {
            try {
                periods = Integer.parseInt(period);
            }
            catch (NumberFormatException e) {
                throw new GuacamoleClientException("Invalid duration.");
            }
        }

        RequestOutcome outcome = provider.getCheckoutService().request(provider.getDataSourceContext(user),
                username(), remoteHost(), id, body == null ? null : body.get("reason"), starts, periods,
                provider.isAdministrator(user));

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
                username(), id));
    }

    /**
     * Where the user is, as Guacamole's connection history records it: the
     * address they logged in from.
     */
    private String remoteHost() {
        return user.getCredentials() == null ? null : user.getCredentials().getRemoteAddress();
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
        provider.getCheckoutService().cancelRequest(provider.getDataSourceContext(user), username(), remoteHost(), id);
    }

    /**
     * Cancels the user's own next reservation, approved but not used yet.
     */
    @DELETE
    @Path("requests/{id}/reservation")
    public void cancelReservation(@PathParam("id") String id) throws GuacamoleException {
        provider.getCheckoutService().cancelReservation(provider.getDataSourceContext(user), username(),
                remoteHost(), id);
    }

    /**
     * Extends the user's checkout, or asks for it to be extended where
     * approval is needed. The body gives the "reason".
     */
    @POST
    @Path("requests/{id}/extension")
    public PasswordRequest extend(@PathParam("id") String id, Map<String, String> body) throws GuacamoleException {
        return provider.getCheckoutService().extend(provider.getDataSourceContext(user), username(), remoteHost(), id,
                body == null ? null : body.get("reason"), provider.isAdministrator(user));
    }

    /**
     * Cancels the user's request to extend their checkout, awaiting approval.
     */
    @DELETE
    @Path("requests/{id}/extension")
    public void cancelExtension(@PathParam("id") String id) throws GuacamoleException {
        provider.getCheckoutService().cancelExtension(provider.getDataSourceContext(user), username(), remoteHost(),
                id);
    }

    @POST
    @Path("requests/{id}/release")
    public void releasePassword(@PathParam("id") String id) throws GuacamoleException {
        provider.getCheckoutService().release(provider.getDataSourceContext(user), username(), remoteHost(), id);
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
        provider.getCheckoutService().revoke(parseId(id), username(), remoteHost());
    }

    private static int parseId(String id) throws GuacamoleResourceNotFoundException {
        Integer parsed = Values.parseId(id);
        if (parsed == null)
            throw new GuacamoleResourceNotFoundException("Not found.");
        return parsed;
    }

}
