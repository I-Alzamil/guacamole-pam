package io.github.ialzamil.guacamole.pam.rest;

import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import javax.ws.rs.Consumes;
import javax.ws.rs.GET;
import javax.ws.rs.POST;
import javax.ws.rs.PUT;
import javax.ws.rs.Path;
import javax.ws.rs.PathParam;
import javax.ws.rs.Produces;
import javax.ws.rs.core.MediaType;

import org.apache.guacamole.GuacamoleException;
import org.apache.guacamole.net.auth.AuthenticatedUser;

import io.github.ialzamil.guacamole.pam.PamAuthenticationProvider;
import io.github.ialzamil.guacamole.pam.ha.HaAuthenticationProvider;
import io.github.ialzamil.guacamole.pam.management.ManagementType;
import io.github.ialzamil.guacamole.pam.management.ManagementTypes;
import io.github.ialzamil.guacamole.pam.notification.email.EmailSettings;
import io.github.ialzamil.guacamole.pam.ssh.SequenceScript;
import io.github.ialzamil.guacamole.pam.ssh.ValidationResult;

/**
 * REST API at "api/session/ext/pam". Requests (for an Account's password,
 * or access to a connection) are available to any user, subject to
 * Guacamole's connection permissions; approvals to approvers, for the
 * connections their permission covers. Platform and password policy names
 * are readable by any user, so the connection editor can list them.
 * Everything else is limited to administrators.
 *
 * Each part of the API has its own class, reached through the paths below;
 * this class answers what concerns the user and the extension as a whole.
 */
@Produces(MediaType.APPLICATION_JSON)
@Consumes(MediaType.APPLICATION_JSON)
public class PamREST extends PamResource {

    public PamREST(PamAuthenticationProvider provider, AuthenticatedUser user) {
        super(provider, user);
    }

    @Path("platforms")
    public PlatformsResource platforms() {
        return new PlatformsResource(provider, user);
    }

    @Path("password-policies")
    public PasswordPoliciesResource passwordPolicies() {
        return new PasswordPoliciesResource(provider, user);
    }

    @Path("connections")
    public RotationResource rotation() {
        return new RotationResource(provider, user);
    }

    @Path("requests")
    public RequestsResource requests() {
        return new RequestsResource(provider, user);
    }

    @Path("approvals")
    public ApprovalsResource approvals() {
        return new ApprovalsResource(provider, user);
    }

    @Path("checkouts")
    public CheckoutsResource checkouts() {
        return new CheckoutsResource(provider, user);
    }

    @Path("settings")
    public SettingsResource settings() {
        return new SettingsResource(provider, user);
    }

    @Path("email-languages")
    public EmailLanguagesResource emailLanguages() {
        return new EmailLanguagesResource(provider, user);
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
     * they are an approver, which notification badges they want ("badges",
     * by name), whether the HA module runs ("ha"), and their emails
     * ("emails": whether emails are sent at all, to which address, which
     * kinds they want, by name, the language they chose, or null for the
     * default one, and the languages offered, with their names).
     */
    @GET
    @Path("access")
    public Map<String, Object> getAccess() throws GuacamoleException {
        Map<String, Object> access = new LinkedHashMap<>();
        access.put("administrator", isAdministrator());
        access.put("approver", provider.getApprover(user).isApprover());
        access.put("badges", provider.getBadgePreferences().get(username()));
        access.put("ha", HaAuthenticationProvider.isEnabled());

        Map<String, Object> emails = new LinkedHashMap<>();
        emails.put("enabled", provider.getSettings().get(EmailSettings.ENABLED));
        emails.put("address", provider.getEmailDirectory().getAddresses(Collections.singleton(username()))
                .get(username()));
        emails.put("wanted", provider.getEmailPreferences().get(username()));
        emails.put("language", provider.getEmailPreferences().getLanguage(username()));
        emails.put("defaultLanguage", provider.getSettings().get(EmailSettings.LANGUAGE));
        emails.put("languages", provider.getEmailLanguages().getNames());
        access.put("emails", emails);
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
     * Turns one kind of email of the current user ("everything", "approvals"
     * or "own") on or off.
     */
    @PUT
    @Path("preferences/emails/{kind}")
    public void setEmailWanted(@PathParam("kind") String kind, Map<String, Boolean> body)
            throws GuacamoleException {
        provider.getEmailPreferences().set(username(), kind,
                body == null || !Boolean.FALSE.equals(body.get("wanted")));
    }

    /**
     * Sets the language of the current user's emails ("language", such as
     * "ar"), or the default one for null.
     */
    @PUT
    @Path("preferences/email-language")
    public void setEmailLanguage(Map<String, String> body) throws GuacamoleException {
        provider.getEmailPreferences().setLanguage(username(), body == null ? null : body.get("language"));
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
     * Parses a sequence script without saving it, for live feedback in the
     * editor of SSH platforms.
     */
    @POST
    @Path("validate")
    public ValidationResult validate(Map<String, String> body) throws GuacamoleException {
        requireAdministrator();
        return new ValidationResult(SequenceScript.parse(body == null ? null : body.get("script")));
    }

}
