package io.github.ialzamil.guacamole.pam.rest;

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
import org.apache.guacamole.GuacamoleResourceNotFoundException;
import org.apache.guacamole.net.auth.AuthenticatedUser;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import io.github.ialzamil.guacamole.pam.PamAuthenticationProvider;
import io.github.ialzamil.guacamole.pam.Values;
import io.github.ialzamil.guacamole.pam.coordination.Standby;
import io.github.ialzamil.guacamole.pam.ha.HaAuthenticationProvider;
import io.github.ialzamil.guacamole.pam.settings.PamSettings;

/**
 * The settings shared by every server, at "settings": administrators only.
 */
@Produces(MediaType.APPLICATION_JSON)
@Consumes(MediaType.APPLICATION_JSON)
public class SettingsResource extends PamResource {

    private static final Logger logger = LoggerFactory.getLogger(SettingsResource.class);

    SettingsResource(PamAuthenticationProvider provider, AuthenticatedUser user) {
        super(provider, user);
    }

    @GET
    public List<PamSettings.Entry> getSettings() throws GuacamoleException {
        requireAdministrator();
        return provider.getSettings().list();
    }

    /**
     * Whether this server runs the HA module ("ha"), and why it is on
     * standby ("standby", or null if PAM works on it), for the tab to say
     * so; and the languages emails are written in ("emailLanguages", their
     * names by code).
     */
    @GET
    @Path("server")
    public Map<String, Object> getServer() throws GuacamoleException {
        requireAdministrator();
        Standby standby = provider.getRotationService().getCoordination().getStandby();
        Map<String, Object> server = new LinkedHashMap<>();
        server.put("ha", HaAuthenticationProvider.isEnabled());
        server.put("standby", standby == null ? null : standby.name());
        server.put("emailLanguages", provider.getEmailLanguages().getNames());
        return server;
    }

    /**
     * Sends a test through an output of events ("syslog", "email"), as
     * saved: whether it was sent ("sent"), and what was sent where, or why
     * not ("message"). Logged.
     */
    @POST
    @Path("test/{output}")
    public Map<String, Object> test(@PathParam("output") String output) throws GuacamoleException {

        requireAdministrator();
        Map<String, Object> result = new LinkedHashMap<>();
        try {
            result.put("message", provider.getEvents().test(output, username()));
            result.put("sent", true);
        }
        catch (GuacamoleResourceNotFoundException e) {
            throw e;
        }
        catch (GuacamoleException e) {
            result.put("message", e.getMessage());
            result.put("sent", false);
        }

        logger.info("User \"{}\" tested {}: {}", username(), output, Values.forLog((String) result.get("message")));
        return result;

    }

    /**
     * Changes shared settings, all or none: each by name, to a value, or to
     * null for its default. Returns the settings as then.
     */
    @PUT
    public List<PamSettings.Entry> updateSettings(Map<String, Object> values) throws GuacamoleException {
        requireAdministrator();
        provider.getSettings().update(values, username());
        return getSettings();
    }

}
