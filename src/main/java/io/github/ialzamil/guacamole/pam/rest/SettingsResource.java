package io.github.ialzamil.guacamole.pam.rest;

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
import io.github.ialzamil.guacamole.pam.coordination.Standby;
import io.github.ialzamil.guacamole.pam.ha.HaAuthenticationProvider;
import io.github.ialzamil.guacamole.pam.settings.PamSettings;

/**
 * The settings shared by every server, at "settings": administrators only.
 */
@Produces(MediaType.APPLICATION_JSON)
@Consumes(MediaType.APPLICATION_JSON)
public class SettingsResource extends PamResource {

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
     * so.
     */
    @GET
    @Path("server")
    public Map<String, Object> getServer() throws GuacamoleException {
        requireAdministrator();
        Standby standby = provider.getRotationService().getCoordination().getStandby();
        Map<String, Object> server = new LinkedHashMap<>();
        server.put("ha", HaAuthenticationProvider.isEnabled());
        server.put("standby", standby == null ? null : standby.name());
        return server;
    }

    /**
     * Sends a test through an output of events ("syslog", "email"), as
     * saved, returning what was sent ("message").
     */
    @POST
    @Path("test/{output}")
    public Map<String, String> test(@PathParam("output") String output) throws GuacamoleException {
        requireAdministrator();
        return Collections.singletonMap("message", provider.getEvents().test(output, username()));
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
