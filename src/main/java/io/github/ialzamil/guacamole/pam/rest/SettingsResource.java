package io.github.ialzamil.guacamole.pam.rest;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import javax.ws.rs.Consumes;
import javax.ws.rs.GET;
import javax.ws.rs.PUT;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.core.MediaType;

import org.apache.guacamole.GuacamoleException;
import org.apache.guacamole.net.auth.AuthenticatedUser;

import io.github.ialzamil.guacamole.pam.PamAuthenticationProvider;
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
     * How many Guacamole servers run the extension on the database
     * ("servers"), and whether this one runs the HA module ("ha"), for the
     * tab to say when several run without it.
     */
    @GET
    @Path("servers")
    public Map<String, Object> getServers() throws GuacamoleException {
        requireAdministrator();
        Map<String, Object> servers = new LinkedHashMap<>();
        servers.put("servers", provider.getRotationService().countServers());
        servers.put("ha", HaAuthenticationProvider.isEnabled());
        return servers;
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
