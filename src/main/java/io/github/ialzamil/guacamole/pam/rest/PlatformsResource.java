package io.github.ialzamil.guacamole.pam.rest;

import java.util.ArrayList;
import java.util.List;
import java.util.TreeSet;

import javax.ws.rs.Consumes;
import javax.ws.rs.DELETE;
import javax.ws.rs.GET;
import javax.ws.rs.POST;
import javax.ws.rs.PUT;
import javax.ws.rs.Path;
import javax.ws.rs.PathParam;
import javax.ws.rs.Produces;
import javax.ws.rs.core.MediaType;

import org.apache.guacamole.GuacamoleClientException;
import org.apache.guacamole.GuacamoleException;
import org.apache.guacamole.GuacamoleResourceNotFoundException;
import org.apache.guacamole.net.auth.AuthenticatedUser;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import io.github.ialzamil.guacamole.pam.PamAuthenticationProvider;
import io.github.ialzamil.guacamole.pam.Values;
import io.github.ialzamil.guacamole.pam.management.ManagementType;
import io.github.ialzamil.guacamole.pam.management.ManagementTypes;
import io.github.ialzamil.guacamole.pam.management.PlatformTestResult;
import io.github.ialzamil.guacamole.pam.platform.Platform;
import io.github.ialzamil.guacamole.pam.platform.PlatformImport;

/**
 * Platforms, at "platforms": readable by name and type by any user, for the
 * connection editor; everything else is limited to administrators.
 */
@Produces(MediaType.APPLICATION_JSON)
@Consumes(MediaType.APPLICATION_JSON)
public class PlatformsResource extends PamResource {

    private static final Logger logger = LoggerFactory.getLogger(PlatformsResource.class);

    PlatformsResource(PamAuthenticationProvider provider, AuthenticatedUser user) {
        super(provider, user);
    }

    /**
     * All platforms. Any user gets names and types, for the connection
     * editor; administrators also get settings and policy. Secrets are never
     * returned, only which ones are stored.
     */
    @GET
    public List<Platform> listPlatforms() throws GuacamoleException {
        return provider.getPlatforms().list(isAdministrator());
    }

    /**
     * Imports platforms, all or none: those named as existing ones fail the
     * import unless asked to update them.
     */
    @POST
    @Path("import")
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
    @Path("defaults")
    public PlatformImport.Report restoreDefaultPlatforms() throws GuacamoleException {
        requireAdministrator();
        return provider.getPlatformImport().restoreDefaults();
    }

    /**
     * Tests a platform as edited, saved or not, changing nothing. Its
     * secrets left empty are those stored, as when saving.
     */
    @POST
    @Path("test")
    public PlatformTestResult testPlatform(Platform platform) throws GuacamoleException {

        requireAdministrator();
        Platform prepared = provider.getPlatforms().prepare(platform);
        ManagementType type = ManagementTypes.get(prepared.getType());
        if (type == null || !type.isTestable())
            throw new GuacamoleClientException("Platforms of this type cannot be tested.");

        // The test connects from this server, wherever the platform says
        PlatformTestResult result = type.test(prepared);
        logger.info("User \"{}\" tested platform \"{}\" ({}): {}.", username(), Values.forLog(prepared.getName()),
                destination(type, prepared), result.isSuccess() ? "passed" : "failed");
        return result;

    }

    /**
     * Where a test of the platform connects, for the log: its settings
     * deciding where its secrets go, but for certificates.
     */
    private static String destination(ManagementType type, Platform platform) {
        List<String> parts = new ArrayList<>();
        for (String name : new TreeSet<>(type.getDestinationFields())) {
            String value = platform.getSettings().get(name);
            if (value != null && !value.isEmpty() && value.indexOf('\n') < 0)
                parts.add(name + "=" + Values.forLog(value));
        }
        return String.join(", ", parts);
    }

    @GET
    @Path("{id}")
    public Platform getPlatform(@PathParam("id") String id) throws GuacamoleException {
        requireAdministrator();
        Platform platform = provider.getPlatforms().getWithSecrets(parseId(id));
        if (platform == null)
            throw new GuacamoleResourceNotFoundException("No such platform.");
        return platform;
    }

    @POST
    public Platform createPlatform(Platform platform) throws GuacamoleException {
        requireAdministrator();
        return provider.getPlatforms().create(platform);
    }

    @PUT
    @Path("{id}")
    public Platform updatePlatform(@PathParam("id") String id, Platform platform) throws GuacamoleException {
        requireAdministrator();
        return provider.getPlatforms().update(parseId(id), platform);
    }

    @DELETE
    @Path("{id}")
    public void deletePlatform(@PathParam("id") String id) throws GuacamoleException {
        requireAdministrator();
        provider.getPlatforms().delete(parseId(id));
    }

}
