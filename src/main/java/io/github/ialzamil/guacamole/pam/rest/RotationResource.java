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
import javax.ws.rs.core.MediaType;

import org.apache.guacamole.GuacamoleException;
import org.apache.guacamole.net.auth.AuthenticatedUser;

import io.github.ialzamil.guacamole.pam.PamAuthenticationProvider;
import io.github.ialzamil.guacamole.pam.rotation.ManagedConnection;
import io.github.ialzamil.guacamole.pam.rotation.RotationResult;

/**
 * The rotation of managed connections, at "connections": their state, and
 * rotating one now. Administrators only, but for the count of failures,
 * which is zero for anyone else.
 */
@Produces(MediaType.APPLICATION_JSON)
@Consumes(MediaType.APPLICATION_JSON)
public class RotationResource extends PamResource {

    RotationResource(PamAuthenticationProvider provider, AuthenticatedUser user) {
        super(provider, user);
    }

    @GET
    public List<ManagedConnection> listConnections() throws GuacamoleException {
        requireAdministrator();
        return provider.getRotationService().listManaged();
    }

    /**
     * Number of managed connections whose last rotation failed or could not
     * be confirmed, for the badge of administrators. Zero for anyone else.
     */
    @GET
    @Path("failures/count")
    public Map<String, Integer> countRotationFailures() throws GuacamoleException {
        int failed = 0;
        if (isAdministrator()) {
            for (ManagedConnection connection : provider.getRotationService().listManaged()) {
                if (RotationResult.FAILED.equals(connection.getStatus())
                        || RotationResult.UNKNOWN.equals(connection.getStatus()))
                    failed++;
            }
        }
        return Collections.singletonMap("failed", failed);
    }

    @POST
    @Path("{id}/rotate")
    public RotationResult rotate(@PathParam("id") String id) throws GuacamoleException {
        requireAdministrator();
        return provider.getRotationService().rotateNow(id);
    }

}
