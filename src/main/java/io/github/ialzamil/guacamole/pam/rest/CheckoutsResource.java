package io.github.ialzamil.guacamole.pam.rest;

import java.util.Collections;
import java.util.List;

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
import io.github.ialzamil.guacamole.pam.checkout.Checkout;

/**
 * Everyone's checkouts, at "checkouts": active ones, which can be revoked,
 * and the history. Administrators only.
 */
@Produces(MediaType.APPLICATION_JSON)
@Consumes(MediaType.APPLICATION_JSON)
public class CheckoutsResource extends PamResource {

    /**
     * Most checkouts returned by one history search, as for Guacamole's own
     * connection history.
     */
    private static final int CHECKOUT_HISTORY_LIMIT = 1000;

    CheckoutsResource(PamAuthenticationProvider provider, AuthenticatedUser user) {
        super(provider, user);
    }

    @GET
    @Path("active")
    public List<Checkout> listActiveCheckouts() throws GuacamoleException {
        requireAdministrator();
        return provider.getCheckoutService().listActive();
    }

    /**
     * Searches the checkout history, newest first. Every "contains" term must
     * match the user, connection, reason, or how and by whom it ended.
     */
    @GET
    @Path("history")
    public List<Checkout> searchCheckouts(@QueryParam("contains") List<String> contains)
            throws GuacamoleException {
        requireAdministrator();
        return provider.getCheckoutService().search(
                contains == null ? Collections.<String>emptyList() : contains, CHECKOUT_HISTORY_LIMIT);
    }

    @POST
    @Path("{id}/revoke")
    public void revokeCheckout(@PathParam("id") String id) throws GuacamoleException {
        requireAdministrator();
        provider.getCheckoutService().revoke(parseId(id), username(), remoteHost());
    }

}
