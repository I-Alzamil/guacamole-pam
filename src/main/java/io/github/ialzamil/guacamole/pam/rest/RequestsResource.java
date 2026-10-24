package io.github.ialzamil.guacamole.pam.rest;

import java.util.List;
import java.util.Map;

import javax.ws.rs.Consumes;
import javax.ws.rs.DELETE;
import javax.ws.rs.GET;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.PathParam;
import javax.ws.rs.Produces;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;

import org.apache.guacamole.GuacamoleClientException;
import org.apache.guacamole.GuacamoleException;
import org.apache.guacamole.net.auth.AuthenticatedUser;
import org.apache.guacamole.net.auth.UserContext;

import io.github.ialzamil.guacamole.pam.PamAuthenticationProvider;
import io.github.ialzamil.guacamole.pam.Values;
import io.github.ialzamil.guacamole.pam.checkout.PasswordRequest;
import io.github.ialzamil.guacamole.pam.checkout.RequestOutcome;

/**
 * The user's own requests, at "requests": for Accounts' passwords, and
 * access to connections needing a request, of the connections Guacamole
 * lets them read.
 */
@Produces(MediaType.APPLICATION_JSON)
@Consumes(MediaType.APPLICATION_JSON)
public class RequestsResource extends PamResource {

    RequestsResource(PamAuthenticationProvider provider, AuthenticatedUser user) {
        super(provider, user);
    }

    /**
     * The user's view of the managed data source, deciding which
     * connections they may read.
     */
    private UserContext context() throws GuacamoleException {
        return provider.getDataSourceContext(user);
    }

    /**
     * Connections needing a request, and Accounts, that the current user
     * can read.
     */
    @GET
    public List<PasswordRequest> listRequests() throws GuacamoleException {
        return provider.getCheckoutService().listRequests(context(), username(), isAdministrator());
    }

    @GET
    @Path("{id}")
    public PasswordRequest getRequest(@PathParam("id") String id) throws GuacamoleException {
        return provider.getCheckoutService().getRequest(context(), username(), id, isAdministrator());
    }

    /**
     * Checks out the password, or shows it again to its current holder. The
     * body gives the "reason", "starts" (milliseconds since the epoch) for
     * access requested ahead of time, and "periods" for access lasting more
     * than one time limit. The response must never be cached.
     */
    @POST
    @Path("{id}")
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

        RequestOutcome outcome = provider.getCheckoutService().request(context(), username(), remoteHost(), id,
                body == null ? null : body.get("reason"), starts, periods, isAdministrator());

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
    @Path("{id}/password")
    public Response revealPassword(@PathParam("id") String id) throws GuacamoleException {
        return uncached(provider.getCheckoutService().revealPassword(context(), username(), id));
    }

    /**
     * Cancels the user's own request awaiting approval.
     */
    @DELETE
    @Path("{id}/pending")
    public void cancelRequest(@PathParam("id") String id) throws GuacamoleException {
        provider.getCheckoutService().cancelRequest(context(), username(), remoteHost(), id);
    }

    /**
     * Cancels the user's own next reservation, approved but not used yet.
     */
    @DELETE
    @Path("{id}/reservation")
    public void cancelReservation(@PathParam("id") String id) throws GuacamoleException {
        provider.getCheckoutService().cancelReservation(context(), username(), remoteHost(), id);
    }

    /**
     * Extends the user's checkout, or asks for it to be extended where
     * approval is needed. The body gives the "reason".
     */
    @POST
    @Path("{id}/extension")
    public PasswordRequest extend(@PathParam("id") String id, Map<String, String> body) throws GuacamoleException {
        return provider.getCheckoutService().extend(context(), username(), remoteHost(), id,
                body == null ? null : body.get("reason"), isAdministrator());
    }

    /**
     * Cancels the user's request to extend their checkout, awaiting approval.
     */
    @DELETE
    @Path("{id}/extension")
    public void cancelExtension(@PathParam("id") String id) throws GuacamoleException {
        provider.getCheckoutService().cancelExtension(context(), username(), remoteHost(), id);
    }

    @POST
    @Path("{id}/release")
    public void releasePassword(@PathParam("id") String id) throws GuacamoleException {
        provider.getCheckoutService().release(context(), username(), remoteHost(), id);
    }

}
