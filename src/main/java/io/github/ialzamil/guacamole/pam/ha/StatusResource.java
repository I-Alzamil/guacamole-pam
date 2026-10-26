package io.github.ialzamil.guacamole.pam.ha;

import java.util.Map;

import javax.ws.rs.GET;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.QueryParam;
import javax.ws.rs.core.MediaType;

import org.apache.guacamole.GuacamoleException;
import org.apache.guacamole.GuacamoleSecurityException;

/**
 * The status page's data, for administrators of a database data source, at
 * "api/session/ext/DATA_SOURCE/pam-ha/status": Guacamole gives each
 * logged-in user the resource of their context of that data source, which
 * this extension decorates. "?check=true" also checks the URL of each
 * server.
 */
public class StatusResource {

    private final Status status;

    private final SessionStore store;

    private final SyncedUserContext context;

    StatusResource(Status status, SessionStore store, SyncedUserContext context) {
        this.status = status;
        this.store = store;
        this.context = context;
    }

    @GET
    @Path(HaAuthenticationProvider.IDENTIFIER + "/status")
    @Produces(MediaType.APPLICATION_JSON)
    public Map<String, Object> getStatus(@QueryParam("check") boolean check) throws GuacamoleException {
        if (!context.isPrivileged())
            throw new GuacamoleSecurityException("Permission denied.");
        return status.read(store, check);
    }

}
