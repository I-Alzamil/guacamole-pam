package io.github.ialzamil.guacamole.pam.ha;

import java.io.File;

import javax.ws.rs.GET;
import javax.ws.rs.HeaderParam;
import javax.ws.rs.Path;
import javax.ws.rs.PathParam;
import javax.ws.rs.Produces;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;

import org.apache.guacamole.GuacamoleException;
import org.apache.guacamole.GuacamoleSecurityException;

/**
 * Where other servers reach this one, at "api/ext/pam-ha/...", giving the
 * secret servers share. Nobody else may. They ask it who it is ("ping"), to
 * check its URL reaches it, and fetch its recordings ("recordings/UUID" or
 * ".../UUID/name"), if shared.
 */
public class PeerResource {

    private final Config config;

    private final String serverId;

    private final Recordings recordings;

    /**
     * @param recordings
     *     This server's recordings, or null if not shared.
     */
    PeerResource(Config config, String serverId, Recordings recordings) {
        this.config = config;
        this.serverId = serverId;
        this.recordings = recordings;
    }

    /**
     * The URL of the given path of this resource, on the server at the
     * given URL ("pam-ha-url").
     */
    static String url(String serverUrl, String path) {
        return serverUrl.replaceAll("/+$", "") + "/api/ext/" + HaAuthenticationProvider.IDENTIFIER + "/"
                + path;
    }

    @GET
    @Path("ping")
    @Produces(MediaType.TEXT_PLAIN)
    public Response ping(@HeaderParam(Recordings.SECRET_HEADER) String secret) {
        if (!config.isSecret(secret))
            return Response.status(Response.Status.FORBIDDEN).build();
        return Response.ok(serverId).build();
    }

    @GET
    @Path("recordings/{path: .+}")
    @Produces(MediaType.APPLICATION_OCTET_STREAM)
    public Response getRecording(@HeaderParam(Recordings.SECRET_HEADER) String secret,
            @PathParam("path") String path) {
        if (recordings == null)
            return Response.status(Response.Status.NOT_FOUND).build();
        try {
            File file = recordings.file(secret, path);
            return Response.ok(file).header("Content-Length", file.length()).build();
        }
        catch (GuacamoleSecurityException e) {
            return Response.status(Response.Status.FORBIDDEN).build();
        }
        catch (GuacamoleException e) {
            return Response.status(Response.Status.NOT_FOUND).build();
        }
    }

}
