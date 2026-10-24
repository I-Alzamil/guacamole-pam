package io.github.ialzamil.guacamole.pam.rest;

import javax.ws.rs.core.CacheControl;
import javax.ws.rs.core.Response;

import org.apache.guacamole.GuacamoleException;
import org.apache.guacamole.GuacamoleResourceNotFoundException;
import org.apache.guacamole.GuacamoleSecurityException;
import org.apache.guacamole.net.auth.AuthenticatedUser;

import io.github.ialzamil.guacamole.pam.PamAuthenticationProvider;
import io.github.ialzamil.guacamole.pam.Values;

/**
 * What every part of the REST API knows: the extension, and the user asking
 * (see {@link PamREST}).
 */
abstract class PamResource {

    protected final PamAuthenticationProvider provider;

    protected final AuthenticatedUser user;

    PamResource(PamAuthenticationProvider provider, AuthenticatedUser user) {
        this.provider = provider;
        this.user = user;
    }

    /**
     * The current user's username in the managed data source (see
     * {@link PamAuthenticationProvider#getUsername}).
     */
    protected String username() throws GuacamoleException {
        return provider.getUsername(user);
    }

    protected boolean isAdministrator() throws GuacamoleException {
        return provider.isAdministrator(user);
    }

    protected void requireAdministrator() throws GuacamoleException {
        if (!isAdministrator())
            throw new GuacamoleSecurityException("Permission denied.");
    }

    /**
     * Where the user is, as Guacamole's connection history records it: the
     * address they logged in from.
     */
    protected String remoteHost() {
        return user.getCredentials() == null ? null : user.getCredentials().getRemoteAddress();
    }

    /**
     * An identifier from a path, as a missing resource if it is not one.
     */
    protected static int parseId(String id) throws GuacamoleResourceNotFoundException {
        Integer parsed = Values.parseId(id);
        if (parsed == null)
            throw new GuacamoleResourceNotFoundException("Not found.");
        return parsed;
    }

    /**
     * A response holding a password, which must never be cached.
     */
    protected static Response uncached(Object entity) {

        CacheControl noStore = new CacheControl();
        noStore.setNoStore(true);
        noStore.setNoCache(true);
        noStore.setPrivate(true);

        return Response.ok(entity).cacheControl(noStore).header("Pragma", "no-cache").build();

    }

}
