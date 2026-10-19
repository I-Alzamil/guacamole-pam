package org.apache.guacamole.pam;

import org.apache.guacamole.GuacamoleException;
import org.apache.guacamole.net.auth.AbstractUserContext;
import org.apache.guacamole.net.auth.AuthenticatedUser;
import org.apache.guacamole.net.auth.AuthenticationProvider;
import org.apache.guacamole.net.auth.User;
import org.apache.guacamole.net.auth.simple.SimpleUser;
import org.apache.guacamole.pam.rest.PamREST;

/**
 * Per-session UserContext of this extension. It holds no connections of its
 * own; it exists to expose the REST API at "api/session/ext/pam".
 */
public class PamUserContext extends AbstractUserContext {

    private final PamAuthenticationProvider authProvider;

    private final AuthenticatedUser authenticatedUser;

    private final User self;

    public PamUserContext(PamAuthenticationProvider authProvider,
            AuthenticatedUser authenticatedUser) {
        this.authProvider = authProvider;
        this.authenticatedUser = authenticatedUser;
        this.self = new SimpleUser(authenticatedUser.getIdentifier());
    }

    @Override
    public User self() {
        return self;
    }

    @Override
    public AuthenticationProvider getAuthenticationProvider() {
        return authProvider;
    }

    @Override
    public Object getResource() throws GuacamoleException {
        return new PamREST(authProvider, authenticatedUser);
    }

}
