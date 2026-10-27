package io.github.ialzamil.guacamole.pam.ha;

import java.util.Collections;
import java.util.Set;

import org.apache.guacamole.net.auth.AbstractAuthenticatedUser;
import org.apache.guacamole.net.auth.AuthenticationProvider;
import org.apache.guacamole.net.auth.Credentials;

/**
 * A user this extension vouches for: one who logged in on another server,
 * whose login goes on here, or someone opening a share link of a session
 * of any server. The first is said to be authenticated by the extension
 * they logged in through there.
 */
final class SyncedAuthenticatedUser extends AbstractAuthenticatedUser {

    private final AuthenticationProvider authenticationProvider;

    private final Credentials credentials;

    private final Set<String> effectiveGroups;

    /**
     * The SHA-256 of the key of the share link used, or null.
     */
    private final String shareKeyHash;

    SyncedAuthenticatedUser(AuthenticationProvider authenticationProvider, String username,
            Set<String> effectiveGroups, Credentials credentials, String shareKeyHash) {
        super();
        setIdentifier(username);
        this.authenticationProvider = authenticationProvider;
        this.credentials = credentials;
        this.effectiveGroups = Collections.unmodifiableSet(effectiveGroups);
        this.shareKeyHash = shareKeyHash;
    }

    String getShareKeyHash() {
        return shareKeyHash;
    }

    @Override
    public AuthenticationProvider getAuthenticationProvider() {
        return authenticationProvider;
    }

    @Override
    public Credentials getCredentials() {
        return credentials;
    }

    /**
     * The groups the user was in where they logged in, as other extensions
     * found them, such as from LDAP: the database's permissions given
     * through groups then still apply.
     */
    @Override
    public Set<String> getEffectiveUserGroups() {
        return effectiveGroups;
    }

}
