package io.github.ialzamil.guacamole.pam.ha;

import java.util.Collections;

import org.apache.guacamole.GuacamoleException;
import org.apache.guacamole.net.auth.AbstractAuthenticationProvider;
import org.apache.guacamole.net.auth.AuthenticatedUser;
import org.apache.guacamole.net.auth.Credentials;
import org.apache.guacamole.net.auth.UserContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * The HA module of the PAM extension, when "pam-ha" turns it on: makes
 * Guacamole servers sharing their database work as one, active-active:
 * what Guacamole keeps on each server alone is kept in the database, for
 * every server. Sessions are counted and limited on every server ("in use
 * by", "max-connections", ...), listed in Active Sessions, ended, joined and
 * shared from any; logins, failed logins (the ban extension's) and TOTP
 * codes used are known to every server; and recordings of any server are
 * shown by every other. Works with each database Guacamole's authentication
 * supports (PostgreSQL, MySQL and MariaDB, SQL Server), as configured for
 * it. Authenticates nobody itself, but those opening share links of
 * sessions of other servers, and users whose login was made on another
 * server. Off, it does nothing: no tables, threads or settings tab.
 */
public class HaAuthenticationProvider extends AbstractAuthenticationProvider {

    private static final Logger logger = LoggerFactory.getLogger(HaAuthenticationProvider.class);

    static final String IDENTIFIER = "pam-ha";

    /**
     * The parameter of share links giving their key, as Guacamole's.
     */
    private static final String SHARE_KEY_PARAMETER = "key";

    /**
     * This server as one of those sharing the database, or null if the HA
     * module is off.
     */
    private final Cluster cluster;

    public HaAuthenticationProvider() {
        cluster = Settings.isEnabled() ? Cluster.get() : null;
        if (cluster != null)
            cluster.start();
    }

    /**
     * Whether the HA module runs on this server ("pam-ha").
     */
    public static boolean isEnabled() {
        return Settings.isEnabled();
    }

    @Override
    public String getIdentifier() {
        return IDENTIFIER;
    }

    /**
     * Where other servers reach this one: to check its URL, and fetch its
     * recordings, if shared.
     */
    @Override
    public Object getResource() {
        if (cluster == null)
            return null;
        Config config = cluster.getConfig();
        return config == null ? null : new PeerResource(config, cluster.getServerId(), cluster.getRecordings());
    }

    /**
     * Lets in whoever opens a share link of a session of any server, as
     * Guacamole lets in those of its own.
     */
    @Override
    public AuthenticatedUser authenticateUser(Credentials credentials) {
        if (cluster == null)
            return null;
        String key = credentials.getParameter(SHARE_KEY_PARAMETER);
        if (key == null)
            return null;
        SyncedAuthenticatedUser user = new SyncedAuthenticatedUser(this, AuthenticatedUser.ANONYMOUS_IDENTIFIER,
                Collections.<String>emptySet(), credentials, Sql.sha256(key));
        return findShare(user) == null ? null : user;
    }

    /**
     * The connection shared, for whoever opened a share link, including on
     * a server other than the one they opened it on.
     */
    @Override
    public UserContext getUserContext(AuthenticatedUser authenticatedUser) {
        return cluster != null && authenticatedUser instanceof SyncedAuthenticatedUser
                ? findShare((SyncedAuthenticatedUser) authenticatedUser) : null;
    }

    /**
     * What the share link the given user opened shows, of any database, or
     * null if they opened none, or this extension may not let in those
     * opening it.
     */
    private ShareUserContext findShare(SyncedAuthenticatedUser user) {

        String keyHash = user.getShareKeyHash();
        if (keyHash == null || !cluster.allowsAnonymousShares())
            return null;

        for (SessionStore store : cluster.getStores()) {
            if (!store.isStarted())
                continue;
            try {
                SessionStore.Share share = store.findShare(keyHash);
                if (share != null)
                    return new ShareUserContext(this, store, share, user);
            }
            catch (GuacamoleException e) {
                logger.warn("Unable to read share links: {}", e.getMessage());
            }
        }
        return null;

    }

    /**
     * Shares what Guacamole's database authentication keeps on each server:
     * the sessions of its users, and of those opening its share links. Also
     * refuses TOTP codes already used on any server.
     */
    @Override
    public UserContext decorate(UserContext context, AuthenticatedUser authenticatedUser,
            Credentials credentials) throws GuacamoleException {

        if (cluster == null)
            return context;

        TotpSync codes = cluster.getCodes();
        if (codes != null)
            codes.check(authenticatedUser, credentials);

        String identifier = context.getAuthenticationProvider().getIdentifier();
        boolean sharing = identifier.endsWith("-sharing");
        SessionStore store = cluster.getStore(DatabaseType.forIdentifier(sharing
                ? identifier.substring(0, identifier.length() - "-sharing".length()) : identifier));
        if (store == null || !store.start())
            return context;

        String remoteHost = credentials == null ? null : credentials.getRemoteAddress();

        if (sharing) {
            String key = credentials == null ? null : credentials.getParameter(SHARE_KEY_PARAMETER);
            SessionStore.Share share = key == null ? null : store.findShare(Sql.sha256(key));
            return share == null ? context : new SharingUserContext(context, store, share, remoteHost);
        }

        return new SyncedUserContext(context, store, cluster.getConfig(), cluster.getRecordings(),
                cluster.getStatus(), remoteHost);

    }

    @Override
    public void shutdown() {
        if (cluster != null)
            cluster.shutdown();
    }

}
