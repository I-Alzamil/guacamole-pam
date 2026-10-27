package io.github.ialzamil.guacamole.pam.ha;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.TimeUnit;

import javax.servlet.http.HttpServletRequest;

import org.apache.guacamole.GuacamoleException;
import org.apache.guacamole.net.auth.AuthenticatedUser;
import org.apache.guacamole.net.auth.AuthenticationProvider;
import org.apache.guacamole.net.auth.Credentials;
import org.apache.guacamole.net.auth.UserContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Logins shared between servers: a token given by one server works on every
 * other. Each login is recorded in pam_ha_login, by the SHA-256 of its
 * token, with who logged in: a server given a token it does not know builds
 * that login again from it, as when the login is refreshed rather than made,
 * so extensions checking a login as it starts, such as TOTP, do not ask
 * again. Logging out, on any server, ends the login on every server, and a
 * login ends once not used for "api-session-timeout" minutes on any server.
 *
 * A login is built again only if every extension that gave it a context
 * where it was made gives one here too: extensions keeping their own logins,
 * such as LDAP, give none for a user they did not log in, who then logs in
 * again, as without this extension. Nor is it if the user's database account
 * may not be used now (see {@link Accounts}), as logging in again would not.
 *
 * Guacamole keeps its logins in memory, in a map no extension may change:
 * this one replaces that map, through {@link Internals}.
 */
final class LoginSync {

    private static final Logger logger = LoggerFactory.getLogger(LoginSync.class);

    /**
     * How often logins used here are recorded as used, and those ended on
     * other servers end here.
     */
    static final int SYNC_SECONDS = 10;

    /**
     * How long a token not found stays unknown, so a client polling with an
     * old token does not query the database each time.
     */
    private static final long MISS_MS = 5000;

    /**
     * Most logins of other servers looked up in the database per second.
     */
    private static final int MAX_LOOKUPS_PER_SECOND = 20;

    /**
     * Lookups of the current second.
     */
    private static final class Rate {

        private long second;
        private int count;

        synchronized boolean tryAcquire() {
            long now = System.currentTimeMillis() / 1000;
            if (now != second) {
                second = now;
                count = 0;
            }
            return ++count <= MAX_LOOKUPS_PER_SECOND;
        }

    }

    private final Rate lookups = new Rate();

    private final SessionStore store;

    /**
     * The sessions of each database configured, whose accounts are checked
     * when a login is built again.
     */
    private final Map<DatabaseType, SessionStore> stores;

    private final int timeoutSeconds;

    /**
     * Whether logins of those opening share links are shared too.
     */
    private final boolean anonymousShares;

    private volatile Internals internals;

    private volatile SyncedMap map;

    private volatile AuthenticationProvider provider;

    private ScheduledFuture<?> installing;

    /**
     * The tokens of this server's logins that are in the database, with the
     * SHA-256 recorded, and when each was last used as last recorded.
     */
    private final Map<String, String> recorded = new ConcurrentHashMap<>();

    private final Map<String, Long> synced = new ConcurrentHashMap<>();

    /**
     * Logins this server keeps to itself, such as share links while those
     * are not shared: tokens.
     */
    private final Set<String> unrecorded = ConcurrentHashMap.newKeySet();

    private final Map<String, Long> misses = new ConcurrentHashMap<>();

    private final Map<String, Object> building = new ConcurrentHashMap<>();

    /**
     * @param store
     *     The sessions of the database logins are kept in.
     *
     * @param stores
     *     The sessions of each database configured.
     *
     * @param anonymousShares
     *     Whether logins of those opening share links are shared too.
     */
    LoginSync(SessionStore store, Map<DatabaseType, SessionStore> stores, Config config, boolean anonymousShares) {
        this.store = store;
        this.stores = stores;
        this.anonymousShares = anonymousShares;
        this.timeoutSeconds = Math.max(1, config.sessionTimeoutMinutes) * 60;
    }

    /**
     * Replaces Guacamole's map of logins once its web application is up,
     * then syncs logins every {@link #SYNC_SECONDS} seconds.
     */
    synchronized void start(ScheduledExecutorService executor) {
        installing = executor.scheduleWithFixedDelay(() -> install(executor), 1, 1, TimeUnit.SECONDS);
    }

    private synchronized void install(ScheduledExecutorService executor) {

        if (map != null || installing == null)
            return;

        Internals found;
        try {
            found = Internals.find();
        }
        catch (ReflectiveOperationException | RuntimeException | LinkageError e) {
            installing.cancel(false);
            installing = null;
            logger.warn("Logins are not shared between servers: this Guacamole does not keep them as Guacamole"
                    + " 1.6.0 does ({}). Users log in again on each server.", e.toString());
            logger.debug("Unable to replace the logins of Guacamole.", e);
            return;
        }
        if (found == null)
            return;

        if (!store.start())
            return;

        provider = found.getAuthProvider(HaAuthenticationProvider.IDENTIFIER);
        internals = found;
        SyncedMap replacement = new SyncedMap();
        try {
            ConcurrentMap<String, Object> current = found.replaceSessions(replacement);
            map = replacement;
            for (Map.Entry<String, Object> login : current.entrySet()) {
                replacement.putLocal(login.getKey(), login.getValue());
                record(login.getKey(), login.getValue());
            }
        }
        catch (ReflectiveOperationException | RuntimeException e) {
            installing.cancel(false);
            installing = null;
            logger.warn("Logins are not shared between servers: {}", e.toString());
            return;
        }

        installing.cancel(false);
        installing = null;
        executor.scheduleWithFixedDelay(this::sync, SYNC_SECONDS, SYNC_SECONDS, TimeUnit.SECONDS);
        logger.info("Logins are shared with the other servers using the {} database.",
                store.getDatabase().getType().getIdentifier());

    }

    /**
     * Whether logins are shared: Guacamole's map of logins was replaced.
     */
    boolean isShared() {
        return map != null;
    }

    synchronized void shutdown() {
        if (installing != null)
            installing.cancel(false);
        installing = null;
    }

    /**
     * Guacamole's map of logins by token: also those of other servers,
     * built again here when first used, and recorded for other servers when
     * added, and gone from every server when removed (logging out). Logins
     * Guacamole drops from it on its own (which have not been used here for
     * long) are only dropped here.
     */
    private final class SyncedMap extends ConcurrentHashMap<String, Object> {

        private static final long serialVersionUID = 1L;

        @Override
        public Object get(Object token) {
            Object session = super.get(token);
            if (session != null || !(token instanceof String))
                return session;
            return rebuild((String) token);
        }

        @Override
        public Object put(String token, Object session) {
            Object previous = super.put(token, session);
            record(token, session);
            return previous;
        }

        @Override
        public Object remove(Object token) {
            Object session = super.remove(token);
            if (token instanceof String)
                forget((String) token);
            return session;
        }

        Object getLocal(String token) {
            return super.get(token);
        }

        void putLocal(String token, Object session) {
            super.put(token, session);
        }

        Object removeLocal(String token) {
            return super.remove(token);
        }

    }

    /**
     * A login as recorded.
     */
    private static final class Login {

        String username;
        String authProvider;
        Set<String> groups;
        List<String> providers;
        String shareKey;
        String remoteAddress;
        String remoteHostname;

    }

    /**
     * Records a login made here.
     */
    private void record(String token, Object session) {

        Internals in = internals;
        if (in == null)
            return;

        String hash = Sql.sha256(token);
        try {

            AuthenticatedUser user = in.getAuthenticatedUser(session);
            Credentials credentials = user.getCredentials();
            String key = credentials == null ? null : credentials.getParameter("key");
            if (AuthenticatedUser.ANONYMOUS_IDENTIFIER.equals(user.getIdentifier())
                    && (key == null || !anonymousShares)) {
                // Not looked at again: each look counts as using it, which
                // would keep it from ever timing out
                unrecorded.add(token);
                return;
            }

            List<String> providers = new ArrayList<>();
            for (Object context : in.getUserContexts(session))
                providers.add(((UserContext) context).getAuthenticationProvider().getIdentifier());

            try (Connection connection = store.getDatabase().connect()) {
                Sql.update(connection, "DELETE FROM pam_ha_login WHERE login_id = ?", hash);
                Sql.update(connection, "INSERT INTO pam_ha_login (login_id, username, auth_provider,"
                        + " user_groups, providers, share_key, remote_address, remote_hostname, created,"
                        + " last_access) VALUES (?, ?, ?, ?, ?, ?, ?, ?, " + now() + ", " + now() + ")", hash,
                        user.getIdentifier(), user.getAuthenticationProvider().getIdentifier(),
                        String.join("\n", user.getEffectiveUserGroups()), String.join("\n", providers),
                        key == null ? null : Sql.sha256(key),
                        credentials == null ? null : credentials.getRemoteAddress(),
                        credentials == null ? null : credentials.getRemoteHostname());
            }

            recorded.put(token, hash);
            synced.put(token, in.getLastAccessedTime(session));

        }
        catch (SQLException | ReflectiveOperationException | RuntimeException e) {
            logger.warn("Unable to record a login for the other servers: {} Trying again in {} seconds.",
                    e.getMessage(), SYNC_SECONDS);
            logger.debug("Unable to record a login.", e);
        }

    }

    /**
     * Ends a login on every server: its user logged out.
     */
    private void forget(String token) {
        String hash = recorded.remove(token);
        synced.remove(token);
        if (internals == null)
            return;
        try (Connection connection = store.getDatabase().connect()) {
            Sql.update(connection, "DELETE FROM pam_ha_login WHERE login_id = ?",
                    hash != null ? hash : Sql.sha256(token));
        }
        catch (SQLException e) {
            logger.warn("Unable to end a login on the other servers: {} It ends there once not used for"
                    + " {} minutes.", e.getMessage(), timeoutSeconds / 60);
        }
    }

    /**
     * The login of another server with the given token, built again here,
     * or null if there is none, or it cannot be built.
     */
    private Object rebuild(String token) {

        Internals in = internals;
        SyncedMap logins = map;
        if (in == null || logins == null)
            return null;

        String hash = Sql.sha256(token);
        Long missedUntil = misses.get(hash);
        if (missedUntil != null && missedUntil > System.currentTimeMillis())
            return null;

        // Tokens of no login, such as made up by the thousand, are looked
        // up at a bounded rate, so they never fill the database's
        // connections
        if (!lookups.tryAcquire())
            return null;

        Object lock = building.computeIfAbsent(hash, h -> new Object());
        try {
            synchronized (lock) {

                Object session = logins.getLocal(token);
                if (session != null)
                    return session;

                Login login = read(hash);
                session = login == null ? null : build(in, login);
                if (login == null || session == null) {
                    if (misses.size() > 10000)
                        misses.clear();
                    misses.put(hash, System.currentTimeMillis() + MISS_MS);
                    return null;
                }

                logins.putLocal(token, session);
                recorded.put(token, hash);
                synced.put(token, 0L);
                logger.info("The login of user \"{}\" made on another server goes on on this one.",
                        login.username);
                return session;

            }
        }
        finally {
            building.remove(hash);
        }

    }

    private Login read(String hash) {
        try (Connection connection = store.getDatabase().connect();
             PreparedStatement statement = connection.prepareStatement("SELECT username, auth_provider,"
                 + " user_groups, providers, share_key, remote_address, remote_hostname FROM pam_ha_login WHERE login_id = ? AND"
                 + " last_access > " + store.getDatabase().getType().secondsAgo(timeoutSeconds))) {
            statement.setString(1, hash);
            try (ResultSet results = statement.executeQuery()) {
                if (!results.next())
                    return null;
                Login login = new Login();
                login.username = results.getString(1);
                login.authProvider = results.getString(2);
                login.groups = new HashSet<>(lines(results.getString(3)));
                login.providers = lines(results.getString(4));
                login.shareKey = results.getString(5);
                login.remoteAddress = results.getString(6);
                login.remoteHostname = results.getString(7);
                return login;
            }
        }
        catch (SQLException e) {
            logger.warn("Unable to read a login of another server: {}", e.getMessage());
            return null;
        }
    }

    private static List<String> lines(String value) {
        if (value == null || value.isEmpty())
            return Collections.emptyList();
        return Arrays.asList(value.split("\n"));
    }

    /**
     * Builds a login of another server: the contexts every extension gives
     * its user, decorated as when the login is refreshed.
     */
    private Object build(Internals in, Login login) {

        HttpServletRequest request = Internals.currentRequest();
        if (request == null)
            request = Internals.placeholderRequest(login.remoteAddress, login.remoteHostname);
        Credentials credentials = new Credentials(login.username, null, request);
        SyncedAuthenticatedUser user = new SyncedAuthenticatedUser(authenticatedBy(in, login), login.username,
                login.groups, credentials, login.shareKey);

        List<UserContext> created = new ArrayList<>();
        try {

            List<Object> contexts = new ArrayList<>();
            Set<String> given = new HashSet<>();
            for (AuthenticationProvider authProvider : in.getAuthProviders()) {
                UserContext context = authProvider.getUserContext(user);
                if (context == null)
                    continue;
                created.add(context);
                String refused = refusal(authProvider, context, login.username);
                if (refused != null) {
                    logger.info("The login of user \"{}\" made on another server cannot go on on this one: {}. They"
                            + " log in again.", login.username, refused);
                    invalidate(created);
                    return null;
                }
                contexts.add(in.decorate(context, user, credentials));
                given.add(authProvider.getIdentifier());
            }

            for (String identifier : login.providers) {
                boolean shared = login.shareKey != null && identifier.endsWith("-sharing");
                if (!given.contains(identifier)
                        && !(shared && given.contains(HaAuthenticationProvider.IDENTIFIER))) {
                    logger.info("The login of user \"{}\" made on another server cannot go on on this one: the"
                            + " \"{}\" extension does not give it a context here. They log in again.",
                            login.username, identifier);
                    invalidate(created);
                    return null;
                }
            }

            return in.newSession(user, contexts);

        }
        catch (GuacamoleException | ReflectiveOperationException | RuntimeException e) {
            logger.info("The login of user \"{}\" made on another server cannot go on on this one: {} They log"
                    + " in again.", login.username, e.getMessage());
            logger.debug("Unable to build a login of another server.", e);
            invalidate(created);
            return null;
        }

    }

    /**
     * The extension a login of another server is said to be made through:
     * the one it was made through there, as the web application shows the
     * user's own profile and preferences from it, or this one for share
     * links, as only this one gives what they show on every server.
     */
    private AuthenticationProvider authenticatedBy(Internals in, Login login) {
        AuthenticationProvider authProvider = login.shareKey == null && login.authProvider != null
                ? in.getAuthProvider(login.authProvider) : null;
        return authProvider != null ? authProvider : provider;
    }

    /**
     * Why the database account of a user may not be used now, if the given
     * provider is the authentication of a database configured here; null
     * otherwise, or if it may.
     */
    private String refusal(AuthenticationProvider authProvider, UserContext context, String username)
            throws GuacamoleException {
        SessionStore database = stores.get(DatabaseType.forIdentifier(authProvider.getIdentifier()));
        return database == null ? null : Accounts.refusal(context, database.getDatabase(), username);
    }

    private static void invalidate(List<UserContext> contexts) {
        for (UserContext context : contexts) {
            try {
                context.invalidate();
            }
            catch (RuntimeException e) {
                logger.debug("Unable to invalidate a context.", e);
            }
        }
    }

    /**
     * Records which of this server's logins were used, ends those not used
     * on any server for too long, and ends here those ended on other
     * servers.
     */
    private void sync() {

        Internals in = internals;
        SyncedMap logins = map;
        if (in == null || logins == null)
            return;

        try {

            unrecorded.removeIf(token -> logins.getLocal(token) == null);
            for (Map.Entry<String, Object> login : logins.entrySet()) {
                if (!recorded.containsKey(login.getKey()) && !unrecorded.contains(login.getKey()))
                    record(login.getKey(), login.getValue());
            }

            List<String> used = new ArrayList<>();
            Map<String, String> hashes = new HashMap<>();
            for (Map.Entry<String, String> login : recorded.entrySet()) {
                Object session = logins.getLocal(login.getKey());
                if (session == null) {
                    recorded.remove(login.getKey());
                    synced.remove(login.getKey());
                    continue;
                }
                hashes.put(login.getValue(), login.getKey());
                long lastAccess = in.getLastAccessedTime(session);
                Long lastSynced = synced.get(login.getKey());
                if (in.hasTunnels(session) || lastSynced == null || lastAccess > lastSynced) {
                    used.add(login.getValue());
                    synced.put(login.getKey(), lastAccess);
                }
            }

            Set<String> present = new HashSet<>();
            try (Connection connection = store.getDatabase().connect()) {

                for (List<String> chunk : Sql.chunks(used))
                    Sql.update(connection, "UPDATE pam_ha_login SET last_access = " + now()
                            + " WHERE login_id IN (" + Sql.marks(chunk.size()) + ")", chunk.toArray());
                Sql.update(connection, "DELETE FROM pam_ha_login WHERE last_access < "
                        + store.getDatabase().getType().secondsAgo(timeoutSeconds));

                for (List<String> chunk : Sql.chunks(hashes.keySet())) {
                    try (PreparedStatement statement = connection.prepareStatement("SELECT login_id FROM"
                            + " pam_ha_login WHERE login_id IN (" + Sql.marks(chunk.size()) + ")")) {
                        Sql.bind(statement, chunk.toArray());
                        try (ResultSet results = statement.executeQuery()) {
                            while (results.next())
                                present.add(results.getString(1));
                        }
                    }
                }

            }

            for (Map.Entry<String, String> login : hashes.entrySet()) {
                if (present.contains(login.getKey()))
                    continue;
                String token = login.getValue();
                recorded.remove(token);
                synced.remove(token);
                Object session = logins.removeLocal(token);
                if (session != null) {
                    in.invalidate(session);
                    logger.info("A login ended on another server (logged out, or not used for {} minutes) ends"
                            + " here too.", timeoutSeconds / 60);
                }
            }

        }
        catch (SQLException | ReflectiveOperationException | RuntimeException e) {
            logger.warn("Unable to share logins with the other servers: {}", e.getMessage());
            logger.debug("Unable to sync logins.", e);
        }

    }

    private String now() {
        return store.getDatabase().getType().now();
    }

}
