package io.github.ialzamil.guacamole.pam.ha;

import java.lang.ref.WeakReference;
import java.lang.reflect.Constructor;
import java.lang.reflect.Field;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.lang.reflect.Proxy;
import java.util.Collections;
import java.util.Iterator;
import java.util.List;
import java.util.concurrent.ConcurrentMap;

import javax.servlet.ServletContext;
import javax.servlet.http.HttpServletRequest;

import org.apache.guacamole.GuacamoleException;
import org.apache.guacamole.net.auth.AuthenticatedUser;
import org.apache.guacamole.net.auth.AuthenticationProvider;
import org.apache.guacamole.net.auth.Credentials;
import org.apache.guacamole.net.auth.UserContext;

/**
 * The parts of Guacamole's web application, as of 1.6.0, that logins shared
 * between servers need, which no extension API offers: where it keeps its
 * logins by token, the authentication providers, and how it builds a
 * login. Found by reflection, through the Guice injector Guacamole keeps in
 * its servlet context, once that is up. All reflection of this extension
 * on Guacamole's web application is here: if a later Guacamole changes
 * these, logins are not shared, and everything else still is.
 */
final class Internals {

    /**
     * The servlet context attribute holding Guacamole's injector
     * (GuacamoleServletContextListener.GUICE_INJECTOR).
     */
    private static final String INJECTOR_ATTRIBUTE = "GUAC_GUICE_INJECTOR";

    private static final String GUICE_FILTER = "com.google.inject.servlet.GuiceFilter";

    private final ClassLoader loader;
    private final Object tokenSessionMap;
    private final Field sessionMap;
    private final List<AuthenticationProvider> authProviders;
    private final Object listenerService;
    private final Constructor<?> newSession;
    private final Constructor<?> newDecorated;
    private final Constructor<?> newRedecorated;
    private final Method getAuthenticatedUser;
    private final Method getUserContexts;
    private final Method hasTunnels;
    private final Method getLastAccessedTime;
    private final Method invalidate;

    @SuppressWarnings("unchecked")
    private Internals(ClassLoader loader, Object injector) throws ReflectiveOperationException {

        this.loader = loader;
        Method getInstance = Class.forName("com.google.inject.Injector", false, loader)
                .getMethod("getInstance", Class.class);

        tokenSessionMap = getInstance.invoke(injector, load("org.apache.guacamole.rest.auth.TokenSessionMap"));
        if (!tokenSessionMap.getClass().getName().equals("org.apache.guacamole.rest.auth.HashTokenSessionMap"))
            throw new NoSuchFieldException("Logins are kept by " + tokenSessionMap.getClass().getName()
                    + ", not as in Guacamole 1.6.0.");
        sessionMap = accessible(tokenSessionMap.getClass().getDeclaredField("sessionMap"));

        Class<?> authenticationService = load("org.apache.guacamole.rest.auth.AuthenticationService");
        Object service = getInstance.invoke(injector, authenticationService);
        authProviders = (List<AuthenticationProvider>) accessible(authenticationService
                .getDeclaredField("authProviders")).get(service);
        listenerService = accessible(authenticationService.getDeclaredField("listenerService")).get(service);

        Class<?> session = load("org.apache.guacamole.GuacamoleSession");
        Class<?> decorated = load("org.apache.guacamole.rest.auth.DecoratedUserContext");
        newSession = session.getConstructor(load("org.apache.guacamole.rest.event.ListenerService"),
                AuthenticatedUser.class, List.class);
        newDecorated = decorated.getConstructor(AuthenticationProvider.class, UserContext.class,
                AuthenticatedUser.class, Credentials.class);
        newRedecorated = decorated.getConstructor(AuthenticationProvider.class, decorated,
                AuthenticatedUser.class, Credentials.class);
        getAuthenticatedUser = session.getMethod("getAuthenticatedUser");
        getUserContexts = session.getMethod("getUserContexts");
        hasTunnels = session.getMethod("hasTunnels");
        getLastAccessedTime = session.getMethod("getLastAccessedTime");
        invalidate = session.getMethod("invalidate");

    }

    /**
     * Guacamole's internals, or null if its web application is not up yet.
     *
     * @throws ReflectiveOperationException
     *     If they are not as in Guacamole 1.6.0.
     */
    static Internals find() throws ReflectiveOperationException {

        Class<?> filter = Class.forName(GUICE_FILTER, false, Internals.class.getClassLoader());
        WeakReference<?> reference = (WeakReference<?>) accessible(filter.getDeclaredField("servletContext"))
                .get(null);
        ServletContext context = reference == null ? null : (ServletContext) reference.get();
        if (context == null)
            return null;

        Object injector = context.getAttribute(INJECTOR_ATTRIBUTE);
        if (injector == null)
            return null;

        return new Internals(filter.getClassLoader(), injector);

    }

    /**
     * The request being handled by this thread, or null if none is, such
     * as for a WebSocket tunnel.
     */
    static HttpServletRequest currentRequest() {
        try {
            Class<?> filter = Class.forName(GUICE_FILTER, false, Internals.class.getClassLoader());
            Object context = ((ThreadLocal<?>) accessible(filter.getDeclaredField("localContext")).get(null)).get();
            if (context == null)
                return null;
            return (HttpServletRequest) accessible(context.getClass().getDeclaredField("originalRequest"))
                    .get(context);
        }
        catch (ReflectiveOperationException | RuntimeException e) {
            return null;
        }
    }

    /**
     * A request with nothing but the given addresses, for a login going on
     * where no request is being handled.
     */
    static HttpServletRequest placeholderRequest(String remoteAddress, String remoteHostname) {
        return (HttpServletRequest) Proxy.newProxyInstance(Internals.class.getClassLoader(),
                new Class<?>[] { HttpServletRequest.class }, (proxy, method, arguments) -> {
                    switch (method.getName()) {
                        case "getRemoteAddr": return remoteAddress;
                        case "getRemoteHost": return remoteHostname != null ? remoteHostname : remoteAddress;
                        case "getParameterMap": return Collections.emptyMap();
                        case "hashCode": return System.identityHashCode(proxy);
                        case "equals": return proxy == arguments[0];
                        case "toString": return "HttpServletRequest (placeholder)";
                        default: break;
                    }
                    Class<?> type = method.getReturnType();
                    if (type == java.util.Enumeration.class)
                        return Collections.emptyEnumeration();
                    if (type == boolean.class)
                        return false;
                    if (type == int.class)
                        return 0;
                    if (type == long.class)
                        return 0L;
                    return null;
                });
    }

    private Class<?> load(String name) throws ClassNotFoundException {
        return Class.forName(name, false, loader);
    }

    private static Field accessible(Field field) {
        field.setAccessible(true);
        return field;
    }

    /**
     * The map of logins by token, which the given one replaces. Logins
     * added to the old one meanwhile are in the map returned.
     */
    @SuppressWarnings("unchecked")
    ConcurrentMap<String, Object> replaceSessions(ConcurrentMap<String, Object> replacement)
            throws ReflectiveOperationException {
        synchronized (tokenSessionMap) {
            ConcurrentMap<String, Object> current = (ConcurrentMap<String, Object>) sessionMap.get(tokenSessionMap);
            sessionMap.set(tokenSessionMap, replacement);
            return current;
        }
    }

    List<AuthenticationProvider> getAuthProviders() {
        return authProviders;
    }

    AuthenticationProvider getAuthProvider(String identifier) {
        for (AuthenticationProvider provider : authProviders) {
            if (provider.getIdentifier().equals(identifier))
                return provider;
        }
        return null;
    }

    /**
     * A new login, as Guacamole keeps it.
     */
    Object newSession(AuthenticatedUser user, List<Object> userContexts) throws GuacamoleException,
            ReflectiveOperationException {
        return construct(newSession, listenerService, user, userContexts);
    }

    /**
     * A context as Guacamole keeps it in a login: decorated by every
     * extension in turn, as when refreshing a login rather than logging in,
     * so extensions checking a login as it starts, such as TOTP, do not ask
     * for more. The decorations then refresh with the login as Guacamole's
     * own.
     */
    Object decorate(UserContext context, AuthenticatedUser user, Credentials credentials)
            throws GuacamoleException, ReflectiveOperationException {
        Iterator<AuthenticationProvider> providers = authProviders.iterator();
        Object decorated = construct(newDecorated, new RedecoratingProvider(providers.next()), context, user,
                credentials);
        while (providers.hasNext())
            decorated = construct(newRedecorated, new RedecoratingProvider(providers.next()), decorated, user,
                    credentials);
        return decorated;
    }

    /**
     * Who logged in. Guacamole counts this as using the login.
     */
    AuthenticatedUser getAuthenticatedUser(Object session) throws ReflectiveOperationException {
        return (AuthenticatedUser) getAuthenticatedUser.invoke(session);
    }

    /**
     * The contexts of a login. Guacamole counts this as using the login.
     */
    List<?> getUserContexts(Object session) throws ReflectiveOperationException {
        return (List<?>) getUserContexts.invoke(session);
    }

    boolean hasTunnels(Object session) throws ReflectiveOperationException {
        return (Boolean) hasTunnels.invoke(session);
    }

    long getLastAccessedTime(Object session) throws ReflectiveOperationException {
        return (Long) getLastAccessedTime.invoke(session);
    }

    /**
     * Ends a login on this server, with its sessions.
     */
    void invalidate(Object session) throws ReflectiveOperationException {
        invalidate.invoke(session);
    }

    private static Object construct(Constructor<?> constructor, Object... arguments)
            throws GuacamoleException, ReflectiveOperationException {
        try {
            return constructor.newInstance(arguments);
        }
        catch (InvocationTargetException e) {
            Throwable cause = e.getCause();
            if (cause instanceof GuacamoleException)
                throw (GuacamoleException) cause;
            if (cause instanceof RuntimeException)
                throw (RuntimeException) cause;
            throw e;
        }
    }

    /**
     * A provider, decorating as it redecorates. Everything else is its own.
     */
    private static final class RedecoratingProvider implements AuthenticationProvider {

        private final AuthenticationProvider provider;

        RedecoratingProvider(AuthenticationProvider provider) {
            this.provider = provider;
        }

        @Override
        public String getIdentifier() {
            return provider.getIdentifier();
        }

        @Override
        public Object getResource() throws GuacamoleException {
            return provider.getResource();
        }

        @Override
        public Credentials updateCredentials(Credentials credentials) throws GuacamoleException {
            return provider.updateCredentials(credentials);
        }

        @Override
        public AuthenticatedUser authenticateUser(Credentials credentials) throws GuacamoleException {
            return provider.authenticateUser(credentials);
        }

        @Override
        public AuthenticatedUser updateAuthenticatedUser(AuthenticatedUser authenticatedUser,
                Credentials credentials) throws GuacamoleException {
            return provider.updateAuthenticatedUser(authenticatedUser, credentials);
        }

        @Override
        public UserContext getUserContext(AuthenticatedUser authenticatedUser) throws GuacamoleException {
            return provider.getUserContext(authenticatedUser);
        }

        @Override
        public UserContext updateUserContext(UserContext context, AuthenticatedUser authenticatedUser,
                Credentials credentials) throws GuacamoleException {
            return provider.updateUserContext(context, authenticatedUser, credentials);
        }

        @Override
        public UserContext decorate(UserContext context, AuthenticatedUser authenticatedUser,
                Credentials credentials) throws GuacamoleException {
            if (context.getAuthenticationProvider() == provider)
                return context;
            return provider.redecorate(null, context, authenticatedUser, credentials);
        }

        @Override
        public UserContext redecorate(UserContext decorated, UserContext context,
                AuthenticatedUser authenticatedUser, Credentials credentials) throws GuacamoleException {
            if (context.getAuthenticationProvider() == provider)
                return context;
            return provider.redecorate(decorated, context, authenticatedUser, credentials);
        }

        @Override
        public void shutdown() {
        }

    }

}
