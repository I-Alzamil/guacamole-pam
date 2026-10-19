package org.apache.guacamole.pam;

import java.util.Map;

import com.google.common.collect.MapMaker;

import org.apache.guacamole.GuacamoleException;
import org.apache.guacamole.GuacamoleSecurityException;
import org.apache.guacamole.environment.Environment;
import org.apache.guacamole.environment.LocalEnvironment;
import org.apache.guacamole.net.auth.AbstractAuthenticationProvider;
import org.apache.guacamole.net.auth.AuthenticatedUser;
import org.apache.guacamole.net.auth.Credentials;
import org.apache.guacamole.net.auth.UserContext;
import org.apache.guacamole.net.auth.permission.SystemPermission;
import org.apache.guacamole.pam.approval.ApprovalRepository;
import org.apache.guacamole.pam.approval.BadgePreferences;
import org.apache.guacamole.pam.approval.Approver;
import org.apache.guacamole.pam.approval.ApprovalService;
import org.apache.guacamole.pam.checkout.CheckoutRepository;
import org.apache.guacamole.pam.checkout.CheckoutService;
import org.apache.guacamole.pam.db.ConnectionRepository;
import org.apache.guacamole.pam.db.PamDatabase;
import org.apache.guacamole.pam.platform.PlatformRepository;
import org.apache.guacamole.pam.rotation.RotationService;
import org.apache.guacamole.properties.BooleanGuacamoleProperty;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Privileged access management extension. Every connection stored in the
 * PostgreSQL database gets password management: stored only, or managed by a
 * platform, which rotates the password over SSH, LDAP or other management
 * types. Also adds "pam-account" connections: accounts whose password users
 * request and check out for a limited time instead of opening a session.
 * Without Guacamole's PostgreSQL authentication, it stays inactive: it logs
 * why once, and changes nothing.
 */
public class PamAuthenticationProvider extends AbstractAuthenticationProvider {

    private static final Logger logger = LoggerFactory.getLogger(PamAuthenticationProvider.class);

    /**
     * Identifier of this provider, and so the REST path
     * "api/session/ext/pam".
     */
    public static final String IDENTIFIER = "pam";

    /**
     * Identifier of the auth provider whose connections are managed. The
     * rotation engine reads and writes that provider's tables directly.
     */
    private static final String MANAGED_DATA_SOURCE = "postgresql";

    /**
     * Whether administrators connect, and check out Accounts, without a
     * request. False by default: administrators then skip approvals only,
     * and give a reason like anyone else.
     */
    private static final BooleanGuacamoleProperty ADMIN_BYPASS_REQUESTS = new BooleanGuacamoleProperty() {
        @Override
        public String getName() { return "pam-admin-bypass-requests"; }
    };

    private final PlatformRepository platforms;

    private final ConnectionRepository connections;

    private final RotationService rotationService;

    private final CheckoutService checkoutService;

    private final ApprovalRepository approvals;

    private final BadgePreferences badgePreferences;

    private final ApprovalService approvalService;

    /**
     * The PostgreSQL UserContext of each session, used for permission checks.
     * Keys are weak and compared by identity, so entries vanish with their
     * session.
     */
    private final Map<AuthenticatedUser, UserContext> dataSourceContexts =
            new MapMaker().weakKeys().makeMap();

    /**
     * Whether the extension is active: false without Guacamole's PostgreSQL
     * authentication, in which case every service is null.
     */
    private final boolean active;

    public PamAuthenticationProvider() throws GuacamoleException {

        Environment environment = LocalEnvironment.getInstance();

        String unavailable = PamDatabase.getUnavailableReason(environment);
        active = unavailable == null;

        if (!active) {
            logger.warn("The PAM extension is inactive: {} Guacamole works as without it.", unavailable);
            platforms = null;
            connections = null;
            rotationService = null;
            approvals = null;
            badgePreferences = null;
            checkoutService = null;
            approvalService = null;
            return;
        }

        PamDatabase database = new PamDatabase(environment);
        CheckoutRepository checkouts = new CheckoutRepository(database);
        platforms = new PlatformRepository(database);
        connections = new ConnectionRepository(database);
        rotationService = new RotationService(platforms, connections, checkouts);
        approvals = new ApprovalRepository(database);
        badgePreferences = new BadgePreferences(database);
        checkoutService = new CheckoutService(connections, checkouts, platforms, approvals, rotationService,
                environment.getProperty(ADMIN_BYPASS_REQUESTS, false));
        approvalService = new ApprovalService(approvals, checkoutService);

        // Offer the Account connection type in the connection editor
        environment.getProtocols().putIfAbsent(AccountProtocol.NAME, AccountProtocol.PROTOCOL);

    }

    @Override
    public String getIdentifier() {
        return IDENTIFIER;
    }

    @Override
    public UserContext getUserContext(AuthenticatedUser authenticatedUser)
            throws GuacamoleException {

        // Inactive: no REST API, so the web UI shows none of the extension
        if (!active)
            return null;

        return new PamUserContext(this, authenticatedUser);

    }

    @Override
    public UserContext decorate(UserContext context,
            AuthenticatedUser authenticatedUser, Credentials credentials)
            throws GuacamoleException {

        if (!active || !MANAGED_DATA_SOURCE.equals(context.getAuthenticationProvider().getIdentifier()))
            return context;

        dataSourceContexts.put(authenticatedUser, context);
        return new PamUserContextDecorator(context, rotationService, checkoutService);

    }

    /**
     * Returns the user's UserContext of the managed data source, through
     * which Guacamole's own permission checks are applied.
     *
     * @throws GuacamoleSecurityException
     *     If the user has no account in the managed data source.
     */
    public UserContext getDataSourceContext(AuthenticatedUser authenticatedUser)
            throws GuacamoleSecurityException {
        UserContext context = dataSourceContexts.get(authenticatedUser);
        if (context == null)
            throw new GuacamoleSecurityException("Permission denied.");
        return context;
    }

    /**
     * Returns whether the given user holds the ADMINISTER system permission
     * within the managed data source. Only administrators may edit profiles
     * or trigger rotations.
     */
    public boolean isAdministrator(AuthenticatedUser authenticatedUser)
            throws GuacamoleException {

        UserContext context = dataSourceContexts.get(authenticatedUser);
        if (context == null)
            return false;

        return context.self().getEffectivePermissions().getSystemPermissions()
                .hasPermission(SystemPermission.Type.ADMINISTER);

    }

    public PlatformRepository getPlatforms() {
        return platforms;
    }

    public ConnectionRepository getConnections() {
        return connections;
    }

    public RotationService getRotationService() {
        return rotationService;
    }

    public CheckoutService getCheckoutService() {
        return checkoutService;
    }

    public ApprovalService getApprovalService() {
        return approvalService;
    }

    public BadgePreferences getBadgePreferences() {
        return badgePreferences;
    }

    /**
     * Returns the user as an approver: whether they are an administrator,
     * and the connections their approval permission covers.
     *
     * @throws GuacamoleSecurityException
     *     If the user has no account in the managed data source.
     */
    public Approver getApprover(AuthenticatedUser authenticatedUser) throws GuacamoleException {
        getDataSourceContext(authenticatedUser);
        return new Approver(authenticatedUser.getIdentifier(), isAdministrator(authenticatedUser),
                approvals.getApprovableConnections(authenticatedUser.getIdentifier(),
                        authenticatedUser.getEffectiveUserGroups()));
    }

    @Override
    public void shutdown() {
        if (rotationService != null)
            rotationService.shutdown();
    }

}
