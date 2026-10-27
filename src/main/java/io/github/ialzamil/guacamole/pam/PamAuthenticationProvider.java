package io.github.ialzamil.guacamole.pam;

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
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import io.github.ialzamil.guacamole.pam.approval.ApprovalRepository;
import io.github.ialzamil.guacamole.pam.approval.ApprovalService;
import io.github.ialzamil.guacamole.pam.approval.Approver;
import io.github.ialzamil.guacamole.pam.approval.ApproverDirectory;
import io.github.ialzamil.guacamole.pam.approval.BadgePreferences;
import io.github.ialzamil.guacamole.pam.checkout.CheckoutRepository;
import io.github.ialzamil.guacamole.pam.checkout.CheckoutService;
import io.github.ialzamil.guacamole.pam.checkout.RequestService;
import io.github.ialzamil.guacamole.pam.coordination.Coordination;
import io.github.ialzamil.guacamole.pam.coordination.SingleServer;
import io.github.ialzamil.guacamole.pam.crypto.SecretMigration;
import io.github.ialzamil.guacamole.pam.crypto.Secrets;
import io.github.ialzamil.guacamole.pam.db.ConnectionRepository;
import io.github.ialzamil.guacamole.pam.db.ConnectionSecrets;
import io.github.ialzamil.guacamole.pam.db.PamDatabase;
import io.github.ialzamil.guacamole.pam.ha.HaAuthenticationProvider;
import io.github.ialzamil.guacamole.pam.ha.SharedCoordination;
import io.github.ialzamil.guacamole.pam.notification.Events;
import io.github.ialzamil.guacamole.pam.notification.email.Directory;
import io.github.ialzamil.guacamole.pam.notification.email.EmailLanguages;
import io.github.ialzamil.guacamole.pam.notification.email.EmailNotifier;
import io.github.ialzamil.guacamole.pam.notification.email.EmailPreferences;
import io.github.ialzamil.guacamole.pam.notification.syslog.SyslogNotifier;
import io.github.ialzamil.guacamole.pam.password.PasswordPolicyRepository;
import io.github.ialzamil.guacamole.pam.platform.PlatformImport;
import io.github.ialzamil.guacamole.pam.platform.PlatformRepository;
import io.github.ialzamil.guacamole.pam.rotation.RotationService;
import io.github.ialzamil.guacamole.pam.settings.PamSettings;

/**
 * Privileged access management extension. Every connection stored in the
 * database of Guacamole's database authentication (PostgreSQL, MySQL or SQL
 * Server) gets password management: stored only, or managed by a platform,
 * which rotates the password over SSH, LDAP or other management types. Also
 * adds "pam-account" connections: accounts whose password users request and
 * check out for a limited time instead of opening a session. Without one of
 * those authentications, it stays inactive: it logs why once, and changes
 * nothing.
 */
public class PamAuthenticationProvider extends AbstractAuthenticationProvider {

    private static final Logger logger = LoggerFactory.getLogger(PamAuthenticationProvider.class);

    /**
     * Identifier of this provider, and so the REST path
     * "api/session/ext/pam".
     */
    public static final String IDENTIFIER = "pam";


    private final PlatformRepository platforms;

    private final PasswordPolicyRepository passwordPolicies;

    private final PlatformImport platformImport;

    private final ConnectionRepository connections;

    private final RotationService rotationService;

    private final CheckoutService checkoutService;

    private final RequestService requestService;

    private final ApprovalRepository approvals;

    private final ApproverDirectory approvers;

    private final BadgePreferences badgePreferences;

    private final EmailPreferences emailPreferences;

    private final Directory emailDirectory;

    private final EmailLanguages emailLanguages;

    private final ApprovalService approvalService;

    private final SecretMigration secretMigration;

    private final ConnectionSecrets connectionSecrets;

    private final PamDatabase database;

    private final PamSettings settings;

    private final Events events;

    /**
     * Identifier of the auth provider whose connections are managed
     * ("postgresql", "mysql" or "sqlserver"), or null while inactive. The
     * rotation engine reads and writes that provider's tables directly.
     */
    private final String managedDataSource;

    /**
     * The managed data source's UserContext of each session, used for permission checks.
     * Keys are weak and compared by identity, so entries vanish with their
     * session.
     */
    private final Map<AuthenticatedUser, UserContext> dataSourceContexts =
            new MapMaker().weakKeys().makeMap();

    /**
     * Whether the extension is active: false without a Guacamole database
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
            passwordPolicies = null;
            platformImport = null;
            connections = null;
            rotationService = null;
            approvals = null;
            approvers = null;
            badgePreferences = null;
            emailPreferences = null;
            emailDirectory = null;
            emailLanguages = null;
            checkoutService = null;
            requestService = null;
            approvalService = null;
            secretMigration = null;
            connectionSecrets = null;
            database = null;
            settings = null;
            events = null;
            managedDataSource = null;
            return;
        }

        Secrets secrets = Secrets.fromEnvironment(environment);
        logEncryption(secrets);

        database = new PamDatabase(environment);
        managedDataSource = database.getDialect().getName();
        logger.info("The PAM extension manages the connections stored in {}.",
                database.getDialect().getDisplayName());
        // Alone on the database unless the HA module runs
        Coordination coordination = HaAuthenticationProvider.isEnabled() ? new SharedCoordination(database)
                : new SingleServer(database);
        events = new Events();
        settings = new PamSettings(database, environment, coordination, secrets, events);
        events.add(new SyslogNotifier(settings));
        CheckoutRepository checkouts = new CheckoutRepository(database);
        connectionSecrets = new ConnectionSecrets(database, secrets);
        passwordPolicies = new PasswordPolicyRepository(database);
        platforms = new PlatformRepository(database, secrets, passwordPolicies);
        platformImport = new PlatformImport(platforms);
        connections = new ConnectionRepository(database, secrets, connectionSecrets);
        secretMigration = new SecretMigration(database, platforms, connections, connectionSecrets, settings, secrets);
        rotationService = new RotationService(database, coordination, platforms, passwordPolicies, connections,
                checkouts, events);
        approvals = new ApprovalRepository(database);
        approvers = new ApproverDirectory(database);
        badgePreferences = new BadgePreferences(database);
        emailLanguages = new EmailLanguages(database, coordination, events);
        emailPreferences = new EmailPreferences(database, emailLanguages);
        emailDirectory = new Directory(database, approvers);
        events.add(new EmailNotifier(settings, emailDirectory, emailPreferences, emailLanguages));
        checkoutService = new CheckoutService(connections, checkouts, platforms, approvals, rotationService,
                settings, events);
        requestService = new RequestService(connections, platforms, checkouts, approvals, rotationService,
                checkoutService, events);
        approvalService = new ApprovalService(approvals, requestService, events);

        // Offer the Account connection type in the connection editor
        environment.getProtocols().putIfAbsent(AccountProtocol.NAME, AccountProtocol.PROTOCOL);

    }

    private static void logEncryption(Secrets secrets) {
        if (secrets.getError() != null)
            logger.error("Stored secrets cannot be encrypted or decrypted: {} Secrets stored as plaintext still"
                    + " work; encrypted ones do not until this is fixed.", secrets.getError());
        else if (secrets.isEncrypting())
            logger.info("Stored secrets are encrypted with key {}.", secrets.getKeyIds().get(0));
        else if (!secrets.getKeyIds().isEmpty())
            logger.warn("Decrypting every stored secret to plaintext (\"pam-encryption-decrypt\" is set).");
        else
            logger.info("Stored secrets are not encrypted: set \"pam-encryption-key\" to encrypt them.");
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

        if (!active || !managedDataSource.equals(context.getAuthenticationProvider().getIdentifier()))
            return context;

        dataSourceContexts.put(authenticatedUser, context);
        return new PamUserContextDecorator(context, rotationService, checkoutService, connectionSecrets);

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

    /**
     * Identifier of the data source whose connections are managed.
     */
    public String getManagedDataSource() {
        return managedDataSource;
    }

    public PlatformRepository getPlatforms() {
        return platforms;
    }

    public PlatformImport getPlatformImport() {
        return platformImport;
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

    public RequestService getRequestService() {
        return requestService;
    }

    public ApprovalService getApprovalService() {
        return approvalService;
    }

    public BadgePreferences getBadgePreferences() {
        return badgePreferences;
    }

    public EmailPreferences getEmailPreferences() {
        return emailPreferences;
    }

    public EmailLanguages getEmailLanguages() {
        return emailLanguages;
    }

    /**
     * Where emails go: the administrators, approvers and email addresses.
     */
    public Directory getEmailDirectory() {
        return emailDirectory;
    }

    public PasswordPolicyRepository getPasswordPolicies() {
        return passwordPolicies;
    }

    public PamSettings getSettings() {
        return settings;
    }

    public Events getEvents() {
        return events;
    }

    /**
     * Returns the user as an approver: whether they are an administrator,
     * and the connections their approval permission covers.
     *
     * @throws GuacamoleSecurityException
     *     If the user has no account in the managed data source.
     */
    public Approver getApprover(AuthenticatedUser authenticatedUser) throws GuacamoleException {
        String username = getUsername(authenticatedUser);
        return new Approver(username, isAdministrator(authenticatedUser),
                approvers.getApprovableConnections(username, authenticatedUser.getEffectiveUserGroups()));
    }

    /**
     * Returns the user's username in the managed data source, under which
     * their requests, checkouts and approvals are recorded and compared.
     * It may differ from the one they logged in with by case only: MySQL and
     * SQL Server compare usernames ignoring case by default, so "Bob"
     * logging in through LDAP is the database's "bob". Comparing that one
     * keeps such a user from approving their own request.
     *
     * @throws GuacamoleSecurityException
     *     If the user has no account in the managed data source.
     */
    public String getUsername(AuthenticatedUser authenticatedUser) throws GuacamoleException {
        return getDataSourceContext(authenticatedUser).self().getIdentifier();
    }

    @Override
    public void shutdown() {
        if (rotationService != null)
            rotationService.shutdown();
        if (secretMigration != null)
            secretMigration.shutdown();
        if (events != null)
            events.shutdown();
        if (database != null)
            database.close();
    }

}
