package org.apache.guacamole.pam;

import java.util.LinkedHashMap;
import java.util.List;
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
import org.apache.guacamole.pam.crypto.SecretMigration;
import org.apache.guacamole.pam.crypto.Secrets;
import org.apache.guacamole.pam.db.ConnectionRepository;
import org.apache.guacamole.pam.db.PamDatabase;
import org.apache.guacamole.pam.db.ConnectionSecrets;
import org.apache.guacamole.pam.platform.PlatformImport;
import org.apache.guacamole.pam.platform.PlatformRepository;
import org.apache.guacamole.pam.rotation.RotationService;
import org.apache.guacamole.pam.settings.PamSettings;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

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

    private final PlatformImport platformImport;

    private final ConnectionRepository connections;

    private final RotationService rotationService;

    private final CheckoutService checkoutService;

    private final ApprovalRepository approvals;

    private final BadgePreferences badgePreferences;

    private final ApprovalService approvalService;

    private final SecretMigration secretMigration;

    private final ConnectionSecrets connectionSecrets;

    private final PamDatabase database;

    private final PamSettings settings;

    /**
     * How stored secrets are protected on this server, as set in its
     * guacamole.properties, or null while inactive.
     */
    private final Secrets secrets;

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
            platformImport = null;
            connections = null;
            rotationService = null;
            approvals = null;
            badgePreferences = null;
            checkoutService = null;
            approvalService = null;
            secretMigration = null;
            connectionSecrets = null;
            database = null;
            settings = null;
            secrets = null;
            managedDataSource = null;
            return;
        }

        secrets = Secrets.fromEnvironment(environment);
        logEncryption(secrets);

        database = new PamDatabase(environment);
        managedDataSource = database.getDialect().getName();
        logger.info("The PAM extension manages the connections stored in {}.",
                database.getDialect().getDisplayName());
        settings = new PamSettings(database, environment);
        CheckoutRepository checkouts = new CheckoutRepository(database);
        connectionSecrets = new ConnectionSecrets(database, secrets);
        platforms = new PlatformRepository(database, secrets);
        platformImport = new PlatformImport(platforms);
        connections = new ConnectionRepository(database, secrets, connectionSecrets);
        secretMigration = new SecretMigration(database, platforms, connections, connectionSecrets, secrets);
        rotationService = new RotationService(database, platforms, connections, checkouts);
        approvals = new ApprovalRepository(database);
        badgePreferences = new BadgePreferences(database);
        checkoutService = new CheckoutService(connections, checkouts, platforms, approvals, rotationService,
                settings);
        approvalService = new ApprovalService(approvals, checkoutService);

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

    public ApprovalService getApprovalService() {
        return approvalService;
    }

    public BadgePreferences getBadgePreferences() {
        return badgePreferences;
    }

    public PamSettings getSettings() {
        return settings;
    }

    /**
     * The settings of this server that stay in its guacamole.properties, as
     * the settings page shows them: the database ("database", its name),
     * its connection pool ("maxConnections"), and how stored secrets are
     * protected ("encryption": "encrypted", "decrypting", "none" or
     * "error", with "keyId", "oldKeys" and "error").
     */
    public Map<String, Object> getServerSettings() {
        Map<String, Object> server = new LinkedHashMap<>();
        server.put("database", database.getDialect().getDisplayName());
        server.put("maxConnections", database.getMaxConnections());
        List<String> keyIds = secrets.getKeyIds();
        if (secrets.getError() != null) {
            server.put("encryption", "error");
            server.put("error", secrets.getError());
        }
        else if (secrets.isEncrypting()) {
            server.put("encryption", "encrypted");
            server.put("keyId", keyIds.get(0));
            server.put("oldKeys", keyIds.size() - 1);
        }
        else
            server.put("encryption", keyIds.isEmpty() ? "none" : "decrypting");
        return server;
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
                approvals.getApprovableConnections(username, authenticatedUser.getEffectiveUserGroups()));
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
        if (database != null)
            database.close();
    }

}
