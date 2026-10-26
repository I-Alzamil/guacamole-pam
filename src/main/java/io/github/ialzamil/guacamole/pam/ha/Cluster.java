package io.github.ialzamil.guacamole.pam.ha;

import java.io.IOException;
import java.net.InetAddress;
import java.util.Collection;
import java.util.EnumMap;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;

import org.apache.guacamole.GuacamoleException;
import org.apache.guacamole.environment.Environment;
import org.apache.guacamole.environment.LocalEnvironment;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * This server, as one of the Guacamole servers sharing their databases: the
 * sessions of each database configured, and the logins, failed logins, TOTP
 * codes and recordings shared through the first of them (PostgreSQL, then
 * MySQL or MariaDB, then SQL Server). One for the extension, shared by its
 * authentication provider and its listener, which Guacamole creates apart.
 */
final class Cluster {

    private static final Logger logger = LoggerFactory.getLogger(Cluster.class);

    private static Cluster instance;

    private final String serverId = UUID.randomUUID().toString();

    /**
     * This server's host name, and the version of this extension, as the
     * status page shows them.
     */
    private final String hostname = hostname();

    private final String version = Cluster.class.getPackage().getImplementationVersion();

    private final Config config;

    private final Map<DatabaseType, SessionStore> stores = new EnumMap<>(DatabaseType.class);

    private final SessionStore primary;

    private final LoginSync logins;

    private final BanSync bans;

    private final TotpSync codes;

    private final Recordings recordings;

    private final Status status = new Status(this);

    /**
     * Whether someone opening a share link may be let in by this extension,
     * on a server other than the session's: Guacamole's database
     * authentication would refuse them, or create an account for them, if
     * it requires or creates accounts for everyone.
     */
    private final boolean anonymousShares;

    private final ScheduledExecutorService executor;

    private boolean started;

    /**
     * The one cluster of this extension, set up on first use.
     */
    static synchronized Cluster get() {
        if (instance == null)
            instance = new Cluster();
        return instance;
    }

    private Cluster() {

        Environment environment = LocalEnvironment.getInstance();

        Config read = null;
        try {
            read = new Config(environment);
        }
        catch (GuacamoleException e) {
            logger.error("Nothing is shared between servers: {}", e.getMessage());
        }
        config = read;

        boolean anonymous = true;
        if (config != null) {
            for (DatabaseType type : DatabaseType.values()) {
                try {
                    Database database = Database.fromEnvironment(type, environment);
                    if (database == null)
                        continue;
                    stores.put(type, new SessionStore(database, Limits.Defaults.fromEnvironment(type,
                            environment), serverId, config.url, hostname, version));
                    if (environment.getProperty(Settings.bool(type.property("user-required")), false)
                            || environment.getProperty(Settings.bool(type.property("auto-create-accounts")),
                                    false))
                        anonymous = false;
                }
                catch (GuacamoleException e) {
                    logger.error("Sessions of the {} data source are not shared between servers: {}",
                            type.getIdentifier(), e.getMessage());
                }
            }
        }
        anonymousShares = anonymous;

        primary = stores.isEmpty() ? null : stores.values().iterator().next();
        if (primary == null) {
            logger.warn("No database authentication is configured (PostgreSQL, MySQL, MariaDB or SQL Server):"
                    + " nothing is shared between servers.");
            logins = null;
            bans = null;
            codes = null;
            recordings = null;
            executor = null;
            return;
        }

        logins = new LoginSync(primary, stores, config, anonymousShares);
        bans = config.ban ? new BanSync(primary, config) : null;
        codes = config.totp ? new TotpSync(primary, config) : null;
        recordings = config.fetchesRecordings() ? new Recordings(primary, config) : null;

        if (config.recordings && recordings == null)
            logger.info("Recordings are shown only by the server that has them: set \"pam-ha-url\" and"
                    + " \"pam-ha-secret\" to fetch them from each other, or share their storage.");
        if (!anonymousShares)
            logger.info("Share links open only on the server running the session shared: database"
                    + " authentication requires or creates accounts for everyone, which those opening them have"
                    + " not.");

        executor = Executors.newScheduledThreadPool(2, task -> {
            Thread thread = new Thread(task, "pam-ha");
            thread.setDaemon(true);
            return thread;
        });

    }

    /**
     * Starts sharing, once: the sessions of each database, then logins
     * once Guacamole is up, and recordings.
     */
    synchronized void start() {

        if (started || primary == null)
            return;
        started = true;

        executor.execute(() -> {
            for (SessionStore store : stores.values())
                store.start();
        });
        logins.start(executor);
        if (recordings != null)
            recordings.start(executor);
        if (bans != null) {
            bans.start(executor);
            logger.info("Failed logins are counted on every server, banning addresses after {} within {}"
                    + " seconds.", config.banMaxAttempts, config.banDurationSeconds);
        }
        if (codes != null)
            logger.info("TOTP codes used on any server may not be used again on another.");

    }

    synchronized void shutdown() {
        if (!started)
            return;
        started = false;
        logins.shutdown();
        executor.shutdownNow();
        for (SessionStore store : stores.values())
            store.shutdown();
    }

    private static String hostname() {
        try {
            return InetAddress.getLocalHost().getHostName();
        }
        catch (IOException | RuntimeException e) {
            return null;
        }
    }

    Config getConfig() {
        return config;
    }

    String getServerId() {
        return serverId;
    }

    /**
     * The sessions of the database of the given data source, or null if
     * not configured.
     */
    SessionStore getStore(DatabaseType type) {
        return type == null ? null : stores.get(type);
    }

    Collection<SessionStore> getStores() {
        return stores.values();
    }

    LoginSync getLogins() {
        return logins;
    }

    BanSync getBans() {
        return bans;
    }

    TotpSync getCodes() {
        return codes;
    }

    Recordings getRecordings() {
        return recordings;
    }

    boolean allowsAnonymousShares() {
        return anonymousShares;
    }

    Status getStatus() {
        return status;
    }

}
