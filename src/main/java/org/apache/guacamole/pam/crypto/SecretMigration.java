package org.apache.guacamole.pam.crypto;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.concurrent.Executors;
import java.util.concurrent.RejectedExecutionException;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

import org.apache.guacamole.GuacamoleException;
import org.apache.guacamole.GuacamoleServerException;
import org.apache.guacamole.pam.db.ConnectionRepository;
import org.apache.guacamole.pam.db.PamDatabase;
import org.apache.guacamole.pam.db.SchemaUnavailableException;
import org.apache.guacamole.pam.platform.PlatformRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Brings stored secrets to the form {@link Secrets} requires: encrypts
 * plaintext once a key is set, encrypts again what earlier keys encrypted,
 * or decrypts everything when asked to. Runs shortly after start (retried
 * every few minutes until the database can be used), then hourly, catching
 * values written another way (by hand, or by a server with other settings).
 * One server at a time migrates, under a database lock.
 */
public class SecretMigration {

    private static final Logger logger = LoggerFactory.getLogger(SecretMigration.class);

    /**
     * Key of the migration's advisory lock ("pams").
     */
    private static final int LOCK = 0x70616d73;

    private static final long FIRST_RUN_SECONDS = 10;

    private static final long INTERVAL_SECONDS = TimeUnit.HOURS.toSeconds(1);

    private static final long RETRY_SECONDS = TimeUnit.MINUTES.toSeconds(5);

    private final PamDatabase database;

    private final PlatformRepository platforms;

    private final ConnectionRepository connections;

    private final Secrets secrets;

    private final ScheduledExecutorService scheduler = Executors.newSingleThreadScheduledExecutor(runnable -> {
        Thread thread = new Thread(runnable, "pam-secrets");
        thread.setDaemon(true);
        return thread;
    });

    public SecretMigration(PamDatabase database, PlatformRepository platforms, ConnectionRepository connections,
            Secrets secrets) {
        this.database = database;
        this.platforms = platforms;
        this.connections = connections;
        this.secrets = secrets;
        scheduler.schedule(this::migrate, FIRST_RUN_SECONDS, TimeUnit.SECONDS);
    }

    /**
     * Migrates every secret now, unless another server is doing so (then
     * returns null).
     */
    MigrationReport run() throws GuacamoleException {

        try (Connection lock = database.getConnection()) {

            try (PreparedStatement statement = lock.prepareStatement("SELECT pg_try_advisory_lock(?)")) {
                statement.setInt(1, LOCK);
                try (ResultSet results = statement.executeQuery()) {
                    if (!results.next() || !results.getBoolean(1))
                        return null;
                }
            }

            // Closing the lock's connection releases it
            MigrationReport report = new MigrationReport();
            platforms.migrateSecrets(report);
            connections.migrateSecrets(report);
            return report;

        }
        catch (SQLException e) {
            throw new GuacamoleServerException("Unable to lock the secrets for migration.", e);
        }

    }

    private void migrate() {

        long next = RETRY_SECONDS;
        try {
            MigrationReport report = run();
            if (report != null && report.getChanged() > 0)
                logger.info("{} stored secret(s) {}.", report.getChanged(), secrets.isEncrypting()
                        ? "encrypted with key " + secrets.getKeyIds().get(0) : "decrypted to plaintext");
            if (report != null && !report.getUnreadable().isEmpty())
                logger.warn("Stored secrets that cannot be decrypted here, by key: {}. They fail where used until"
                        + " their key is set in \"pam-encryption-key\" or \"pam-encryption-old-keys\".",
                        report.getUnreadable());
            next = INTERVAL_SECONDS;
        }
        catch (SchemaUnavailableException e) {
            logger.debug("Secret migration skipped: {}", e.getMessage());
        }
        catch (Exception e) {
            logger.error("Secret migration failed: {}", e.getMessage());
            logger.debug("Secret migration failed.", e);
        }

        try {
            scheduler.schedule(this::migrate, next, TimeUnit.SECONDS);
        }
        catch (RejectedExecutionException e) {
            // Shutting down
        }

    }

    public void shutdown() {
        scheduler.shutdownNow();
    }

}
