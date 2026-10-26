package io.github.ialzamil.guacamole.pam.ha;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

import org.apache.guacamole.GuacamoleException;
import org.apache.guacamole.language.TranslatableGuacamoleClientTooManyException;
import org.apache.guacamole.net.auth.Credentials;
import org.apache.guacamole.net.auth.credentials.GuacamoleInsufficientCredentialsException;
import org.apache.guacamole.net.event.AuthenticationFailureEvent;
import org.apache.guacamole.net.event.AuthenticationRequestReceivedEvent;
import org.apache.guacamole.net.event.AuthenticationSuccessEvent;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Failed logins counted on every server, as Guacamole's ban extension counts
 * them on each: an address that failed "ban-max-invalid-attempts" times,
 * the last less than "ban-address-duration" seconds ago, may not log in on
 * any server, until that long after its last failure. The ban extension
 * still bans on its own on each server, which never bans more.
 */
final class BanSync {

    private static final Logger logger = LoggerFactory.getLogger(BanSync.class);

    /**
     * How often the failures of addresses not seen for longer than a ban
     * lasts are removed: each address's are otherwise removed only once it
     * tries again, which addresses used once never do.
     */
    private static final int PURGE_SECONDS = 60;

    private final SessionStore store;

    private final int maxAttempts;

    private final int durationSeconds;

    BanSync(SessionStore store, Config config) {
        this.store = store;
        this.maxAttempts = config.banMaxAttempts;
        this.durationSeconds = config.banDurationSeconds;
    }

    void start(ScheduledExecutorService executor) {
        executor.scheduleWithFixedDelay(this::purge, PURGE_SECONDS, PURGE_SECONDS, TimeUnit.SECONDS);
    }

    private void purge() {
        if (!store.isStarted())
            return;
        try (Connection connection = store.getDatabase().connect()) {
            Sql.update(connection, "DELETE FROM pam_ha_ban WHERE last_failure < " + ago());
        }
        catch (SQLException | RuntimeException e) {
            logger.debug("Unable to remove old failed logins.", e);
        }
    }

    /**
     * Refuses a login from a banned address, and counts failed ones, as the
     * ban extension does: a login asking for more, such as a TOTP code, has
     * not failed.
     */
    void handleEvent(Object event) throws GuacamoleException {
        if (event instanceof AuthenticationRequestReceivedEvent)
            check(((AuthenticationRequestReceivedEvent) event).getCredentials(), false);
        else if (event instanceof AuthenticationFailureEvent) {
            AuthenticationFailureEvent failure = (AuthenticationFailureEvent) event;
            check(failure.getCredentials(),
                    !(failure.getFailure() instanceof GuacamoleInsufficientCredentialsException));
        }
        else if (event instanceof AuthenticationSuccessEvent)
            check(((AuthenticationSuccessEvent) event).getCredentials(), false);
    }

    private void check(Credentials credentials, boolean failed) throws GuacamoleException {

        if (credentials == null || credentials.isEmpty() || !store.isStarted())
            return;
        String address = credentials.getRemoteAddress();
        if (address == null)
            return;

        int failures;
        boolean recent;
        try (Connection connection = store.getDatabase().connect()) {

            if (failed && fail(connection, address) == 0) {
                try {
                    Sql.update(connection, "INSERT INTO pam_ha_ban (address, failures, last_failure)"
                            + " VALUES (?, 1, " + now() + ")", address);
                }
                catch (SQLException e) {
                    fail(connection, address);
                }
            }

            try (PreparedStatement statement = connection.prepareStatement("SELECT failures, CASE WHEN"
                    + " last_failure > " + ago() + " THEN 1 ELSE 0 END FROM pam_ha_ban WHERE address = ?")) {
                statement.setString(1, address);
                try (ResultSet results = statement.executeQuery()) {
                    if (!results.next())
                        return;
                    failures = results.getInt(1);
                    recent = results.getInt(2) != 0;
                }
            }

            if (!recent)
                Sql.update(connection, "DELETE FROM pam_ha_ban WHERE address = ? AND last_failure < "
                        + ago(), address);

        }
        catch (SQLException e) {
            logger.warn("Unable to count failed logins of every server: {}", e.getMessage());
            return;
        }

        if (failed)
            logger.info("Authentication has failed for address \"{}\" (total failures on every server: {}/{}).",
                    address, failures, maxAttempts);

        if (recent && failures >= maxAttempts) {
            logger.warn("Blocking authentication attempt from address \"{}\" due to number of authentication"
                    + " failures on every server.", address);
            throw new TranslatableGuacamoleClientTooManyException("Too many failed authentication attempts.",
                    "LOGIN.ERROR_TOO_MANY_ATTEMPTS");
        }

    }

    /**
     * Counts one more failure of an address already counted, from one if
     * its last was long ago. Returns the rows changed: none if the
     * address was not counted yet.
     */
    private int fail(Connection connection, String address) throws SQLException {
        return Sql.update(connection, "UPDATE pam_ha_ban SET failures = CASE WHEN last_failure < " + ago()
                + " THEN 1 ELSE failures + 1 END, last_failure = " + now() + " WHERE address = ?", address);
    }

    private String now() {
        return store.getDatabase().getType().now();
    }

    private String ago() {
        return store.getDatabase().getType().secondsAgo(durationSeconds);
    }

}
