package io.github.ialzamil.guacamole.pam.ha;

import java.sql.Connection;
import java.sql.SQLException;
import java.util.Collections;
import java.util.Map;
import java.util.WeakHashMap;

import org.apache.guacamole.GuacamoleException;
import org.apache.guacamole.language.TranslatableGuacamoleClientException;
import org.apache.guacamole.net.auth.AuthenticatedUser;
import org.apache.guacamole.net.auth.Credentials;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * TOTP codes used on every server, which may not be used again on any, as
 * the TOTP extension refuses a code used on its own server: for two periods
 * ("totp-period") after its first use. Refused with the TOTP extension's
 * own message.
 */
final class TotpSync {

    private static final Logger logger = LoggerFactory.getLogger(TotpSync.class);

    /**
     * The parameter the TOTP extension takes codes from.
     */
    private static final String CODE_PARAMETER = "guac-totp";

    private final SessionStore store;

    private final int keptSeconds;

    /**
     * The logins already checked: each login decorates every context it
     * gets, with the same credentials.
     */
    private final Map<Credentials, Boolean> checked = Collections.synchronizedMap(new WeakHashMap<>());

    TotpSync(SessionStore store, Config config) {
        this.store = store;
        this.keptSeconds = Math.max(1, config.totpPeriodSeconds) * 2;
    }

    /**
     * Records the TOTP code of a login, refusing it if already used, on
     * any server.
     */
    void check(AuthenticatedUser user, Credentials credentials) throws GuacamoleException {

        String code = credentials == null ? null : credentials.getParameter(CODE_PARAMETER);
        if (code == null || !store.isStarted() || checked.put(credentials, Boolean.TRUE) != null)
            return;

        String username = user.getIdentifier();
        try (Connection connection = store.getDatabase().connect()) {
            Sql.update(connection, "DELETE FROM pam_ha_totp WHERE used < "
                    + store.getDatabase().getType().secondsAgo(keptSeconds));
            try {
                Sql.update(connection, "INSERT INTO pam_ha_totp (username, code, used) VALUES (?, ?, "
                        + store.getDatabase().getType().now() + ")", username, code);
            }
            catch (SQLException e) {
                if (e.getSQLState() == null || !e.getSQLState().startsWith("23"))
                    throw e;
                logger.warn("Refusing TOTP code of user \"{}\" already used on a server.", username);
                throw new TranslatableGuacamoleClientException("Provided TOTP code is not valid.",
                        "TOTP.INFO_VERIFICATION_FAILED");
            }
        }
        catch (SQLException e) {
            logger.warn("Unable to check TOTP codes used on other servers: {}", e.getMessage());
        }

    }

}
