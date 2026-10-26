package io.github.ialzamil.guacamole.pam.rotation;

import java.net.InetAddress;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.UUID;

import org.apache.guacamole.GuacamoleException;
import org.apache.guacamole.GuacamoleServerException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import io.github.ialzamil.guacamole.pam.db.PamDatabase;
import io.github.ialzamil.guacamole.pam.db.SqlDialect;
import io.github.ialzamil.guacamole.pam.ha.HaAuthenticationProvider;

/**
 * The Guacamole servers running the extension on the database, in
 * "pam_server": each refreshes its row with every heartbeat, and removes it
 * when it stops. A server not heard from for as long as its sessions stay
 * trusted no longer counts. PAM itself works across servers without the HA
 * module, but Guacamole does not: several servers without it are warned of.
 */
class ServerRegistry {

    private static final Logger logger = LoggerFactory.getLogger(ServerRegistry.class);

    private final PamDatabase database;

    private final SqlDialect dialect;

    /**
     * Identifies this server, in its rows here and in "pam_session": its
     * host name, made unique per start.
     */
    private final String server = hostName() + "/" + UUID.randomUUID().toString().substring(0, 8);

    /**
     * How many servers were running when last warned of, so the warning is
     * logged once, and again only if more start.
     */
    private int warned = 1;

    ServerRegistry(PamDatabase database) {
        this.database = database;
        this.dialect = database.getDialect();
    }

    private static String hostName() {
        try {
            return InetAddress.getLocalHost().getHostName();
        }
        catch (Exception e) {
            return "guacamole";
        }
    }

    String getServer() {
        return server;
    }

    /**
     * Refreshes this server's row, recording it if missing, and warns if
     * other servers run on the database without the HA module.
     */
    void heartbeat() throws GuacamoleException {

        Map<String, String> values = new LinkedHashMap<>();
        values.put("server", "?");

        try (Connection connection = database.getConnection();
             PreparedStatement statement = connection.prepareStatement(dialect.upsert("pam_server",
                     Collections.singletonList("server"), values, "heartbeat = " + dialect.now()))) {
            statement.setString(1, server);
            statement.executeUpdate();
        }
        catch (SQLException e) {
            throw new GuacamoleServerException("Unable to record this server.", e);
        }

        int running = count();
        if (running > warned && !HaAuthenticationProvider.isEnabled())
            logger.warn("{} Guacamole servers share this database without the HA module: PAM works across them,"
                    + " but each keeps its own logins, connection limits, Active Sessions, share links, failed"
                    + " logins and TOTP codes. Set \"pam-ha: true\" on every server to share them.", running);
        warned = Math.max(warned, running);

    }

    /**
     * How many servers run the extension on the database, this one
     * included once it has reported.
     */
    int count() throws GuacamoleException {
        try (Connection connection = database.getConnection();
             PreparedStatement statement = connection.prepareStatement("SELECT COUNT(*) FROM pam_server WHERE"
                     + " heartbeat > " + dialect.plusSeconds(dialect.now(),
                             Integer.toString(-SessionRegistry.STALE_SECONDS)));
             ResultSet results = statement.executeQuery()) {
            return results.next() ? results.getInt(1) : 0;
        }
        catch (SQLException e) {
            throw new GuacamoleServerException("Unable to count the servers.", e);
        }
    }

    /**
     * Removes this server's row, as it stops.
     */
    void remove() {
        try (Connection connection = database.getConnection();
             PreparedStatement statement = connection.prepareStatement("DELETE FROM pam_server WHERE server = ?")) {
            statement.setString(1, server);
            statement.executeUpdate();
        }
        catch (GuacamoleException | SQLException e) {
            logger.debug("Unable to remove this server's row: {}", e.getMessage());
        }
    }

}
