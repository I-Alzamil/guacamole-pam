package io.github.ialzamil.guacamole.pam.ha;

import java.lang.reflect.Method;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.Locale;

import org.apache.guacamole.GuacamoleException;
import org.apache.guacamole.net.DelegatingGuacamoleSocket;
import org.apache.guacamole.net.GuacamoleSocket;
import org.apache.guacamole.net.GuacamoleTunnel;
import org.apache.guacamole.protocol.ConfiguredGuacamoleSocket;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Where the tunnel of a session runs: its guacd, and its connection there,
 * which sessions of other servers join, as Guacamole's own sharing joins
 * it.
 */
final class Tunnels {

    private static final Logger logger = LoggerFactory.getLogger(Tunnels.class);

    /**
     * DelegatingGuacamoleSocket.getDelegateSocket(), protected: the socket
     * of a tunnel is the guacd connection wrapped in others, such as the
     * one Guacamole fails over with.
     */
    private static final Method DELEGATE_SOCKET;

    static {
        Method method = null;
        try {
            method = DelegatingGuacamoleSocket.class.getDeclaredMethod("getDelegateSocket");
            method.setAccessible(true);
        }
        catch (ReflectiveOperationException | RuntimeException e) {
            logger.warn("Sessions cannot be joined from other servers: {}", e.getMessage());
        }
        DELEGATE_SOCKET = method;
    }

    private Tunnels() {
    }

    /**
     * The identifier guacd gave the connection of a tunnel, or null if not
     * found.
     */
    static String guacdConnectionId(GuacamoleTunnel tunnel) {

        GuacamoleSocket socket = tunnel.getSocket();
        for (int depth = 0; socket != null && depth < 16; depth++) {
            if (socket instanceof ConfiguredGuacamoleSocket)
                return ((ConfiguredGuacamoleSocket) socket).getConnectionID();
            if (!(socket instanceof DelegatingGuacamoleSocket) || DELEGATE_SOCKET == null)
                return null;
            try {
                socket = (GuacamoleSocket) DELEGATE_SOCKET.invoke(socket);
            }
            catch (ReflectiveOperationException | RuntimeException e) {
                logger.debug("Unable to unwrap the socket of a tunnel.", e);
                return null;
            }
        }
        return null;

    }

    /**
     * The guacd the given connection of Guacamole's database uses, as its
     * own settings or else guacamole.properties set it, and as other
     * servers reach it; null if they cannot: it is this server's own
     * ("localhost") and "pam-ha-guacd-hostname" is not set.
     */
    static SessionRow.Guacd guacd(Database database, Config config, String connectionId,
            String guacdConnectionId) {

        if (guacdConnectionId == null)
            return null;

        String hostname = null;
        Integer port = null;
        String encryption = null;
        Integer id = Sql.id(connectionId);
        if (id != null) {
            try (Connection connection = database.connect();
                 PreparedStatement statement = connection.prepareStatement("SELECT proxy_hostname, proxy_port,"
                     + " proxy_encryption_method FROM guacamole_connection WHERE connection_id = ?")) {
                statement.setInt(1, id);
                try (ResultSet results = statement.executeQuery()) {
                    if (results.next()) {
                        hostname = results.getString(1);
                        int value = results.getInt(2);
                        port = results.wasNull() ? null : value;
                        encryption = results.getString(3);
                    }
                }
            }
            catch (SQLException e) {
                logger.debug("Unable to read the guacd settings of connection {}.", connectionId, e);
            }
        }

        if (hostname == null || hostname.trim().isEmpty())
            hostname = config.defaultGuacdHostname;
        boolean ssl = encryption != null ? encryption.equalsIgnoreCase("SSL") : config.defaultGuacdSsl;

        if (isLocal(hostname)) {
            if (config.guacdHostname == null)
                return null;
            hostname = config.guacdHostname;
        }

        return new SessionRow.Guacd(hostname, port != null ? port : config.defaultGuacdPort, ssl,
                guacdConnectionId);

    }

    /**
     * Whether a host name is this server itself, which other servers reach
     * by another name.
     */
    /**
     * Closes a tunnel, if any, ignoring a failure to.
     */
    static void closeQuietly(GuacamoleTunnel tunnel) {
        if (tunnel == null)
            return;
        try {
            tunnel.close();
        }
        catch (GuacamoleException | RuntimeException e) {
            logger.debug("Unable to close a tunnel.", e);
        }
    }

    static boolean isLocal(String hostname) {
        String name = hostname.trim().toLowerCase(Locale.ROOT);
        if (name.startsWith("[") && name.endsWith("]"))
            name = name.substring(1, name.length() - 1);
        return name.equals("localhost") || name.startsWith("127.") || name.equals("::1")
                || name.equals("0:0:0:0:0:0:0:1") || name.equals("0.0.0.0");
    }

}
