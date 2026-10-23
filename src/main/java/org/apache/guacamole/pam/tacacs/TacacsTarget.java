package org.apache.guacamole.pam.tacacs;

import java.util.Map;

import org.apache.guacamole.pam.Values;

/**
 * A TACACS+ account and the servers holding it, read from the settings of a
 * TACACS+ platform combined with the account of a connection.
 */
public final class TacacsTarget {

    public static final String SERVER = "tacacs-server";
    public static final String PORT = "tacacs-port";

    /**
     * Server tried when the first cannot be reached, or empty.
     */
    public static final String BACKUP_SERVER = "tacacs-backup-server";

    /**
     * Key shared with the servers, which obfuscates every packet.
     */
    public static final String SECRET = "tacacs-secret";

    public static final String USERNAME = "tacacs-username";
    public static final String PASSWORD = "password";

    public static final int DEFAULT_PORT = 49;

    private final String server;
    private final String backupServer;
    private final int port;
    private final String secret;
    private final String username;
    private final String password;

    private TacacsTarget(String server, String backupServer, int port, String secret, String username,
            String password) {
        this.server = server;
        this.backupServer = backupServer;
        this.port = port;
        this.secret = secret;
        this.username = username;
        this.password = password;
    }

    /**
     * Reads the target from the given settings.
     *
     * @throws IllegalArgumentException
     *     If a required parameter is missing or invalid.
     */
    public static TacacsTarget fromParameters(Map<String, String> parameters) {

        String server = Values.trimToNull(parameters.get(SERVER));
        if (server == null)
            throw new IllegalArgumentException("The platform has no TACACS+ server.");

        String secret = Values.emptyToNull(parameters.get(SECRET));
        if (secret == null)
            throw new IllegalArgumentException("The platform has no shared secret.");

        String username = Values.trimToNull(parameters.get(USERNAME));
        if (username == null)
            throw new IllegalArgumentException("The connection has no TACACS+ username and no username.");

        return new TacacsTarget(server, Values.trimToNull(parameters.get(BACKUP_SERVER)),
                Values.parsePort(parameters.get(PORT), DEFAULT_PORT), secret, username,
                Values.emptyToNull(parameters.get(PASSWORD)));

    }

    public TacacsTarget withPassword(String newPassword) {
        return new TacacsTarget(server, backupServer, port, secret, username, newPassword);
    }

    public String getServer() {
        return server;
    }

    /**
     * The server tried when the first cannot be reached, or null.
     */
    public String getBackupServer() {
        return backupServer;
    }

    public int getPort() {
        return port;
    }

    public String getSecret() {
        return secret;
    }

    public String getUsername() {
        return username;
    }

    public String getPassword() {
        return password;
    }

}
