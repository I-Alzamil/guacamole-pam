package io.github.ialzamil.guacamole.pam.ldap;

import java.util.Map;

import io.github.ialzamil.guacamole.pam.Values;

/**
 * A directory account and the server holding it, read from the settings of
 * an LDAP platform combined with the account of a connection.
 */
public final class LdapTarget {

    public static final String HOSTNAME = "hostname";
    public static final String PORT = "port";

    /**
     * "" for LDAPS (the default), "starttls", or "none".
     */
    public static final String ENCRYPTION = "ldap-encryption";
    public static final String ENCRYPTION_STARTTLS = "starttls";
    public static final String ENCRYPTION_NONE = "none";

    /**
     * Optional SHA-256 fingerprint the server certificate must match. When
     * empty, the certificate must be trusted by the JVM and match the hostname.
     */
    public static final String CERTIFICATE = "ldap-certificate-fingerprint";

    /**
     * "" for standard LDAP (RFC 3062 password modify), or "active-directory"
     * (unicodePwd).
     */
    public static final String DIRECTORY_TYPE = "ldap-directory-type";
    public static final String DIRECTORY_ACTIVE_DIRECTORY = "active-directory";

    /**
     * Optional account allowed to reset the password. Without it, the
     * account changes its own password.
     */
    public static final String ADMIN_DN = "ldap-admin-dn";
    public static final String ADMIN_PASSWORD = "ldap-admin-password";

    public static final String USER_DN = "ldap-user-dn";
    public static final String USERNAME = "username";
    public static final String PASSWORD = "password";

    public enum Encryption { LDAPS, STARTTLS, NONE }

    private final String hostname;
    private final int port;
    private final Encryption encryption;
    private final String pinnedCertificate;
    private final boolean activeDirectory;
    private final String userDn;
    private final String username;
    private final String password;
    private final String adminDn;
    private final String adminPassword;

    private LdapTarget(String hostname, int port, Encryption encryption, String pinnedCertificate,
            boolean activeDirectory, String userDn, String username, String password,
            String adminDn, String adminPassword) {
        this.hostname = hostname;
        this.port = port;
        this.encryption = encryption;
        this.pinnedCertificate = pinnedCertificate;
        this.activeDirectory = activeDirectory;
        this.userDn = userDn;
        this.username = username;
        this.password = password;
        this.adminDn = adminDn;
        this.adminPassword = adminPassword;
    }

    /**
     * Reads the target from the given settings.
     *
     * @throws IllegalArgumentException
     *     If a required parameter is missing or the combination is unsafe.
     */
    public static LdapTarget fromParameters(Map<String, String> parameters) {

        String hostname = value(parameters, HOSTNAME);
        if (hostname == null)
            throw new IllegalArgumentException("No LDAP server hostname is set.");

        String userDn = value(parameters, USER_DN);
        if (userDn == null)
            throw new IllegalArgumentException("No account DN is set.");

        Encryption encryption = Encryption.LDAPS;
        if (ENCRYPTION_STARTTLS.equals(value(parameters, ENCRYPTION)))
            encryption = Encryption.STARTTLS;
        else if (ENCRYPTION_NONE.equals(value(parameters, ENCRYPTION)))
            encryption = Encryption.NONE;

        boolean activeDirectory = DIRECTORY_ACTIVE_DIRECTORY.equals(
                value(parameters, DIRECTORY_TYPE));
        if (activeDirectory && encryption == Encryption.NONE)
            throw new IllegalArgumentException("Active Directory only accepts password changes over LDAPS or StartTLS.");

        Integer port = Values.toPort(value(parameters, PORT));
        if (value(parameters, PORT) != null && port == null)
            throw new IllegalArgumentException("Invalid LDAP port \"" + value(parameters, PORT) + "\".");
        if (port == null)
            port = encryption == Encryption.LDAPS ? 636 : 389;

        String adminDn = value(parameters, ADMIN_DN);
        String adminPassword = parameters.get(ADMIN_PASSWORD);
        if (adminDn != null && (adminPassword == null || adminPassword.isEmpty()))
            throw new IllegalArgumentException("The rotation account has no password.");

        // A rotation account can usually change any password in the
        // directory, so its credentials never travel unencrypted
        if (adminDn != null && encryption == Encryption.NONE)
            throw new IllegalArgumentException("A rotation account is set, so the connection to the LDAP server"
                    + " must be encrypted (LDAPS or StartTLS).");

        String password = parameters.get(PASSWORD);
        String username = value(parameters, USERNAME);

        return new LdapTarget(hostname, port, encryption, value(parameters, CERTIFICATE),
                activeDirectory, userDn, username == null ? userDn : username,
                password == null || password.isEmpty() ? null : password,
                adminDn, adminPassword);

    }

    private static String value(Map<String, String> parameters, String name) {
        return Values.trimToNull(parameters.get(name));
    }

    /**
     * Returns a copy of this target with a different current password.
     */
    public LdapTarget withPassword(String newPassword) {
        return new LdapTarget(hostname, port, encryption, pinnedCertificate, activeDirectory,
                userDn, username, newPassword, adminDn, adminPassword);
    }

    public String getHostname() {
        return hostname;
    }

    public int getPort() {
        return port;
    }

    public Encryption getEncryption() {
        return encryption;
    }

    public String getPinnedCertificate() {
        return pinnedCertificate;
    }

    public boolean isActiveDirectory() {
        return activeDirectory;
    }

    public String getUserDn() {
        return userDn;
    }

    /**
     * Display name of the account, defaulting to its DN.
     */
    public String getUsername() {
        return username;
    }

    /**
     * Current password of the account, or null if not stored yet.
     */
    public String getPassword() {
        return password;
    }

    public String getAdminDn() {
        return adminDn;
    }

    public String getAdminPassword() {
        return adminPassword;
    }

}
