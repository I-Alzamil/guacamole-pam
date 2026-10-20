package org.apache.guacamole.pam.winrm;

import java.util.Map;
import java.util.regex.Pattern;

import org.apache.guacamole.pam.Values;

/**
 * A local Windows account and the host holding it, reached over WinRM
 * (HTTPS), read from the settings of a WinRM platform combined with the
 * account of a connection. On a domain controller, whose local accounts are
 * the domain's, these are domain accounts.
 */
public final class WinRmTarget {

    public static final String HOSTNAME = "winrm-hostname";
    public static final String PORT = "winrm-port";

    /**
     * SHA-256 fingerprint the host's certificate must match, or empty to
     * trust the first certificate seen.
     */
    public static final String CERTIFICATE = "winrm-certificate";

    /**
     * Optional local administrator setting other accounts' passwords.
     * Without it, each account (itself an administrator) sets its own.
     */
    public static final String ADMIN_USERNAME = "winrm-admin-username";
    public static final String ADMIN_PASSWORD = "winrm-admin-password";

    public static final String USERNAME = "username";
    public static final String PASSWORD = "password";

    public static final int DEFAULT_PORT = 5986;

    /**
     * Characters Windows refuses in account names, which also keeps the
     * name from changing the meaning of the ADSI path it is used in.
     */
    private static final Pattern INVALID_ACCOUNT_CHARACTERS = Pattern.compile("[\"/\\\\\\[\\]:;|=,+*?<>@\\p{Cntrl}]");

    private final String hostname;
    private final int port;
    private final String certificate;
    private final Credentials account;
    private final String password;
    private final Credentials admin;
    private final String adminPassword;

    /**
     * A user name split into its domain (empty for a local account) and
     * account name.
     */
    public static final class Credentials {

        private final String domain;
        private final String name;

        Credentials(String domain, String name) {
            this.domain = domain;
            this.name = name;
        }

        /**
         * Reads "name", ".\name", "HOST\name" or "name@domain". Accounts on
         * the host itself have an empty domain.
         */
        static Credentials parse(String username) {
            String domain = "";
            String name = username;
            int slash = username.indexOf('\\');
            int at = username.lastIndexOf('@');
            if (slash >= 0) {
                domain = username.substring(0, slash);
                name = username.substring(slash + 1);
            }
            else if (at > 0) {
                domain = username.substring(at + 1);
                name = username.substring(0, at);
            }
            if (".".equals(domain))
                domain = "";
            return new Credentials(domain, name);
        }

        public String getDomain() {
            return domain;
        }

        public String getName() {
            return name;
        }

    }

    private WinRmTarget(String hostname, int port, String certificate, Credentials account, String password,
            Credentials admin, String adminPassword) {
        this.hostname = hostname;
        this.port = port;
        this.certificate = certificate;
        this.account = account;
        this.password = password;
        this.admin = admin;
        this.adminPassword = adminPassword;
    }

    /**
     * Reads the target from the given settings.
     *
     * @throws IllegalArgumentException
     *     If a required parameter is missing or invalid.
     */
    public static WinRmTarget fromParameters(Map<String, String> parameters) {

        String hostname = Values.trimToNull(parameters.get(HOSTNAME));
        if (hostname == null)
            throw new IllegalArgumentException("The connection has no hostname. Set the WinRM hostname in its"
                    + " password management settings.");

        String username = Values.trimToNull(parameters.get(USERNAME));
        if (username == null)
            throw new IllegalArgumentException("The connection has no username.");

        Credentials account = Credentials.parse(username);
        if (!account.getDomain().isEmpty())
            throw new IllegalArgumentException("Only local accounts can be managed over WinRM, not \"" + username
                    + "\". Manage domain accounts with an LDAP or Kerberos platform.");
        if (account.getName().isEmpty() || INVALID_ACCOUNT_CHARACTERS.matcher(account.getName()).find())
            throw new IllegalArgumentException("Invalid Windows account name: " + username);

        String adminUsername = Values.trimToNull(parameters.get(ADMIN_USERNAME));
        String adminPassword = Values.emptyToNull(parameters.get(ADMIN_PASSWORD));
        if (adminUsername != null && adminPassword == null)
            throw new IllegalArgumentException("The administrator account has no password.");

        Credentials admin = adminUsername == null ? null : Credentials.parse(adminUsername);
        if (admin != null && (admin.getName().isEmpty() || INVALID_ACCOUNT_CHARACTERS.matcher(admin.getName()).find()))
            throw new IllegalArgumentException("Invalid administrator name: " + adminUsername
                    + " (expected \"name\", \"DOMAIN\\name\" or \"name@domain\").");

        return new WinRmTarget(hostname, Values.parsePort(parameters.get(PORT), DEFAULT_PORT), normalize(parameters.get(CERTIFICATE)),
                account, Values.emptyToNull(parameters.get(PASSWORD)), admin, adminPassword);

    }

    public WinRmTarget withPassword(String newPassword) {
        return new WinRmTarget(hostname, port, certificate, account, newPassword, admin, adminPassword);
    }

    public WinRmTarget withCertificate(String fingerprint) {
        return new WinRmTarget(hostname, port, normalize(fingerprint), account, password, admin, adminPassword);
    }

    /**
     * Upper case "AB:CD:..." form of a SHA-256 fingerprint, as openssl
     * prints it, or null if empty.
     */
    static String normalize(String fingerprint) {
        String value = Values.trimToNull(fingerprint);
        if (value == null)
            return null;
        if (value.regionMatches(true, 0, "sha256 fingerprint=", 0, 19))
            value = value.substring(19);
        String hex = value.replaceAll("[:\\s]", "").toUpperCase();
        if (!hex.matches("[0-9A-F]{64}"))
            throw new IllegalArgumentException("Invalid certificate fingerprint (expected SHA-256): " + fingerprint);
        return hex.replaceAll("(..)(?!$)", "$1:");
    }

    /**
     * Whether the value is a certificate fingerprint in the form recorded
     * by this type.
     */
    static boolean isFingerprint(String value) {
        return value != null && value.matches("([0-9A-F]{2}:){31}[0-9A-F]{2}");
    }

    public String getHostname() {
        return hostname;
    }

    public int getPort() {
        return port;
    }

    /**
     * Fingerprint the certificate must match, or null to trust any (on
     * first contact).
     */
    public String getCertificate() {
        return certificate;
    }

    public Credentials getAccount() {
        return account;
    }

    public String getPassword() {
        return password;
    }

    /**
     * The administrator, or null if each account sets its own password.
     */
    public Credentials getAdmin() {
        return admin;
    }

    public String getAdminPassword() {
        return adminPassword;
    }

}
