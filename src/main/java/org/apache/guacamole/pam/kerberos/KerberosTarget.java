package org.apache.guacamole.pam.kerberos;

import java.util.Map;

import org.apache.guacamole.pam.Values;

/**
 * A Kerberos principal and the realm servers holding it, read from the
 * settings of a Kerberos platform combined with the account of a connection.
 */
public final class KerberosTarget {

    public static final String REALM = "kerberos-realm";

    /**
     * KDC asked for the tickets of the password change service.
     */
    public static final String KDC = "kerberos-kdc";
    public static final String KDC_PORT = "kerberos-kdc-port";

    /**
     * Password change server (kpasswd), the KDC if empty.
     */
    public static final String KPASSWD_SERVER = "kerberos-kpasswd-server";
    public static final String KPASSWD_PORT = "kerberos-kpasswd-port";

    /**
     * Optional principal allowed to set other principals' passwords. Without
     * it, each principal changes its own password.
     */
    public static final String ADMIN_PRINCIPAL = "kerberos-admin-principal";
    public static final String ADMIN_PASSWORD = "kerberos-admin-password";

    public static final String PRINCIPAL = "kerberos-principal";
    public static final String PASSWORD = "password";

    public static final int DEFAULT_KDC_PORT = 88;
    public static final int DEFAULT_KPASSWD_PORT = 464;

    private final String realm;
    private final String kdc;
    private final int kdcPort;
    private final String kpasswdServer;
    private final int kpasswdPort;
    private final String principal;
    private final String password;
    private final String adminPrincipal;
    private final String adminPassword;

    private KerberosTarget(String realm, String kdc, int kdcPort, String kpasswdServer, int kpasswdPort,
            String principal, String password, String adminPrincipal, String adminPassword) {
        this.realm = realm;
        this.kdc = kdc;
        this.kdcPort = kdcPort;
        this.kpasswdServer = kpasswdServer;
        this.kpasswdPort = kpasswdPort;
        this.principal = principal;
        this.password = password;
        this.adminPrincipal = adminPrincipal;
        this.adminPassword = adminPassword;
    }

    /**
     * Reads the target from the given settings. Principals without a realm
     * are in the platform's realm.
     *
     * @throws IllegalArgumentException
     *     If a required parameter is missing or invalid.
     */
    public static KerberosTarget fromParameters(Map<String, String> parameters) {

        String realm = require(parameters, REALM, "The platform has no Kerberos realm.");
        String kdc = require(parameters, KDC, "The platform has no KDC.");
        String kpasswd = Values.trimToNull(parameters.get(KPASSWD_SERVER));

        String principal = require(parameters, PRINCIPAL,
                "The connection has no Kerberos principal and no username.");

        String adminPrincipal = Values.trimToNull(parameters.get(ADMIN_PRINCIPAL));
        String adminPassword = Values.trimToNull(parameters.get(ADMIN_PASSWORD));
        if (adminPrincipal != null && adminPassword == null)
            throw new IllegalArgumentException("The admin principal has no password.");

        return new KerberosTarget(realm, kdc, Values.parsePort(parameters.get(KDC_PORT), DEFAULT_KDC_PORT),
                kpasswd != null ? kpasswd : kdc, Values.parsePort(parameters.get(KPASSWD_PORT), DEFAULT_KPASSWD_PORT),
                qualify(principal, realm), Values.trimToNull(parameters.get(PASSWORD)),
                adminPrincipal == null ? null : qualify(adminPrincipal, realm), adminPassword);

    }

    public KerberosTarget withPassword(String newPassword) {
        return new KerberosTarget(realm, kdc, kdcPort, kpasswdServer, kpasswdPort, principal,
                newPassword, adminPrincipal, adminPassword);
    }

    /**
     * Appends the realm to a principal that has none.
     */
    static String qualify(String principal, String realm) {
        return principal.contains("@") ? principal : principal + "@" + realm;
    }

    private static String require(Map<String, String> parameters, String name, String message) {
        String value = Values.trimToNull(parameters.get(name));
        if (value == null)
            throw new IllegalArgumentException(message);
        return value;
    }

    public String getRealm() {
        return realm;
    }

    public String getKdc() {
        return kdc;
    }

    public int getKdcPort() {
        return kdcPort;
    }

    public String getKpasswdServer() {
        return kpasswdServer;
    }

    public int getKpasswdPort() {
        return kpasswdPort;
    }

    /**
     * The managed principal, with its realm.
     */
    public String getPrincipal() {
        return principal;
    }

    public String getPassword() {
        return password;
    }

    /**
     * The admin principal with its realm, or null if each principal changes
     * its own password.
     */
    public String getAdminPrincipal() {
        return adminPrincipal;
    }

    public String getAdminPassword() {
        return adminPassword;
    }

}
