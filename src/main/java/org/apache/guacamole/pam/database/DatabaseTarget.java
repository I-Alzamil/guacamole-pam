package org.apache.guacamole.pam.database;

import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.regex.Pattern;

import org.apache.guacamole.pam.Values;

/**
 * A database account and the database server holding it, read from the
 * settings of a Database platform combined with the account of a
 * connection.
 */
public final class DatabaseTarget {

    /**
     * What the server is: PostgreSQL, MySQL (or MariaDB, told apart once
     * connected), or SQL Server.
     */
    public enum Kind {

        POSTGRESQL("postgresql", "PostgreSQL", 5432),
        MYSQL("mysql", "MySQL or MariaDB", 3306),
        SQLSERVER("sqlserver", "SQL Server", 1433);

        private final String value;
        private final String displayName;
        private final int defaultPort;

        Kind(String value, String displayName, int defaultPort) {
            this.value = value;
            this.displayName = displayName;
            this.defaultPort = defaultPort;
        }

        public String getValue() {
            return value;
        }

        public String getDisplayName() {
            return displayName;
        }

        static Kind of(String value) {
            for (Kind kind : values()) {
                if (kind.value.equals(value))
                    return kind;
            }
            return null;
        }

    }

    public static final String TYPE = "database-type";
    public static final String HOSTNAME = "database-hostname";
    public static final String PORT = "database-port";

    /**
     * Database connected to, which changing passwords does not depend on:
     * empty for "postgres" on PostgreSQL, "master" on SQL Server, none on
     * MySQL.
     */
    public static final String DATABASE = "database-name";

    /**
     * Encryption of the connection: empty for TLS with the server's
     * certificate checked, as for its hostname.
     */
    public static final String ENCRYPTION = "database-encryption";
    public static final String ENCRYPTION_UNVERIFIED = "unverified";
    public static final String ENCRYPTION_NONE = "none";

    /**
     * Certificates, in PEM, of the certificate authorities issuing the
     * server's certificate, or the server's own certificate. Empty: those
     * Java trusts.
     */
    public static final String CA_CERTIFICATES = "database-ca-certificates";

    /**
     * Optional account allowed to set other accounts' passwords. Without
     * it, each account changes its own password.
     */
    public static final String ADMIN_USERNAME = "database-admin-username";
    public static final String ADMIN_PASSWORD = "database-admin-password";

    public static final String USERNAME = "database-username";
    public static final String PASSWORD = "password";

    /**
     * Host part of a MySQL or MariaDB account ('name'@'host').
     */
    public static final String ACCOUNT_HOST = "database-account-host";
    public static final String DEFAULT_ACCOUNT_HOST = "%";

    /**
     * A hostname, an IPv4 address, or an IPv6 address (bracketed or not).
     * They are written into JDBC URLs, where anything more (a path, "?",
     * "&" or ";") would set other options of the driver, such as MySQL's
     * reading of local files for the server.
     */
    private static final Pattern VALID_HOSTNAME = Pattern.compile(
            "[A-Za-z0-9_](?:[A-Za-z0-9_.-]*[A-Za-z0-9_])?|\\[?[0-9A-Fa-f:.]*:[0-9A-Fa-f:.]*\\]?");

    /**
     * A database name, which PostgreSQL and MySQL take in the URL as well.
     * Only the database connected to, which changing passwords does not
     * depend on, so plain names are enough.
     */
    private static final Pattern VALID_DATABASE = Pattern.compile("[A-Za-z0-9_$-]{1,128}");

    private final Kind kind;
    private final String hostname;
    private final int port;
    private final String database;
    private final String encryption;
    private final List<X509Certificate> authorities;
    private final String adminUsername;
    private final String adminPassword;
    private final String username;
    private final String password;
    private final String accountHost;

    private DatabaseTarget(Kind kind, String hostname, int port, String database, String encryption,
            List<X509Certificate> authorities, String adminUsername, String adminPassword, String username,
            String password, String accountHost) {
        this.kind = kind;
        this.hostname = hostname;
        this.port = port;
        this.database = database;
        this.encryption = encryption;
        this.authorities = authorities;
        this.adminUsername = adminUsername;
        this.adminPassword = adminPassword;
        this.username = username;
        this.password = password;
        this.accountHost = accountHost;
    }

    /**
     * Reads the target from the given settings.
     *
     * @throws IllegalArgumentException
     *     If a required parameter is missing or invalid.
     */
    public static DatabaseTarget fromParameters(Map<String, String> parameters) {

        Kind kind = Kind.of(Values.trimToNull(parameters.get(TYPE)));
        if (kind == null)
            throw new IllegalArgumentException("The platform has no database type.");

        String hostname = Values.trimToNull(parameters.get(HOSTNAME));
        if (hostname == null)
            throw new IllegalArgumentException("The platform has no database hostname.");
        if (!VALID_HOSTNAME.matcher(hostname).matches())
            throw new IllegalArgumentException("Invalid database hostname \"" + hostname + "\": give a hostname or an"
                    + " IP address only.");

        String database = Values.trimToNull(parameters.get(DATABASE));
        if (database != null && !VALID_DATABASE.matcher(database).matches())
            throw new IllegalArgumentException("Invalid database name \"" + database + "\": use letters, digits, \"_\","
                    + " \"$\" and \"-\" only.");

        String encryption = Values.trimToNull(parameters.get(ENCRYPTION));
        if (encryption != null && !ENCRYPTION_UNVERIFIED.equals(encryption) && !ENCRYPTION_NONE.equals(encryption))
            throw new IllegalArgumentException("Unknown encryption \"" + encryption + "\".");

        String adminUsername = Values.trimToNull(parameters.get(ADMIN_USERNAME));
        String adminPassword = Values.emptyToNull(parameters.get(ADMIN_PASSWORD));
        if (adminUsername != null && adminPassword == null)
            throw new IllegalArgumentException("The administrator account has no password.");

        String username = Values.trimToNull(parameters.get(USERNAME));
        if (username == null)
            throw new IllegalArgumentException("The connection has no username.");

        String accountHost = Values.trimToNull(parameters.get(ACCOUNT_HOST));

        return new DatabaseTarget(kind, hostname, Values.parsePort(parameters.get(PORT), kind.defaultPort),
                database, encryption,
                parseAuthorities(parameters.get(CA_CERTIFICATES)), adminUsername, adminPassword, username,
                Values.emptyToNull(parameters.get(PASSWORD)),
                accountHost == null ? DEFAULT_ACCOUNT_HOST : accountHost);

    }

    /**
     * Reads the certificates of a PEM text, or none if it is empty.
     *
     * @throws IllegalArgumentException
     *     If the text holds anything but certificates, or none.
     */
    static List<X509Certificate> parseAuthorities(String pem) {

        String text = Values.trimToNull(pem);
        if (text == null)
            return Collections.emptyList();

        List<X509Certificate> certificates = new ArrayList<>();
        try {
            for (Certificate certificate : CertificateFactory.getInstance("X.509").generateCertificates(
                    new ByteArrayInputStream(text.getBytes(StandardCharsets.US_ASCII))))
                certificates.add((X509Certificate) certificate);
        }
        catch (CertificateException e) {
            throw new IllegalArgumentException("The CA certificates are not valid PEM certificates (\"-----BEGIN"
                    + " CERTIFICATE-----\" ...): " + e.getMessage());
        }

        if (certificates.isEmpty())
            throw new IllegalArgumentException("The CA certificates field holds no certificate.");
        return Collections.unmodifiableList(certificates);

    }

    public DatabaseTarget withPassword(String newPassword) {
        return new DatabaseTarget(kind, hostname, port, database, encryption, authorities, adminUsername,
                adminPassword, username, newPassword, accountHost);
    }

    public Kind getKind() {
        return kind;
    }

    public String getHostname() {
        return hostname;
    }

    public int getPort() {
        return port;
    }

    /**
     * The database connected to, or null for the default.
     */
    public String getDatabase() {
        return database;
    }

    /**
     * Whether connections are encrypted.
     */
    public boolean isEncrypted() {
        return !ENCRYPTION_NONE.equals(encryption);
    }

    /**
     * Whether the server's certificate, and its name, are checked.
     */
    public boolean isVerified() {
        return encryption == null;
    }

    /**
     * Certificates the server's must be, or be issued by, or none for those
     * Java trusts.
     */
    public List<X509Certificate> getAuthorities() {
        return authorities;
    }

    /**
     * The administrator account, or null if each account changes its own
     * password.
     */
    public String getAdminUsername() {
        return adminUsername;
    }

    public String getAdminPassword() {
        return adminPassword;
    }

    public String getUsername() {
        return username;
    }

    public String getPassword() {
        return password;
    }

    /**
     * Host part of the account, for MySQL and MariaDB.
     */
    public String getAccountHost() {
        return accountHost;
    }

    /**
     * The server, as messages name it: "PostgreSQL server db1:5432".
     */
    public String describe() {
        return kind.displayName + " server " + hostname + ":" + port;
    }

}
