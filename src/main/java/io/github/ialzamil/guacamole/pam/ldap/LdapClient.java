package io.github.ialzamil.guacamole.pam.ldap;

import java.net.ConnectException;
import java.net.SocketTimeoutException;
import java.net.UnknownHostException;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;

import javax.net.ssl.SSLHandshakeException;

import com.unboundid.ldap.sdk.ExtendedResult;
import com.unboundid.ldap.sdk.LDAPConnection;
import com.unboundid.ldap.sdk.LDAPConnectionOptions;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.Modification;
import com.unboundid.ldap.sdk.ModificationType;
import com.unboundid.ldap.sdk.ResultCode;
import com.unboundid.ldap.sdk.extensions.PasswordModifyExtendedRequest;
import com.unboundid.ldap.sdk.extensions.StartTLSExtendedRequest;
import com.unboundid.util.ssl.HostNameSSLSocketVerifier;
import com.unboundid.util.ssl.SSLUtil;

import io.github.ialzamil.guacamole.pam.management.PlatformTestResult;
import io.github.ialzamil.guacamole.pam.rotation.ChangeOutcome;

/**
 * Changes and verifies directory account passwords. Standard directories use
 * the password modify extended operation (RFC 3062); Active Directory takes
 * the quoted, UTF-16LE encoded password in the unicodePwd attribute.
 */
public class LdapClient {

    private static final int TIMEOUT_MS = 15000;

    /**
     * Changes the password of the target account. Uses the rotation account
     * when configured, otherwise the account changes its own password. Never
     * throws: every failure is reported in the outcome.
     */
    public ChangeOutcome changePassword(LdapTarget target, String newPassword) {

        CertificateTrustManager trust = new CertificateTrustManager(target.getPinnedCertificate());
        boolean useAdmin = target.getAdminDn() != null;
        boolean sent = false;

        if (!useAdmin && target.getPassword() == null)
            return new ChangeOutcome(false, false, "The account has no current password and no rotation"
                    + " account is configured.", null, null);

        try (LDAPConnection connection = open(target, trust)) {

            if (useAdmin)
                connection.bind(target.getAdminDn(), target.getAdminPassword());
            else
                connection.bind(target.getUserDn(), target.getPassword());

            sent = true;

            if (target.isActiveDirectory()) {
                Modification[] modifications = useAdmin
                    ? new Modification[] {
                        new Modification(ModificationType.REPLACE, "unicodePwd", encodeUnicodePwd(newPassword))
                    }
                    : new Modification[] {
                        new Modification(ModificationType.DELETE, "unicodePwd", encodeUnicodePwd(target.getPassword())),
                        new Modification(ModificationType.ADD, "unicodePwd", encodeUnicodePwd(newPassword))
                    };
                connection.modify(target.getUserDn(), modifications);
            }
            else {
                ExtendedResult result = connection.processExtendedOperation(new PasswordModifyExtendedRequest(
                        target.getUserDn(), useAdmin ? null : target.getPassword(), newPassword));
                if (result.getResultCode() != ResultCode.SUCCESS)
                    return new ChangeOutcome(false, true, "The directory refused the password change: "
                            + describe(result.getResultCode(), result.getDiagnosticMessage()),
                            null, trust.getPresentedFingerprint());
            }

            return new ChangeOutcome(true, true, null, null, trust.getPresentedFingerprint());

        }
        catch (LDAPException e) {
            return new ChangeOutcome(false, sent, describe(e, target, trust, useAdmin), null,
                    trust.getPresentedFingerprint());
        }

    }

    /**
     * Returns whether the directory accepts the given password for the
     * target account.
     *
     * @throws LDAPException
     *     If the server could not be reached or its certificate is not
     *     trusted, with a message saying so as the outcome of a change does.
     */
    public boolean acceptsPassword(LdapTarget target, String password) throws LDAPException {

        if (password == null || password.isEmpty())
            return false;

        CertificateTrustManager trust = new CertificateTrustManager(target.getPinnedCertificate());
        try (LDAPConnection connection = open(target, trust)) {
            connection.bind(target.getUserDn(), password);
            return true;
        }
        catch (LDAPException e) {
            if (e.getResultCode() == ResultCode.INVALID_CREDENTIALS)
                return false;
            throw new LDAPException(e.getResultCode(), describe(e, target, trust, false), e);
        }

    }

    /**
     * Checks that the directory can be reached and trusted, and that the
     * rotation account, if any, can sign in, changing nothing.
     */
    public PlatformTestResult test(LdapTarget target) {

        PlatformTestResult result = new PlatformTestResult();
        CertificateTrustManager trust = new CertificateTrustManager(target.getPinnedCertificate());
        String server = target.getHostname() + ":" + target.getPort();

        try (LDAPConnection connection = open(target, trust)) {

            if (target.getEncryption() == LdapTarget.Encryption.NONE)
                result.passed("Connected to " + server + ", without encryption.");
            else
                result.passed("Connected to " + server + " over "
                        + (target.getEncryption() == LdapTarget.Encryption.STARTTLS ? "StartTLS" : "LDAPS")
                        + ". Its certificate " + trust.getPresentedFingerprint()
                        + (trust.isPinned() ? " is the pinned one." : " is issued by a trusted CA for this host."));

            if (target.getAdminDn() == null) {
                result.info("No rotation account: each account changes its own password.");
                return result;
            }

            connection.bind(target.getAdminDn(), target.getAdminPassword());
            return result.passed("The rotation account signed in.");

        }
        catch (LDAPException e) {
            return result.failed(describe(e, target, trust, true));
        }

    }

    /**
     * Connects to the directory, establishing TLS before any credentials are
     * sent unless encryption is disabled.
     */
    private LDAPConnection open(LdapTarget target, CertificateTrustManager trust) throws LDAPException {

        LDAPConnectionOptions options = new LDAPConnectionOptions();
        options.setConnectTimeoutMillis(TIMEOUT_MS);
        options.setResponseTimeoutMillis(TIMEOUT_MS);

        // A pinned certificate identifies the server by itself; otherwise the
        // CA-signed certificate must also match the hostname
        if (!trust.isPinned())
            options.setSSLSocketVerifier(new HostNameSSLSocketVerifier(true));

        SSLUtil ssl = new SSLUtil(trust);

        try {
            switch (target.getEncryption()) {

                case LDAPS:
                    return new LDAPConnection(ssl.createSSLSocketFactory(), options,
                            target.getHostname(), target.getPort());

                case STARTTLS:
                    LDAPConnection connection = new LDAPConnection(options, target.getHostname(), target.getPort());
                    try {
                        ExtendedResult result = connection.processExtendedOperation(
                                new StartTLSExtendedRequest(ssl.createSSLContext()));
                        if (result.getResultCode() != ResultCode.SUCCESS)
                            throw new LDAPException(result);
                        return connection;
                    }
                    catch (LDAPException e) {
                        connection.close();
                        throw e;
                    }

                default:
                    return new LDAPConnection(options, target.getHostname(), target.getPort());

            }
        }
        catch (GeneralSecurityException e) {
            throw new LDAPException(ResultCode.LOCAL_ERROR, "Unable to set up TLS: " + e.getMessage(), e);
        }

    }

    /**
     * Active Directory expects the password surrounded by double quotes and
     * encoded as UTF-16LE.
     */
    static byte[] encodeUnicodePwd(String password) {
        return ("\"" + password + "\"").getBytes(StandardCharsets.UTF_16LE);
    }

    /**
     * What went wrong, for administrators. The SDK's own messages nest the
     * exceptions they wrap, with the SDK's version and build: the cause is
     * told in plain words instead, and the version left out.
     */
    private static String describe(LDAPException e, LdapTarget target, CertificateTrustManager trust,
            boolean useAdmin) {

        String message = withoutVersion(e.getMessage() == null ? "" : e.getMessage());

        if (message.contains("does not match the pinned fingerprint"))
            return "The LDAP server certificate " + trust.getPresentedFingerprint()
                    + " does not match the pinned fingerprint. No credentials were sent.";

        Throwable handshake = findCause(e, SSLHandshakeException.class);
        if (handshake != null && trust.getPresentedFingerprint() != null)
            return "The LDAP server certificate " + trust.getPresentedFingerprint() + " is not trusted ("
                    + rootMessage(handshake) + "). No credentials were sent. If this is the expected"
                    + " certificate, pin its fingerprint in the platform.";
        if (e.getResultCode() == ResultCode.INVALID_CREDENTIALS)
            return useAdmin ? "The directory rejected the rotation account credentials."
                            : "The directory rejected the account's current password.";
        if (e.getResultCode() == ResultCode.CONNECT_ERROR || e.getResultCode() == ResultCode.SERVER_DOWN
                || e.getResultCode() == ResultCode.TIMEOUT)
            return "Unable to reach the LDAP server " + target.getHostname() + ":" + target.getPort() + ": "
                    + connectionProblem(e) + ".";

        return "LDAP error: " + describe(e.getResultCode(), e.getDiagnosticMessage() != null
                ? withoutVersion(e.getDiagnosticMessage()) : message);

    }

    /**
     * Why the server could not be reached, in plain words.
     */
    private static String connectionProblem(LDAPException e) {
        if (findCause(e, UnknownHostException.class) != null)
            return "unknown host";
        if (findCause(e, ConnectException.class) != null)
            return "connection refused";
        if (findCause(e, SocketTimeoutException.class) != null || e.getResultCode() == ResultCode.TIMEOUT)
            return "no answer in time";
        return withoutVersion(rootMessage(e));
    }

    /**
     * The message without the SDK's version and build, which the SDK adds
     * to the exceptions it nests.
     */
    static String withoutVersion(String message) {
        return message.replaceAll(",?\\s*ldapSDKVersion=[^,)']*(,\\s*revision=[0-9a-fA-F]+)?", "");
    }

    private static Throwable findCause(Throwable error, Class<? extends Throwable> type) {
        for (Throwable cause = error; cause != null; cause = cause.getCause()) {
            if (type.isInstance(cause))
                return cause;
        }
        return null;
    }

    private static String rootMessage(Throwable error) {
        Throwable root = error;
        while (root.getCause() != null && root.getCause() != root)
            root = root.getCause();
        return root.getMessage() == null ? root.getClass().getSimpleName() : root.getMessage();
    }

    private static String describe(ResultCode code, String diagnostic) {
        return code.getName() + (diagnostic == null || diagnostic.isEmpty() ? "" : " (" + diagnostic + ")");
    }

}
