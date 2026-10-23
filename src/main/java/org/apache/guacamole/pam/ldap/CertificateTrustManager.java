package org.apache.guacamole.pam.ldap;

import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

import javax.net.ssl.X509TrustManager;

import com.unboundid.util.ssl.JVMDefaultTrustManager;

import org.apache.guacamole.pam.Certificates;

/**
 * Validates LDAP server certificates. With a pinned fingerprint only that
 * exact certificate is accepted; otherwise the certificate must chain to a
 * CA trusted by the JVM. The fingerprint of the presented certificate is
 * recorded either way, so administrators can pin it.
 */
class CertificateTrustManager implements X509TrustManager {

    private final String pinned;

    private volatile String presented;

    CertificateTrustManager(String pinnedFingerprint) {
        this.pinned = normalize(pinnedFingerprint);
    }

    boolean isPinned() {
        return pinned != null;
    }

    /**
     * Fingerprint of the presented certificate in "AB:CD:..." form, or null
     * if the server presented none yet.
     */
    String getPresentedFingerprint() {
        return presented;
    }

    @Override
    public void checkServerTrusted(X509Certificate[] chain, String authType) throws CertificateException {

        if (chain == null || chain.length == 0)
            throw new CertificateException("The LDAP server presented no certificate.");

        presented = Certificates.fingerprint(chain[0]);

        if (pinned == null) {
            JVMDefaultTrustManager.getInstance().checkServerTrusted(chain, authType);
            return;
        }

        if (!pinned.equals(normalize(presented)))
            throw new CertificateException("The LDAP server certificate " + presented
                    + " does not match the pinned fingerprint.");

    }

    @Override
    public void checkClientTrusted(X509Certificate[] chain, String authType) throws CertificateException {
        throw new CertificateException("Client certificates are not accepted.");
    }

    @Override
    public X509Certificate[] getAcceptedIssuers() {
        return new X509Certificate[0];
    }

    /**
     * Accepts hex with or without colons, optionally prefixed as openssl
     * prints it ("sha256 Fingerprint=...").
     */
    static String normalize(String fingerprint) {

        if (fingerprint == null)
            return null;

        String value = fingerprint.trim();
        int equals = value.indexOf('=');
        if (equals >= 0)
            value = value.substring(equals + 1);
        if (value.regionMatches(true, 0, "SHA256:", 0, 7))
            value = value.substring(7);

        value = value.replaceAll("[:\\s]", "").toLowerCase();
        return value.isEmpty() ? null : value;

    }

}
