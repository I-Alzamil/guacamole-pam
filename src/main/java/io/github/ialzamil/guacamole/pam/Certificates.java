package io.github.ialzamil.guacamole.pam;

import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * Server certificates as platforms name them: by fingerprint, and the CA
 * certificates a platform trusts, in PEM.
 */
public final class Certificates {

    private Certificates() {
    }

    /**
     * SHA-256 fingerprint of a certificate, as "openssl x509 -fingerprint
     * -sha256" prints it: "AB:CD:...".
     */
    public static String fingerprint(X509Certificate certificate) throws CertificateEncodingException {
        try {
            byte[] digest = MessageDigest.getInstance("SHA-256").digest(certificate.getEncoded());
            StringBuilder hex = new StringBuilder();
            for (byte b : digest) {
                if (hex.length() > 0)
                    hex.append(':');
                hex.append(String.format("%02X", b));
            }
            return hex.toString();
        }
        catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }

    /**
     * Reads the certificates of a PEM text, or none if it is empty.
     *
     * @throws IllegalArgumentException
     *     If the text holds anything but certificates, or none.
     */
    public static List<X509Certificate> parseAuthorities(String pem) {

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

}
