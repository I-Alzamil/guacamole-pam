package io.github.ialzamil.guacamole.pam.winrm;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.KeyStore;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Base64;

import org.junit.Test;

/**
 * The channel binding added to smbj's NTLM login. Expected values were
 * computed independently (Python: hashlib over the same certificates).
 */
public class NtlmLoginTest {

    static X509Certificate certificate(String keystore) throws Exception {
        KeyStore store = KeyStore.getInstance("PKCS12");
        try (InputStream in = NtlmLoginTest.class.getResourceAsStream(keystore)) {
            store.load(in, "changeit".toCharArray());
        }
        return (X509Certificate) store.getCertificate("server");
    }

    static byte[] hex(String value) {
        byte[] bytes = new byte[value.length() / 2];
        for (int i = 0; i < bytes.length; i++)
            bytes[i] = (byte) Integer.parseInt(value.substring(2 * i, 2 * i + 2), 16);
        return bytes;
    }

    @Test
    public void bindsToSha256Certificate() throws Exception {
        X509Certificate certificate = certificate("test-server.p12");
        assertEquals("SHA-256", NtlmLogin.endPointHashAlgorithm(certificate));
        assertArrayEquals(hex("6c3611874c686079d475750f960ff89c"), NtlmLogin.channelBindingsHash(certificate));
    }

    @Test
    public void bindsToSha384CertificateWithItsOwnHash() throws Exception {
        X509Certificate certificate = certificate("test-sha384.p12");
        assertEquals("SHA-384", NtlmLogin.endPointHashAlgorithm(certificate));
        assertArrayEquals(hex("79a0eac9f915de474d5c1db4f5c8f6b9"), NtlmLogin.channelBindingsHash(certificate));
    }

    @Test
    public void negotiateIsAnNtlmNegotiateMessage() {
        byte[] message = new NtlmLogin().negotiate();
        assertArrayEquals("NTLMSSP\0".getBytes(StandardCharsets.US_ASCII), Arrays.copyOf(message, 8));
        assertEquals(1, message[8]);
    }

    /**
     * A challenge recorded from Windows 11 is answered with an
     * AUTHENTICATE message naming the user, in UTF-16.
     */
    @Test
    public void answersARecordedWindowsChallenge() throws Exception {

        byte[] challenge;
        try (InputStream in = NtlmLoginTest.class.getResourceAsStream("challenge-windows11.b64")) {
            challenge = Base64.getDecoder().decode(new String(in.readAllBytes(), StandardCharsets.US_ASCII).trim());
        }

        byte[] answer = new NtlmLogin().authenticate(challenge, WinRmTarget.Credentials.parse("pamtest"),
                "Some-Password1", certificate("test-server.p12"));

        assertArrayEquals("NTLMSSP\0".getBytes(StandardCharsets.US_ASCII), Arrays.copyOf(answer, 8));
        assertEquals(3, answer[8]);
        assertTrue(new String(answer, StandardCharsets.UTF_16LE).contains("pamtest")
                || new String(Arrays.copyOfRange(answer, 1, answer.length), StandardCharsets.UTF_16LE).contains("pamtest"));

        // A different random client challenge each time
        byte[] again = new NtlmLogin().authenticate(challenge, WinRmTarget.Credentials.parse("pamtest"),
                "Some-Password1", certificate("test-server.p12"));
        assertTrue(!Arrays.equals(answer, again));

    }

}
