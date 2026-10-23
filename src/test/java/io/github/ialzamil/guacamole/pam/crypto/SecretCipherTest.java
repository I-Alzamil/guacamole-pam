package io.github.ialzamil.guacamole.pam.crypto;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotEquals;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.security.GeneralSecurityException;
import java.util.Base64;

import org.junit.Test;

/**
 * The stored form of encrypted values, checked against a value encrypted
 * independently (Python's "cryptography" AES-GCM, with the same key id,
 * associated data and layout).
 */
public class SecretCipherTest {

    /** Bytes 0 to 31. */
    static final String KEY = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=";

    static final String OTHER_KEY = Base64.getEncoder().encodeToString(new byte[32]);

    /**
     * Purpose the independent value was encrypted for. Any purpose will do:
     * the value only decrypts for the one it was encrypted for.
     */
    private static final String PURPOSE = "connection-password";

    /** "Account-Pw1! é" for {@link #PURPOSE}, nonce bytes 100 to 111. */
    private static final String INDEPENDENT = "pam:v1:630dcd29:ZGVmZ2hpamtsbW5vCXi9CQyHIrNuFW7J+qbDPheHV0hZYfmvMPafRfmsaA==";

    @Test
    public void decryptsValueEncryptedIndependently() throws Exception {
        SecretCipher cipher = new SecretCipher(KEY);
        assertEquals("630dcd29", cipher.getKeyId());
        assertEquals("Account-Pw1! é", cipher.decrypt(PURPOSE, INDEPENDENT));
    }

    @Test
    public void encryptsWithFreshNonces() throws Exception {
        SecretCipher cipher = new SecretCipher(KEY);
        String first = cipher.encrypt(Secrets.PLATFORM_SECRETS, "{\"ldap-admin-password\":\"x\"}");
        String second = cipher.encrypt(Secrets.PLATFORM_SECRETS, "{\"ldap-admin-password\":\"x\"}");
        assertTrue(first.startsWith("pam:v1:630dcd29:"));
        assertNotEquals(first, second);
        assertEquals("{\"ldap-admin-password\":\"x\"}", cipher.decrypt(Secrets.PLATFORM_SECRETS, second));
    }

    @Test
    public void refusesAnotherPurpose() {
        refused(new SecretCipher(KEY), Secrets.PENDING_PASSWORD, INDEPENDENT);
    }

    @Test
    public void refusesAlteredValues() {
        SecretCipher cipher = new SecretCipher(KEY);
        // A byte of the tag (not the base64 padding bits, which decoders
        // ignore), then a byte of the ciphertext
        refused(cipher, PURPOSE, INDEPENDENT.replace("RfmsaA==", "RfmtaA=="));
        refused(cipher, PURPOSE, INDEPENDENT.replace("CXi9", "CXi8"));
        refused(cipher, PURPOSE, "pam:v1:630dcd29:ZGVmZ2hpamtsbW5v");
    }

    @Test
    public void refusesValuesOfAnotherKey() {
        refused(new SecretCipher(OTHER_KEY), PURPOSE, INDEPENDENT);
    }

    @Test
    public void recognizesOnlyItsOwnForm() {
        assertTrue(SecretCipher.isEncrypted(INDEPENDENT));
        assertEquals("630dcd29", SecretCipher.keyIdOf(INDEPENDENT));
        for (String plaintext : new String[] { "P@ssw0rd", "pam:v1:", "pam:v1:630dcd29:", "pam:v1:XYZ:abc",
                "pam:v2:630dcd29:abcd", " " + INDEPENDENT }) {
            assertFalse(plaintext, SecretCipher.isEncrypted(plaintext));
            assertEquals(null, SecretCipher.keyIdOf(plaintext));
        }
    }

    @Test
    public void refusesInvalidKeys() {
        for (String key : new String[] { "", "not base64!", Base64.getEncoder().encodeToString(new byte[16]) }) {
            try {
                new SecretCipher(key);
                fail("Accepted key \"" + key + "\"");
            }
            catch (IllegalArgumentException expected) {
            }
        }
    }

    private static void refused(SecretCipher cipher, String purpose, String value) {
        try {
            cipher.decrypt(purpose, value);
            fail("Decrypted " + value);
        }
        catch (GeneralSecurityException expected) {
        }
    }

}
