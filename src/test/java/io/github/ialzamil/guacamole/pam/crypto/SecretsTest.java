package io.github.ialzamil.guacamole.pam.crypto;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotEquals;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.util.Arrays;
import java.util.Collections;

import org.apache.guacamole.GuacamoleException;
import org.junit.Test;

/**
 * What is stored and read in each configuration: no key, a key, a new key
 * with the earlier one kept, decrypting everything, and a broken key.
 */
public class SecretsTest {

    private static final String KEY = SecretCipherTest.KEY;

    private static final String OTHER_KEY = SecretCipherTest.OTHER_KEY;

    private static final String PURPOSE = Secrets.PENDING_PASSWORD;

    private static Secrets secrets(String key, String... oldKeys) {
        return new Secrets(key, Arrays.asList(oldKeys), false);
    }

    @Test
    public void withoutKeyStoresPlaintext() throws Exception {
        Secrets none = secrets(null);
        assertFalse(none.isEncrypting());
        assertNull(none.getError());
        assertEquals("P@ss", none.protect(PURPOSE, "P@ss"));
        assertEquals("P@ss", none.reveal(PURPOSE, "P@ss"));
        assertFalse(none.needsMigration("P@ss"));
    }

    @Test
    public void withoutKeyExplainsEncryptedValues() throws Exception {
        String encrypted = secrets(KEY).protect(PURPOSE, "P@ss");
        Secrets none = secrets(null);
        assertFalse(none.needsMigration(encrypted));
        assertRefused(() -> none.reveal(PURPOSE, encrypted), "\"pam-encryption-key\" is not set");
    }

    @Test
    public void withKeyEncryptsAndKeepsCurrentValues() throws Exception {
        Secrets key = secrets(KEY);
        assertTrue(key.isEncrypting());
        String encrypted = key.protect(PURPOSE, "P@ss");
        assertTrue(SecretCipher.isEncrypted(encrypted));
        assertEquals("P@ss", key.reveal(PURPOSE, encrypted));
        // Saved again unchanged, as the connection editor does
        assertEquals(encrypted, key.protect(PURPOSE, encrypted));
        assertTrue(key.needsMigration("P@ss"));
        assertFalse(key.needsMigration(encrypted));
        // Plaintext from before the key still reads
        assertEquals("Old-Pw", key.reveal(PURPOSE, "Old-Pw"));
    }

    @Test
    public void emptyValuesStayEmpty() throws Exception {
        Secrets key = secrets(KEY);
        assertEquals("", key.protect(PURPOSE, ""));
        assertNull(key.protect(PURPOSE, null));
        assertFalse(key.needsMigration(""));
    }

    @Test
    public void newKeyReadsAndReplacesOldValues() throws Exception {
        String old = secrets(OTHER_KEY).protect(PURPOSE, "P@ss");
        Secrets rotated = secrets(KEY, OTHER_KEY);
        assertEquals("P@ss", rotated.reveal(PURPOSE, old));
        assertTrue(rotated.needsMigration(old));
        String migrated = rotated.protect(PURPOSE, old);
        assertEquals("630dcd29", SecretCipher.keyIdOf(migrated));
        assertEquals("P@ss", rotated.reveal(PURPOSE, migrated));
        assertEquals(Arrays.asList("630dcd29", SecretCipher.keyIdOf(old)), rotated.getKeyIds());
    }

    @Test
    public void unknownKeyIsNamed() throws Exception {
        String old = secrets(OTHER_KEY).protect(PURPOSE, "P@ss");
        Secrets key = secrets(KEY);
        assertFalse(key.needsMigration(old));
        assertFalse(key.canReveal(old));
        assertTrue(key.canReveal("Plain"));
        assertTrue(secrets(KEY, OTHER_KEY).canReveal(old));
        assertFalse(secrets("too short").canReveal(old));
        assertRefused(() -> key.reveal(PURPOSE, old), "add it to \"pam-encryption-old-keys\"");
    }

    @Test
    public void valueOfAnotherFieldIsRefused() throws Exception {
        Secrets key = secrets(KEY);
        String platformSecrets = key.protect(Secrets.PLATFORM_SECRETS, "{\"ldap-admin-password\":\"x\"}");
        assertRefused(() -> key.protect(PURPOSE, platformSecrets), "belongs to another field");
    }

    @Test
    public void decryptingStoresPlaintext() throws Exception {
        String encrypted = secrets(KEY).protect(PURPOSE, "P@ss");
        Secrets decrypt = new Secrets(KEY, Collections.<String>emptyList(), true);
        assertFalse(decrypt.isEncrypting());
        assertNull(decrypt.getError());
        assertTrue(decrypt.needsMigration(encrypted));
        assertFalse(decrypt.needsMigration("P@ss"));
        assertEquals("P@ss", decrypt.protect(PURPOSE, encrypted));
        assertEquals("P@ss", decrypt.protect(PURPOSE, "P@ss"));
    }

    @Test
    public void decryptingNeedsAKey() {
        assertNotEquals(null, new Secrets(null, Collections.<String>emptyList(), true).getError());
    }

    @Test
    public void brokenKeyNeverStoresPlaintext() throws Exception {
        Secrets broken = secrets("too short");
        assertFalse(broken.isEncrypting());
        assertTrue(broken.getError().contains("\"pam-encryption-key\" is invalid"));
        // Plaintext already stored still reads; nothing new is stored
        assertEquals("Old-Pw", broken.reveal(PURPOSE, "Old-Pw"));
        assertFalse(broken.needsMigration("Old-Pw"));
        assertRefused(() -> broken.protect(PURPOSE, "P@ss"), "cannot be stored");
        assertRefused(() -> secrets(KEY, "bad").protect(PURPOSE, "P@ss"), "A key in \"pam-encryption-old-keys\"");
    }

    @FunctionalInterface
    private interface Action {
        void run() throws GuacamoleException;
    }

    private static void assertRefused(Action action, String message) {
        try {
            action.run();
            fail("Not refused");
        }
        catch (GuacamoleException e) {
            assertTrue(e.getMessage(), e.getMessage().contains(message));
        }
    }

}
