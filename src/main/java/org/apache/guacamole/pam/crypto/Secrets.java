package org.apache.guacamole.pam.crypto;

import java.security.GeneralSecurityException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import org.apache.guacamole.GuacamoleException;
import org.apache.guacamole.GuacamoleServerException;
import org.apache.guacamole.environment.Environment;
import org.apache.guacamole.properties.BooleanGuacamoleProperty;
import org.apache.guacamole.properties.StringGuacamoleProperty;

/**
 * Encryption at rest of the secrets this extension stores: platform secrets,
 * passwords kept from unconfirmed rotations, and Account passwords.
 *
 * Without "pam-encryption-key", values are stored as plaintext, as before.
 * With it, new values are encrypted, and existing ones are encrypted by
 * {@link SecretMigration}. Earlier keys in "pam-encryption-old-keys" still
 * decrypt values until they are encrypted again with the current key. With
 * "pam-encryption-decrypt" set, everything is decrypted back to plaintext,
 * before removing the key or the extension.
 *
 * Plaintext values are always read as they are. A misconfigured key never
 * stops the extension: only reading and writing encrypted values fails, with
 * the reason.
 */
public final class Secrets {

    /**
     * What a value is, bound into its encryption.
     */
    public static final String PLATFORM_SECRETS = "platform-secrets";
    public static final String PENDING_PASSWORD = "pending-password";
    public static final String CONNECTION_PASSWORD = "connection-password";

    private static final StringGuacamoleProperty KEY = new StringGuacamoleProperty() {
        @Override
        public String getName() { return "pam-encryption-key"; }
    };

    private static final StringGuacamoleProperty OLD_KEYS = new StringGuacamoleProperty() {
        @Override
        public String getName() { return "pam-encryption-old-keys"; }
    };

    private static final BooleanGuacamoleProperty DECRYPT = new BooleanGuacamoleProperty() {
        @Override
        public String getName() { return "pam-encryption-decrypt"; }
    };

    /**
     * The key new values are encrypted with, or null to store plaintext.
     */
    private final SecretCipher current;

    /**
     * Every key that may decrypt, by key id.
     */
    private final Map<String, SecretCipher> keys = new LinkedHashMap<>();

    /**
     * Why the keys could not be read, or null.
     */
    private final String error;

    Secrets(String currentKey, List<String> oldKeys, boolean decrypt) {

        SecretCipher cipher = null;
        String problem = null;

        if (currentKey != null && !currentKey.trim().isEmpty()) {
            try {
                cipher = new SecretCipher(currentKey);
                keys.put(cipher.getKeyId(), cipher);
            }
            catch (IllegalArgumentException e) {
                problem = "\"" + KEY.getName() + "\" is invalid: " + e.getMessage();
            }
        }

        for (String oldKey : oldKeys) {
            if (problem != null)
                break;
            try {
                SecretCipher key = new SecretCipher(oldKey);
                keys.putIfAbsent(key.getKeyId(), key);
            }
            catch (IllegalArgumentException e) {
                problem = "A key in \"" + OLD_KEYS.getName() + "\" is invalid: " + e.getMessage();
            }
        }

        if (problem == null && decrypt && keys.isEmpty())
            problem = "\"" + DECRYPT.getName() + "\" is set, but no key to decrypt with: set \"" + KEY.getName() + "\".";

        this.error = problem;
        this.current = problem != null || decrypt ? null : cipher;
        if (problem != null)
            keys.clear();

    }

    public static Secrets fromEnvironment(Environment environment) throws GuacamoleException {
        String oldKeys = environment.getProperty(OLD_KEYS);
        List<String> old = new ArrayList<>();
        if (oldKeys != null) {
            for (String key : oldKeys.split(","))
                if (!key.trim().isEmpty())
                    old.add(key.trim());
        }
        return new Secrets(environment.getProperty(KEY), old, environment.getProperty(DECRYPT, false));
    }

    /**
     * Whether new values are encrypted.
     */
    public boolean isEncrypting() {
        return current != null;
    }

    /**
     * Why secrets cannot be encrypted or decrypted, or null.
     */
    public String getError() {
        return error;
    }

    /**
     * The value as it must be stored: encrypted with the current key, or
     * plaintext without one. An encrypted value is decrypted first, so it
     * is checked, and only encrypted again if another key encrypted it.
     */
    public String protect(String purpose, String value) throws GuacamoleException {

        // A key was meant to be used: never store plaintext instead
        if (error != null && value != null && !value.isEmpty())
            throw new GuacamoleServerException("A secret cannot be stored: " + error);

        String plaintext = reveal(purpose, value);
        if (plaintext == null || plaintext.isEmpty() || current == null)
            return plaintext;

        if (current.getKeyId().equals(SecretCipher.keyIdOf(value)))
            return value;

        try {
            return current.encrypt(purpose, plaintext);
        }
        catch (GeneralSecurityException e) {
            throw new GuacamoleServerException("Unable to encrypt a secret.", e);
        }

    }

    /**
     * The value decrypted, or as it is if it is plaintext.
     *
     * @throws GuacamoleException
     *     If it is encrypted but cannot be decrypted here.
     */
    public String reveal(String purpose, String value) throws GuacamoleException {

        if (!SecretCipher.isEncrypted(value))
            return value;

        if (error != null)
            throw new GuacamoleServerException("A secret is encrypted, but cannot be decrypted: " + error);

        SecretCipher key = keys.get(SecretCipher.keyIdOf(value));
        if (key == null)
            throw new GuacamoleServerException("A secret is encrypted with key " + SecretCipher.keyIdOf(value)
                    + ", which is not configured" + (keys.isEmpty() ? " (\"" + KEY.getName() + "\" is not set)"
                    : ": add it to \"" + OLD_KEYS.getName() + "\"") + ".");

        try {
            return key.decrypt(purpose, value);
        }
        catch (GeneralSecurityException e) {
            throw new GuacamoleServerException("A secret could not be decrypted: it was altered, or belongs"
                    + " to another field.", e);
        }

    }

    /**
     * Whether a stored value is not in the form {@link #protect} gives: plaintext
     * while encrypting, encrypted with an earlier key, or encrypted while
     * decrypting everything. Values that cannot be decrypted here are left
     * alone.
     */
    public boolean needsMigration(String value) {

        if (value == null || value.isEmpty() || error != null)
            return false;

        if (!SecretCipher.isEncrypted(value))
            return current != null;

        String keyId = SecretCipher.keyIdOf(value);
        return keys.containsKey(keyId) && (current == null || !current.getKeyId().equals(keyId));

    }

    /**
     * Whether the value can be read here: plaintext, or encrypted with a
     * configured key.
     */
    public boolean canReveal(String value) {
        return !SecretCipher.isEncrypted(value)
                || (error == null && keys.containsKey(SecretCipher.keyIdOf(value)));
    }

    /**
     * Ids of the configured keys, the current one first.
     */
    public List<String> getKeyIds() {
        return Collections.unmodifiableList(new ArrayList<>(keys.keySet()));
    }

}
