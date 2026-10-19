package org.apache.guacamole.pam.crypto;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * Encrypts values with one AES-256-GCM key, as
 * "pam:v1:&lt;key id&gt;:&lt;base64 of nonce and ciphertext&gt;". The key id
 * (from a hash of the key) tells which key encrypted a value. Each value is
 * bound to its purpose, such as "platform-secrets", so a value cannot be
 * moved to another kind of field and decrypted there.
 *
 * Uses the JDK only, so stored values can be decrypted by hand:
 * <pre>
 * PAM_ENCRYPTION_KEY=... java -cp guacamole-pam-1.6.0.jar org.apache.guacamole.pam.crypto.SecretCipher PURPOSE
 * </pre>
 * reads a value on standard input and prints it decrypted.
 */
public final class SecretCipher {

    private static final String PREFIX = "pam:v1:";

    private static final Pattern ENCRYPTED = Pattern.compile("pam:v1:([0-9a-f]{8}):([A-Za-z0-9+/]+={0,2})");

    private static final int KEY_BYTES = 32;

    private static final int NONCE_BYTES = 12;

    private static final int TAG_BITS = 128;

    private static final SecureRandom RANDOM = new SecureRandom();

    private final SecretKeySpec key;

    private final String keyId;

    /**
     * @throws IllegalArgumentException
     *     If the key is not 32 bytes, encoded in base64.
     */
    public SecretCipher(String base64Key) {

        byte[] bytes;
        try {
            bytes = Base64.getDecoder().decode(base64Key == null ? "" : base64Key.trim());
        }
        catch (IllegalArgumentException e) {
            throw new IllegalArgumentException("The key is not valid base64.");
        }
        if (bytes.length != KEY_BYTES)
            throw new IllegalArgumentException("The key must be " + KEY_BYTES + " bytes (\"openssl rand -base64 32\"),"
                    + " not " + bytes.length + ".");

        key = new SecretKeySpec(bytes, "AES");
        keyId = hex(sha256(bytes)).substring(0, 8);

    }

    public String getKeyId() {
        return keyId;
    }

    /**
     * Whether the value has the form of an encrypted value.
     */
    public static boolean isEncrypted(String value) {
        return value != null && ENCRYPTED.matcher(value).matches();
    }

    /**
     * The id of the key that encrypted the value, or null if it is not
     * encrypted.
     */
    public static String keyIdOf(String value) {
        if (value == null)
            return null;
        Matcher matcher = ENCRYPTED.matcher(value);
        return matcher.matches() ? matcher.group(1) : null;
    }

    public String encrypt(String purpose, String plaintext) throws GeneralSecurityException {

        byte[] nonce = new byte[NONCE_BYTES];
        RANDOM.nextBytes(nonce);

        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(TAG_BITS, nonce));
        cipher.updateAAD(associatedData(purpose));
        byte[] ciphertext = cipher.doFinal(plaintext.getBytes(StandardCharsets.UTF_8));

        return PREFIX + keyId + ":" + Base64.getEncoder().encodeToString(
                ByteBuffer.allocate(nonce.length + ciphertext.length).put(nonce).put(ciphertext).array());

    }

    /**
     * @throws GeneralSecurityException
     *     If the value was not encrypted by this key for this purpose, or
     *     was altered.
     */
    public String decrypt(String purpose, String value) throws GeneralSecurityException {

        Matcher matcher = value == null ? null : ENCRYPTED.matcher(value);
        if (matcher == null || !matcher.matches())
            throw new GeneralSecurityException("Not an encrypted value.");
        if (!matcher.group(1).equals(keyId))
            throw new GeneralSecurityException("Encrypted by another key (" + matcher.group(1) + ").");

        byte[] data = Base64.getDecoder().decode(matcher.group(2));
        if (data.length < NONCE_BYTES + TAG_BITS / 8)
            throw new GeneralSecurityException("Truncated value.");

        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.DECRYPT_MODE, key, new GCMParameterSpec(TAG_BITS, data, 0, NONCE_BYTES));
        cipher.updateAAD(associatedData(purpose));
        return new String(cipher.doFinal(data, NONCE_BYTES, data.length - NONCE_BYTES), StandardCharsets.UTF_8);

    }

    private byte[] associatedData(String purpose) {
        return (PREFIX + keyId + ":" + purpose).getBytes(StandardCharsets.UTF_8);
    }

    private static byte[] sha256(byte[] bytes) {
        try {
            return MessageDigest.getInstance("SHA-256").digest(bytes);
        }
        catch (GeneralSecurityException e) {
            throw new IllegalStateException(e);
        }
    }

    private static String hex(byte[] bytes) {
        StringBuilder hex = new StringBuilder();
        for (byte b : bytes)
            hex.append(String.format("%02x", b));
        return hex.toString();
    }

    /**
     * Decrypts a value read on standard input, with the key in the
     * PAM_ENCRYPTION_KEY environment variable (never on the command line,
     * where other users could see it).
     */
    public static void main(String[] args) throws Exception {

        if (args.length != 1 || System.getenv("PAM_ENCRYPTION_KEY") == null) {
            System.err.println("Usage: PAM_ENCRYPTION_KEY=<key> java -cp guacamole-pam-1.6.0.jar "
                    + SecretCipher.class.getName() + " <purpose> < value");
            System.err.println("Purposes: " + Secrets.PLATFORM_SECRETS + ", " + Secrets.PENDING_PASSWORD + ", "
                    + Secrets.CONNECTION_PASSWORD);
            System.exit(2);
        }

        String value = new BufferedReader(new InputStreamReader(System.in, StandardCharsets.UTF_8)).readLine();
        try {
            System.out.println(new SecretCipher(System.getenv("PAM_ENCRYPTION_KEY")).decrypt(args[0],
                    value == null ? "" : value.trim()));
        }
        catch (IllegalArgumentException | GeneralSecurityException e) {
            System.err.println("Unable to decrypt: " + e.getMessage());
            System.exit(1);
        }

    }

}
