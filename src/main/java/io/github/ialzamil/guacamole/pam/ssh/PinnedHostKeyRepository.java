package io.github.ialzamil.guacamole.pam.ssh;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

import com.jcraft.jsch.HostKey;
import com.jcraft.jsch.HostKeyRepository;
import com.jcraft.jsch.UserInfo;

/**
 * Host key check run by JSch before authenticating, so credentials are never
 * sent to a host whose key does not match the pinned fingerprint. Without a
 * pin, any key is accepted only if asked to (trust on first use); either
 * way, the fingerprint presented is kept for display.
 */
class PinnedHostKeyRepository implements HostKeyRepository {

    private final String pinned;

    private final boolean acceptAny;

    private volatile String presented;

    private volatile String presentedType;

    PinnedHostKeyRepository(String pinnedFingerprint, boolean acceptAny) {
        this.pinned = normalize(pinnedFingerprint);
        this.acceptAny = acceptAny;
    }

    /**
     * Whether the key presented was refused for want of a trusted one, not
     * as a mismatch.
     */
    boolean isUntrusted() {
        return pinned == null && !acceptAny && presented != null;
    }

    /**
     * Fingerprint of the key presented by the host, in OpenSSH format
     * ("SHA256:..."), or null if no key was seen yet.
     */
    String getPresentedFingerprint() {
        return presented;
    }

    @Override
    public int check(String host, byte[] key) {
        presented = fingerprint(key);
        presentedType = type(key);
        if (pinned == null)
            return acceptAny ? OK : NOT_INCLUDED;
        return pinned.equals(normalize(presented)) ? OK : CHANGED;
    }

    @Override
    public void add(HostKey hostkey, UserInfo ui) {
    }

    @Override
    public void remove(String host, String type) {
    }

    @Override
    public void remove(String host, String type, byte[] key) {
    }

    @Override
    public String getKnownHostsRepositoryID() {
        return "guacamole-pam";
    }

    @Override
    public HostKey[] getHostKey() {
        return new HostKey[0];
    }

    @Override
    public HostKey[] getHostKey(String host, String type) {
        return new HostKey[0];
    }

    /**
     * Type of the key the host presented, such as "ssh-ed25519", or null.
     */
    String getPresentedType() {
        return presentedType;
    }

    /**
     * The type a public key blob starts with, after its length.
     */
    static String type(byte[] key) {
        if (key == null || key.length < 4)
            return null;
        int length = ((key[0] & 0xff) << 24) | ((key[1] & 0xff) << 16) | ((key[2] & 0xff) << 8) | (key[3] & 0xff);
        if (length <= 0 || length > key.length - 4 || length > 64)
            return null;
        return new String(key, 4, length, StandardCharsets.US_ASCII);
    }

    /**
     * Same format as "ssh-keygen -l": SHA256 digest, unpadded base64.
     */
    static String fingerprint(byte[] key) {
        try {
            byte[] digest = MessageDigest.getInstance("SHA-256").digest(key);
            return "SHA256:" + Base64.getEncoder().withoutPadding().encodeToString(digest);
        }
        catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }

    private static String normalize(String fingerprint) {

        if (fingerprint == null || fingerprint.trim().isEmpty())
            return null;

        String value = fingerprint.trim();
        if (value.regionMatches(true, 0, "SHA256:", 0, 7))
            value = value.substring(7);

        while (value.endsWith("="))
            value = value.substring(0, value.length() - 1);

        return value;

    }

}
