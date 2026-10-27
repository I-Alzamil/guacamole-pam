package io.github.ialzamil.guacamole.pam.ssh;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collections;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import com.jcraft.jsch.HostKey;
import com.jcraft.jsch.HostKeyRepository;
import com.jcraft.jsch.JSchException;
import com.jcraft.jsch.UserInfo;

/**
 * Host key check run by JSch before authenticating, so credentials are never
 * sent to a host whose key does not match the pinned fingerprint. Without a
 * pin, a host certificate signed by one of the given certificate
 * authorities is trusted, which JSch checks with the authorities this
 * lists (as known_hosts "@cert-authority" lines); otherwise any key is
 * accepted only if asked to (trust on first use). Either way, the
 * fingerprint of a key presented is kept for display.
 */
class PinnedHostKeyRepository implements HostKeyRepository {

    /**
     * A SHA-256 fingerprint anywhere in a line.
     */
    private static final Pattern SHA256_FINGERPRINT = Pattern.compile("(?i)SHA256:([A-Za-z0-9+/]+)");

    private final String pinned;

    private final boolean acceptAny;

    /**
     * The authorities, as JSch reads them, for the host as JSch looks it up.
     */
    private final HostKey[] authorities;

    private volatile String presented;

    private volatile String presentedType;

    /**
     * Whether the key presented was accepted.
     */
    private volatile boolean accepted;

    PinnedHostKeyRepository(String pinnedFingerprint, boolean acceptAny) {
        this(pinnedFingerprint, acceptAny, null, 0, Collections.<byte[]>emptyList());
    }

    /**
     * @param authorities
     *     Keys of the certificate authorities trusted for the given host and
     *     port, unless a fingerprint is pinned.
     */
    PinnedHostKeyRepository(String pinnedFingerprint, boolean acceptAny, String host, int port,
            List<byte[]> authorities) {
        this.pinned = normalize(pinnedFingerprint);
        this.acceptAny = acceptAny;
        List<HostKey> keys = new ArrayList<>();
        if (pinned == null) {
            // As JSch names the host it looks up
            String lookup = port == 22 ? host : "[" + host + "]:" + port;
            for (byte[] key : authorities) {
                try {
                    keys.add(new HostKey("@cert-authority", lookup, HostKey.GUESS, key, null));
                }
                catch (JSchException e) {
                    throw new IllegalArgumentException("Unsupported SSH CA key: " + e.getMessage(), e);
                }
            }
        }
        this.authorities = keys.toArray(new HostKey[0]);
    }

    /**
     * Whether host certificates of certificate authorities are trusted.
     */
    boolean hasAuthorities() {
        return authorities.length > 0;
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

    /**
     * Fingerprint of the key presented, if it was accepted, or null: the
     * only one to record, so a key refused as untrusted never becomes
     * trusted later.
     */
    String getTrustedFingerprint() {
        return accepted ? presented : null;
    }

    @Override
    public int check(String host, byte[] key) {
        presented = fingerprint(key);
        presentedType = type(key);
        int result = pinned == null ? (acceptAny ? OK : NOT_INCLUDED)
                : pinned.equals(normalize(presented)) ? OK : CHANGED;
        accepted = result == OK;
        return result;
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
        return authorities.clone();
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

        // As pasted from "ssh-keygen -lf": "256 SHA256:... root@host (ED25519)"
        String value = fingerprint.trim();
        Matcher inLine = SHA256_FINGERPRINT.matcher(value);
        if (inLine.find())
            value = inLine.group(1);
        else if (value.regionMatches(true, 0, "SHA256:", 0, 7))
            value = value.substring(7);

        while (value.endsWith("="))
            value = value.substring(0, value.length() - 1);

        return value;

    }

}
