package org.apache.guacamole.pam.ssh;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

import com.jcraft.jsch.HostKey;
import com.jcraft.jsch.HostKeyRepository;
import com.jcraft.jsch.UserInfo;

/**
 * Host key check run by JSch before authenticating, so credentials are never
 * sent to a host whose key does not match the pinned fingerprint. Without a
 * pin any key is accepted, and its fingerprint is recorded for display.
 */
class PinnedHostKeyRepository implements HostKeyRepository {

    private final String pinned;

    private volatile String presented;

    PinnedHostKeyRepository(String pinnedFingerprint) {
        this.pinned = normalize(pinnedFingerprint);
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
        if (pinned == null || pinned.equals(normalize(presented)))
            return OK;
        return CHANGED;
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
