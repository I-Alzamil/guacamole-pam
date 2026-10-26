package io.github.ialzamil.guacamole.pam.ssh;

import java.util.List;

/**
 * Where and as whom to log in over SSH to rotate a password.
 */
public final class SshTarget {

    private final String hostname;
    private final int port;
    private final String username;
    private final String password;
    private final String privateKey;
    private final String passphrase;
    private final String pinnedHostKey;
    private final boolean trustFirstKey;
    private final List<byte[]> authorities;

    public SshTarget(String hostname, int port, String username, String password,
            String privateKey, String passphrase, String pinnedHostKey, boolean trustFirstKey,
            List<byte[]> authorities) {
        this.hostname = hostname;
        this.port = port;
        this.username = username;
        this.password = password;
        this.privateKey = privateKey;
        this.passphrase = passphrase;
        this.pinnedHostKey = pinnedHostKey;
        this.trustFirstKey = trustFirstKey;
        this.authorities = authorities;
    }

    /**
     * Returns a copy of this target using a different current password.
     */
    public SshTarget withPassword(String newPassword) {
        return new SshTarget(hostname, port, username, newPassword, privateKey, passphrase, pinnedHostKey,
                trustFirstKey, authorities);
    }

    public String getHostname() {
        return hostname;
    }

    public int getPort() {
        return port;
    }

    public String getUsername() {
        return username;
    }

    /**
     * The current password, possibly null for key-based connections.
     */
    public String getPassword() {
        return password;
    }

    public String getPrivateKey() {
        return privateKey;
    }

    public String getPassphrase() {
        return passphrase;
    }

    /**
     * SHA256 fingerprint the host key must match, or null if none is
     * trusted yet.
     */
    public String getPinnedHostKey() {
        return pinnedHostKey;
    }

    /**
     * Whether any host key is accepted while none is trusted yet, at the
     * first contact with the host.
     */
    public boolean isTrustFirstKey() {
        return trustFirstKey;
    }

    /**
     * Keys of the certificate authorities whose host certificates are
     * trusted, unless a host key is pinned; empty if none.
     */
    public List<byte[]> getAuthorities() {
        return authorities;
    }

}
