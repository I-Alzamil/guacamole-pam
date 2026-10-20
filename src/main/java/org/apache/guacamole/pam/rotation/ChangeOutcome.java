package org.apache.guacamole.pam.rotation;

/**

 * What happened while changing a password on a target.
 */
public final class ChangeOutcome {

    private final boolean completed;
    private final boolean newPasswordSent;
    private final String error;
    private final String transcript;
    private final String hostKey;

    public ChangeOutcome(boolean completed, boolean newPasswordSent, String error,
            String transcript, String hostKey) {
        this.completed = completed;
        this.newPasswordSent = newPasswordSent;
        this.error = error;
        this.transcript = transcript;
        this.hostKey = hostKey;
    }

    /**
     * Whether the change ran to completion without reporting an error.
     */
    public boolean isCompleted() {
        return completed;
    }

    /**
     * Whether the new password was sent to the target. If not, the
     * password on the target is certainly unchanged.
     */
    public boolean isNewPasswordSent() {
        return newPasswordSent;
    }

    /**
     * Why the change stopped early, or null if it completed.
     */
    public String getError() {
        return error;
    }

    /**
     * Tail of the session output with both passwords masked, if any.
     */
    public String getTranscript() {
        return transcript;
    }

    /**
     * Fingerprint of the SSH host key or TLS certificate presented by the
     * target, if known.
     */
    public String getHostKey() {
        return hostKey;
    }

}
