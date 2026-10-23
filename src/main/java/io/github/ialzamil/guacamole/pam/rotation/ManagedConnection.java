package io.github.ialzamil.guacamole.pam.rotation;

import java.sql.Timestamp;

import io.github.ialzamil.guacamole.pam.PamAttributes;
import io.github.ialzamil.guacamole.pam.db.ConnectionRepository;
import io.github.ialzamil.guacamole.pam.platform.Platform;

/**
 * A connection with a platform, with its effective policy and latest
 * rotation state, as listed by the REST API.
 */
public class ManagedConnection {

    private final String identifier;
    private final String name;
    private final String protocol;
    private final String platformId;
    private final String platformName;
    private final String platformType;
    private final String mode;
    private final Integer interval;
    private final boolean overridden;
    private final Long lastAttempt;
    private final Long lastSuccess;
    private final String status;
    private final String message;
    private final String hostKey;
    private final boolean pendingPassword;
    private final int activeSessions;
    private final boolean rotating;

    ManagedConnection(ConnectionRepository.Target target, Platform platform, EffectivePolicy policy,
            int activeSessions, boolean rotating) {

        ConnectionRepository.State state = target.getState();

        this.identifier = Integer.toString(target.getId());
        this.name = target.getName();
        this.protocol = target.getProtocol();
        this.platformId = target.getAttribute(PamAttributes.PLATFORM);
        this.platformName = platform == null ? null : platform.getName();
        this.platformType = platform == null ? null : platform.getType();
        this.mode = policy.getMode();
        this.interval = policy.getIntervalHours();
        this.overridden = target.getAttribute(PamAttributes.ROTATION_MODE) != null
                || target.getAttribute(PamAttributes.ROTATION_INTERVAL) != null
                || target.getAttribute(PamAttributes.PASSWORD_LENGTH) != null;
        this.lastAttempt = toMillis(state.getLastAttempt());
        this.lastSuccess = toMillis(state.getLastSuccess());
        this.status = rotating ? RotationResult.RUNNING : state.getStatus();
        this.message = state.getMessage();
        this.hostKey = state.getHostKey();
        this.pendingPassword = state.hasPendingPassword();
        this.activeSessions = activeSessions;
        this.rotating = rotating;

    }

    private static Long toMillis(Timestamp timestamp) {
        return timestamp == null ? null : timestamp.getTime();
    }

    public String getIdentifier() {
        return identifier;
    }

    public String getName() {
        return name;
    }

    public String getProtocol() {
        return protocol;
    }

    public String getPlatformId() {
        return platformId;
    }

    /**
     * Name of the platform, or null if it no longer exists.
     */
    public String getPlatformName() {
        return platformName;
    }

    public String getPlatformType() {
        return platformType;
    }

    /**
     * Effective rotation mode: "never", "after-use" or "periodic".
     */
    public String getMode() {
        return mode;
    }

    /**
     * Effective hours between periodic rotations, or null.
     */
    public Integer getInterval() {
        return interval;
    }

    /**
     * Whether the connection overrides part of its platform's policy.
     */
    public boolean isOverridden() {
        return overridden;
    }

    public Long getLastAttempt() {
        return lastAttempt;
    }

    public Long getLastSuccess() {
        return lastSuccess;
    }

    public String getStatus() {
        return status;
    }

    public String getMessage() {
        return message;
    }

    public String getHostKey() {
        return hostKey;
    }

    public boolean isPendingPassword() {
        return pendingPassword;
    }

    public int getActiveSessions() {
        return activeSessions;
    }

    public boolean isRotating() {
        return rotating;
    }

}
