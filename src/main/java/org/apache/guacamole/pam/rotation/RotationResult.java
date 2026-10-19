package org.apache.guacamole.pam.rotation;

/**
 * Outcome of a single rotation, as returned by the REST API.
 */
public class RotationResult {

    /**
     * The new password was set on the target, verified, and stored.
     */
    public static final String SUCCESS = "SUCCESS";

    /**
     * The password on the target is unchanged.
     */
    public static final String FAILED = "FAILED";

    /**
     * Neither the old nor the new password is accepted any more. The new
     * password is kept in pam_rotation_state.pending_password.
     */
    public static final String UNKNOWN = "UNKNOWN";

    public static final String RUNNING = "RUNNING";

    private final String status;

    private final String message;

    public RotationResult(String status, String message) {
        this.status = status;
        this.message = message;
    }

    public String getStatus() {
        return status;
    }

    public String getMessage() {
        return message;
    }

}
