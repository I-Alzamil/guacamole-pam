package io.github.ialzamil.guacamole.pam.notification;

import java.util.Locale;

/**
 * What happened, with how much it matters: its syslog severity (RFC 5424,
 * 0 emergency to 7 debug).
 */
public enum EventType {

    ROTATION_SUCCEEDED(6),
    ROTATION_FAILED(3),

    /**
     * A request awaits approval: for access, or to extend a checkout.
     */
    REQUEST_SUBMITTED(6),

    /**
     * One approval of a request needing more.
     */
    REQUEST_APPROVED(6),

    /**
     * The last approval of a request: access granted, reserved for its time,
     * or the checkout extended.
     */
    REQUEST_GRANTED(5),

    /**
     * Denied by an approver, or rejected as it overlaps a reservation.
     */
    REQUEST_DENIED(5),

    REQUEST_CANCELLED(6),

    CHECKOUT_STARTED(5),
    CHECKOUT_EXTENDED(6),
    CHECKOUT_RELEASED(6),
    CHECKOUT_EXPIRED(6),

    /**
     * Ended by an administrator, or as its connection was deleted.
     */
    CHECKOUT_REVOKED(4),

    PASSWORD_REVEALED(5),

    SESSION_STARTED(6),
    SESSION_ENDED(6),

    /**
     * This server went on standby: read-only for PAM.
     */
    SERVER_STANDBY(4),

    /**
     * This server works again after a standby.
     */
    SERVER_ACTIVE(5),

    SETTINGS_CHANGED(5),

    /**
     * A test of an output, from the settings page.
     */
    TEST(6);

    private final int severity;

    EventType(int severity) {
        this.severity = severity;
    }

    public int getSeverity() {
        return severity;
    }

    /**
     * The name of the type in messages: "rotation-failed".
     */
    public String getId() {
        return name().toLowerCase(Locale.ROOT).replace('_', '-');
    }

}
