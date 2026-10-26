package io.github.ialzamil.guacamole.pam.coordination;

/**
 * Why a server is on standby, read-only for PAM (see {@link Coordination}).
 */
public enum Standby {

    /** It has not yet checked whether other servers run. */
    STARTING("PAM is starting on this Guacamole server. Please try again in a moment."),

    /** Another server runs without the HA module. */
    OTHER_SERVER("Another Guacamole server runs PAM on this database without the HA module, so this one is on"
            + " standby until that one stops, or \"pam-ha: true\" is set on every server."),

    /** This one runs without the HA module, others with it. */
    SHARED_SERVERS("Guacamole servers with the HA module run PAM on this database, so this one, without it, is"
            + " on standby until \"pam-ha: true\" is set on it too."),

    /** This one runs the HA module, another without it. */
    SERVER_WITHOUT_HA("A Guacamole server without the HA module runs PAM on this database, so this one is on"
            + " standby until that one stops, or \"pam-ha: true\" is set on it too."),

    /** This server cannot tell, the database being unreachable. */
    DATABASE("This Guacamole server cannot reach the PAM database, so it is on standby until it can.");

    /**
     * Whether another server works on the database meanwhile: this one's
     * sessions of managed connections are then closed, as that one neither
     * counts them nor knows their connections in use.
     */
    public boolean isOtherServerWorking() {
        return this == OTHER_SERVER || this == SHARED_SERVERS || this == SERVER_WITHOUT_HA;
    }

    /**
     * What a server on standby refuses, ending every message.
     */
    private static final String READ_ONLY = " PAM is read-only here: no checkouts, approvals, rotations, setting"
            + " changes or sessions of managed connections.";

    private final String message;

    Standby(String message) {
        this.message = message;
    }

    public String getMessage() {
        return this == STARTING ? message : message + READ_ONLY;
    }

}
