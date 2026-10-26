package io.github.ialzamil.guacamole.pam.notification;

/**
 * What an event says, in one sentence: "User "bob" checked out "web01".",
 * as outputs give it before its details.
 */
public final class Summary {

    private Summary() {
    }

    public static String of(Event event) {

        String user = quoted(event.getUser());
        String actor = quoted(event.getActor());
        String connection = quoted(event.getConnectionName() != null ? event.getConnectionName()
                : event.getConnectionIdentifier());
        String request = event.getRequestId() == null ? "A request" : "Request " + event.getRequestId();

        switch (event.getType()) {
            case ROTATION_SUCCEEDED:
                return "The password of " + connection + " was rotated.";
            case ROTATION_FAILED:
                return "The rotation of the password of " + connection + " failed.";
            case REQUEST_SUBMITTED:
                return "User " + user + " requested " + connection + ", which awaits approval.";
            case REQUEST_APPROVED:
                return "User " + actor + " approved the request of " + user + " for " + connection
                        + ", which needs more approvals.";
            case REQUEST_GRANTED:
                return "User " + actor + " approved the request of " + user + " for " + connection + ".";
            case REQUEST_DENIED:
                return event.getActor() == null || event.getActor().equals(event.getUser())
                        ? request + " of " + user + " for " + connection + " was rejected."
                        : "User " + actor + " denied the request of " + user + " for " + connection + ".";
            case REQUEST_CANCELLED:
                return request + " of " + user + " for " + connection + " was cancelled.";
            case CHECKOUT_STARTED:
                return "User " + user + " checked out " + connection + ".";
            case CHECKOUT_EXTENDED:
                return "The checkout of " + connection + " by " + user + " was extended.";
            case CHECKOUT_RELEASED:
                return "User " + user + " released " + connection + ".";
            case CHECKOUT_EXPIRED:
                return "The checkout of " + connection + " by " + user + " expired.";
            case CHECKOUT_REVOKED:
                return "The checkout of " + connection + " by " + user + " was ended"
                        + (event.getActor() == null ? "" : " by " + actor) + ".";
            case PASSWORD_REVEALED:
                return "User " + user + " viewed the password of " + connection + ".";
            case SESSION_STARTED:
                return "User " + user + " connected to " + connection + ".";
            case SESSION_ENDED:
                return "User " + user + " disconnected from " + connection + ".";
            case SERVER_STANDBY:
                return "Guacamole server \"" + event.getServer() + "\" is on standby: PAM is read-only there.";
            case SERVER_ACTIVE:
                return "PAM works again on Guacamole server \"" + event.getServer() + "\".";
            case SETTINGS_CHANGED:
                return "User " + actor + " changed the PAM settings.";
            case TEST:
                return "A test from the PAM settings page, sent by " + actor + ".";
            default:
                return event.getType().getId();
        }

    }

    private static String quoted(String value) {
        return value == null ? "(unknown)" : "\"" + value + "\"";
    }

}
