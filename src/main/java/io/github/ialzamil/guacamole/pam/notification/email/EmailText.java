package io.github.ialzamil.guacamole.pam.notification.email;

import java.time.Instant;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;

import io.github.ialzamil.guacamole.pam.notification.Event;
import io.github.ialzamil.guacamole.pam.notification.EventType;
import io.github.ialzamil.guacamole.pam.notification.Summary;

/**
 * The subject and text of the email of an event, as its recipient's role
 * calls for: what happened, its details, what to do next with a link to
 * Guacamole if its address is set, and why they receive it. Plain text,
 * never a password.
 */
final class EmailText {

    private static final String SUBJECT_PREFIX = "[Guacamole PAM] ";

    private static final int MAX_SUBJECT = 150;

    private static final DateTimeFormatter TIME = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss 'UTC'")
            .withZone(ZoneOffset.UTC);

    private EmailText() {
    }

    static String subject(Event event) {
        String subject = SUBJECT_PREFIX + Summary.of(event).replaceAll("[\\p{Cntrl}\\u2028\\u2029]+", " ");
        return subject.length() > MAX_SUBJECT ? subject.substring(0, MAX_SUBJECT - 3) + "..." : subject;
    }

    /**
     * The text, for a user of the given role, or for the address receiving
     * what administrators receive if the role is null.
     *
     * @param link
     *     Guacamole's address, such as "https://guac.example.org/guacamole/",
     *     or null if unknown.
     */
    static String body(Event event, Audience.Role role, String link) {

        StringBuilder text = new StringBuilder();
        text.append(Summary.of(event)).append("\n\n");

        line(text, "Connection", event.getConnectionName());
        line(text, "User", event.getUser());
        line(text, "By", event.getActor());
        line(text, "Request", event.getRequestId());
        line(text, "Checkout", event.getCheckoutId());
        line(text, event.getType() == EventType.CHECKOUT_STARTED || event.getType() == EventType.CHECKOUT_EXTENDED
                ? "Since" : "From", time(event.getStarts()));
        line(text, "Until", time(event.getEnds()));
        line(text, "Reason", event.getReason());
        line(text, "Details", event.getDetail());
        line(text, "Client address", event.getRemoteHost());
        line(text, "Server", event.getServer());
        line(text, "Time", time(event.getTime()));

        String next = next(event, role);
        if (next != null || link != null) {
            text.append('\n');
            if (next != null)
                text.append(next);
            if (link != null)
                text.append(next != null ? ": " : "").append(link(link, event, role));
            text.append('\n');
        }

        text.append("\n-- \n").append(why(role)).append('\n');
        return text.toString();

    }

    private static void line(StringBuilder text, String name, Object value) {
        if (value != null)
            text.append(name).append(": ").append(String.valueOf(value).replaceAll("[\\r\\n]+", " ")).append('\n');
    }

    private static String time(Long time) {
        return time == null ? null : TIME.format(Instant.ofEpochMilli(time));
    }

    /**
     * What the recipient may do next, or null.
     */
    private static String next(Event event, Audience.Role role) {
        switch (event.getType()) {
            case REQUEST_SUBMITTED:
            case REQUEST_APPROVED:
                return role == Audience.Role.OWN ? null : "Approve or deny it on the Approvals tab";
            case REQUEST_GRANTED:
                return role == Audience.Role.OWN ? (event.getStarts() != null
                        ? "Open the connection in Guacamole during that time" : "Open the connection in Guacamole")
                        : null;
            case CHECKOUT_EXPIRED:
            case CHECKOUT_REVOKED:
                return role == Audience.Role.OWN ? "To use it again, request it again in Guacamole" : null;
            case ROTATION_FAILED:
                return "See the Password Rotation tab";
            default:
                return null;
        }
    }

    /**
     * The page of Guacamole to open.
     */
    private static String link(String link, Event event, Audience.Role role) {
        String base = link.endsWith("/") ? link : link + "/";
        switch (event.getType()) {
            case REQUEST_SUBMITTED:
            case REQUEST_APPROVED:
                return role == Audience.Role.OWN ? base : base + "#/settings/pam-approvals";
            case ROTATION_FAILED:
                return base + "#/settings/pam-rotation";
            default:
                return base;
        }
    }

    private static String why(Audience.Role role) {
        if (role == null)
            return "This address receives what Guacamole administrators receive, as set on the PAM Settings tab.";
        switch (role) {
            case OWN:
                return "You receive this about your own requests and access. To stop, turn it off under"
                        + " Preferences > Email notifications in Guacamole.";
            case APPROVER:
                return "You receive this as an approver of the connection. To stop, turn it off under"
                        + " Preferences > Email notifications in Guacamole.";
            default:
                return "You receive this as a Guacamole administrator, for everything PAM does. To stop, turn it"
                        + " off under Preferences > Email notifications in Guacamole.";
        }
    }

}
