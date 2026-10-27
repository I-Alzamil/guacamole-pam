package io.github.ialzamil.guacamole.pam.notification.email;

import java.time.Instant;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.HashMap;
import java.util.Map;

import io.github.ialzamil.guacamole.pam.Values;
import io.github.ialzamil.guacamole.pam.notification.Event;
import io.github.ialzamil.guacamole.pam.notification.EventType;
import io.github.ialzamil.guacamole.pam.notification.Summary;

/**
 * The subject and text of the email of an event, in one language: from the
 * template of its kind (see {@link EmailTemplates}), filled with that
 * language's messages (see {@link EmailLanguages}) as its recipient's role
 * calls for: what happened, its details, what to do next with a link to
 * Guacamole if its address is set, and why they receive it. Plain text,
 * never a password.
 */
final class EmailText {

    private static final int MAX_SUBJECT = 150;

    private final String subject;

    private final String body;

    private final String link;

    private final DateTimeFormatter time;

    private final EmailLanguage language;

    /**
     * @param language
     *     The language, complete (see {@link EmailLanguage#over}).
     *
     * @param kind
     *     The kind of email, whose templates are used.
     *
     * @param link
     *     Guacamole's address, such as "https://guac.example.org/guacamole/",
     *     or null if unknown.
     *
     * @param zone
     *     The time zone of the times shown.
     */
    EmailText(EmailLanguage language, EmailTemplates.Kind kind, String link, ZoneId zone) {
        this.language = language;
        this.subject = language.template(kind).getSubject();
        this.body = language.template(kind).getBody();
        this.link = link;
        this.time = zone.normalized().equals(ZoneOffset.UTC)
                ? DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss 'UTC'").withZone(ZoneOffset.UTC)
                : DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss xxx '('VV')'").withZone(zone);
    }

    /**
     * The built-in English of the given kind, with times in UTC.
     */
    static EmailText standard(EmailTemplates.Kind kind, String link) {
        return new EmailText(EmailLanguages.getBuiltIn(), kind, link, ZoneOffset.UTC);
    }

    /**
     * The subject: one line, cut at {@link #MAX_SUBJECT} characters.
     */
    String subject(Event event, Audience.Role role) {
        String line = oneLine(EmailTemplates.render(subject, values(event, role))).trim();
        return line.length() > MAX_SUBJECT ? line.substring(0, MAX_SUBJECT - 3) + "..." : line;
    }

    /**
     * The text, for a user of the given role, or for the address receiving
     * what administrators receive if the role is null. Lines left empty by
     * placeholders without a value never make more than one blank line.
     */
    String body(Event event, Audience.Role role) {
        String text = EmailTemplates.render(body, values(event, role)).replace("\r\n", "\n")
                .replaceAll("\n(?:[ \t]*\n){2,}", "\n\n");
        return text.trim() + "\n";
    }

    /**
     * The value of each placeholder, null where the event has none.
     */
    private Map<String, String> values(Event event, Audience.Role role) {

        Map<String, String> values = new HashMap<>();
        values.put("event", event.getType().getId());
        values.put("user", oneLine(event.getUser()));
        values.put("actor", oneLine(event.getActor()));
        values.put("connection", oneLine(event.getConnectionName()));
        values.put("connection-id", event.getConnectionIdentifier());
        values.put("request", event.getRequestId() == null ? null : event.getRequestId().toString());
        values.put("checkout", event.getCheckoutId() == null ? null : event.getCheckoutId().toString());
        values.put("minutes", event.getMinutes() == null ? null : event.getMinutes().toString());
        values.put("approvals", event.getApprovals() == null ? null : event.getApprovals().toString());
        values.put("approvals-required", event.getApprovalsRequired() == null ? null
                : event.getApprovalsRequired().toString());
        values.put("starts", time(event.getStarts()));
        values.put("ends", time(event.getEnds()));
        values.put("reason", oneLine(event.getReason()));
        values.put("detail", oneLine(detail(event)));
        // Where someone else acted from is not the user's to know
        boolean byAnother = event.getActor() != null && !event.getActor().equals(event.getUser());
        values.put("client-address", role == Audience.Role.OWN && byAnother ? null : event.getRemoteHost());
        values.put("server", event.getServer());
        values.put("time", time(event.getTime()));
        values.put("summary", oneLine(Summary.of(event, language::message)));

        StringBuilder details = new StringBuilder();
        line(details, "LABEL_CONNECTION", values.get("connection"));
        line(details, "LABEL_USER", values.get("user"));
        line(details, "LABEL_BY", values.get("actor"));
        line(details, "LABEL_REQUEST", values.get("request"));
        line(details, "LABEL_CHECKOUT", values.get("checkout"));
        line(details, event.getType() == EventType.CHECKOUT_STARTED || event.getType() == EventType.CHECKOUT_EXTENDED
                ? "LABEL_SINCE" : "LABEL_FROM", values.get("starts"));
        line(details, "LABEL_UNTIL", values.get("ends"));
        line(details, "LABEL_REASON", values.get("reason"));
        line(details, "LABEL_DETAILS", values.get("detail"));
        line(details, "LABEL_CLIENT_ADDRESS", values.get("client-address"));
        line(details, "LABEL_SERVER", values.get("server"));
        line(details, "LABEL_TIME", values.get("time"));
        values.put("details", details.toString().trim());

        String next = next(event, role);
        String page = link == null ? null : link(link, event, role);
        values.put("link", page);
        values.put("action", next == null ? page : page == null ? next : next + ": " + page);
        values.put("why", message(role == null ? "WHY_ADDRESS" : role == Audience.Role.OWN ? "WHY_OWN"
                : role == Audience.Role.APPROVER ? "WHY_APPROVER" : "WHY_ADMINISTRATOR"));
        return values;

    }

    private String message(String key) {
        return language.message(key);
    }

    /**
     * The event's detail, in the language where PAM wrote it; as recorded,
     * in English, where it came from elsewhere, such as a rotation's error.
     */
    private String detail(Event event) {
        return event.getDetailKey() != null ? Summary.detail(event, language::message) : event.getDetail();
    }

    private void line(StringBuilder text, String label, String value) {
        if (value != null)
            text.append(message(label)).append(": ").append(value).append('\n');
    }

    /**
     * Line breaks and other control characters as spaces, so a value never
     * adds lines, nor headers to a subject.
     */
    private static String oneLine(String value) {
        return value == null ? null : value.replaceAll(Values.UNPRINTABLE, " ");
    }

    private String time(Long millis) {
        return millis == null ? null : time.format(Instant.ofEpochMilli(millis));
    }

    /**
     * What the recipient may do next, or null.
     */
    private String next(Event event, Audience.Role role) {
        switch (event.getType()) {
            case REQUEST_SUBMITTED:
            case REQUEST_APPROVED:
                return role == Audience.Role.OWN ? null : message("ACTION_APPROVE");
            case REQUEST_GRANTED:
                return role == Audience.Role.OWN
                        ? message(event.getStarts() != null ? "ACTION_OPEN_DURING" : "ACTION_OPEN") : null;
            case REQUEST_EXPIRED:
            case CHECKOUT_EXPIRED:
            case CHECKOUT_REVOKED:
                return role == Audience.Role.OWN ? message("ACTION_REQUEST_AGAIN") : null;
            case ROTATION_FAILED:
                return message("ACTION_ROTATION");
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

}
