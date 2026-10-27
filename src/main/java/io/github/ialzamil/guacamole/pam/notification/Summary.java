package io.github.ialzamil.guacamole.pam.notification;

import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

import io.github.ialzamil.guacamole.pam.notification.email.EmailLanguage;
import io.github.ialzamil.guacamole.pam.notification.email.EmailLanguages;
import io.github.ialzamil.guacamole.pam.notification.email.EmailTemplates;

/**
 * What an event says, in one sentence: "User "bob" checked out "web01".",
 * as outputs give it before its details: the SUMMARY_ message of its type
 * in a language (see {@link EmailLanguage}), English as built in unless
 * another is given.
 */
public final class Summary {

    private static final EmailLanguage ENGLISH = EmailLanguages.getBuiltIn();

    private Summary() {
    }

    public static String of(Event event) {
        return of(event, ENGLISH::message);
    }

    /**
     * The sentence of the event from the given messages, by key, values
     * unknown said so ("UNKNOWN").
     */
    public static String of(Event event, Function<String, String> messages) {

        String key;
        boolean byAnother = event.getActor() != null && !event.getActor().equals(event.getUser());
        if (event.getType() == EventType.REQUEST_DENIED && !byAnother)
            key = "SUMMARY_REQUEST_REJECTED";
        else if (event.getType() == EventType.CHECKOUT_REVOKED && event.getActor() != null)
            key = "SUMMARY_CHECKOUT_REVOKED_BY";
        else
            key = "SUMMARY_" + event.getType().name();

        return EmailTemplates.render(messages.apply(key), values(event, messages));

    }

    /**
     * The event's detail in English, from its message (see
     * {@link Event#detailMessage}).
     */
    static String detail(Event event) {
        return detail(event, ENGLISH::message);
    }

    /**
     * The event's detail from its message in the given messages, or null
     * if it has none.
     */
    public static String detail(Event event, Function<String, String> messages) {
        return event.getDetailKey() == null ? null
                : EmailTemplates.render(messages.apply(event.getDetailKey()), values(event, messages));
    }

    private static Map<String, String> values(Event event, Function<String, String> messages) {
        String unknown = messages.apply("UNKNOWN");
        Map<String, String> values = new HashMap<>();
        values.put("user", orElse(event.getUser(), unknown));
        values.put("actor", orElse(event.getActor(), unknown));
        values.put("connection", orElse(event.getConnectionName() != null ? event.getConnectionName()
                : event.getConnectionIdentifier(), unknown));
        values.put("request", orElse(event.getRequestId() == null ? null : event.getRequestId().toString(), unknown));
        values.put("server", event.getServer());
        values.put("minutes", orElse(event.getMinutes() == null ? null : event.getMinutes().toString(), unknown));
        values.put("approvals", orElse(event.getApprovals() == null ? null : event.getApprovals().toString(),
                unknown));
        values.put("approvals-required", orElse(event.getApprovalsRequired() == null ? null
                : event.getApprovalsRequired().toString(), unknown));
        return values;
    }

    private static String orElse(String value, String otherwise) {
        return value != null ? value : otherwise;
    }

}
