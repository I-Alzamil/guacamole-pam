package io.github.ialzamil.guacamole.pam.notification.email;

import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import io.github.ialzamil.guacamole.pam.notification.EventType;

/**
 * The templates of emails: in each language (see {@link EmailLanguage}), a
 * subject and a body for each kind of email, in which placeholders such as
 * "{user}" are replaced by the event's values, as text (a value is never
 * read as a template). Those of the recipient's role, "{action}" and
 * "{why}", say what to do next and why they receive it. "{{" and "}}"
 * stand for "{" and "}". A language's messages use the same placeholders.
 */
public final class EmailTemplates {

    private EmailTemplates() {
    }

    /**
     * Every placeholder, in the order the Email Templates tab lists them.
     */
    static final Set<String> PLACEHOLDERS = Collections.unmodifiableSet(new LinkedHashSet<>(Arrays.asList(
            "summary", "details", "action", "link", "why", "event", "user", "actor", "connection", "connection-id",
            "request", "checkout", "minutes", "approvals", "approvals-required", "starts", "ends", "reason",
            "detail", "client-address", "server", "time")));

    private static final Pattern PLACEHOLDER = Pattern.compile("\\{\\{|\\}\\}|\\{([a-z-]+)\\}");

    /**
     * A placeholder of any name, to find those that do not exist.
     */
    private static final Pattern UNKNOWN = Pattern.compile("\\{([A-Za-z_-]+)\\}");

    /**
     * Kinds of email, each with its own template, by the events they are
     * about.
     */
    public enum Kind {

        /**
         * A request awaiting approval, or another approval of it.
         */
        APPROVAL("approval", EventType.REQUEST_SUBMITTED, EventType.REQUEST_APPROVED),

        /**
         * A request granted or denied, or expired undecided.
         */
        DECISION("decision", EventType.REQUEST_GRANTED, EventType.REQUEST_DENIED, EventType.REQUEST_EXPIRED),

        /**
         * A checkout expired, or ended by someone else.
         */
        ENDED("ended", EventType.CHECKOUT_EXPIRED, EventType.CHECKOUT_REVOKED),

        /**
         * Every other event, which administrators receive.
         */
        OTHER("other");

        private final String name;
        private final List<EventType> types;

        Kind(String name, EventType... types) {
            this.name = name;
            this.types = Arrays.asList(types);
        }

        /**
         * Its name in languages' files: "approval".
         */
        public String getName() {
            return name;
        }

        static Kind of(EventType type) {
            for (Kind kind : values()) {
                if (kind.types.contains(type))
                    return kind;
            }
            return OTHER;
        }

        static Kind named(String name) {
            for (Kind kind : values()) {
                if (kind.name.equals(name))
                    return kind;
            }
            return null;
        }

    }

    /**
     * Refuses a template naming a placeholder that does not exist, likely
     * mistyped.
     *
     * @throws IllegalArgumentException
     *     If one does not exist.
     */
    static void check(String template) {
        Matcher matcher = UNKNOWN.matcher(template.replace("{{", "").replace("}}", ""));
        while (matcher.find()) {
            if (!PLACEHOLDERS.contains(matcher.group(1)))
                throw new IllegalArgumentException("unknown placeholder {" + matcher.group(1) + "}. Placeholders: {"
                        + String.join("}, {", PLACEHOLDERS) + "}.");
        }
    }

    /**
     * The template with each placeholder replaced by its value, or nothing
     * if it has none.
     */
    public static String render(String template, Map<String, String> values) {
        Matcher matcher = PLACEHOLDER.matcher(template);
        StringBuffer text = new StringBuffer();
        while (matcher.find()) {
            String replacement;
            if (matcher.group(1) == null)
                replacement = matcher.group().substring(1);
            else {
                String value = values.get(matcher.group(1));
                replacement = value != null ? value : PLACEHOLDERS.contains(matcher.group(1)) ? ""
                        : matcher.group();
            }
            matcher.appendReplacement(text, Matcher.quoteReplacement(replacement));
        }
        matcher.appendTail(text);
        return text.toString();
    }

}
