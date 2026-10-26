package io.github.ialzamil.guacamole.pam.notification.syslog;

import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.charset.CharsetEncoder;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Map;

import io.github.ialzamil.guacamole.pam.notification.Event;
import io.github.ialzamil.guacamole.pam.notification.Summary;

/**
 * Events as syslog messages (RFC 5424): the event's type as MSGID, then a
 * sentence saying what happened, followed by its fields as name="value"
 * pairs, which log servers and SIEMs split without configuration:
 *
 * <pre>
 * &lt;85&gt;1 2026-10-27T10:00:00.123Z guac1 guacamole-pam - checkout-started - User "bob" checked out
 * "web01". event="checkout-started" user="bob" connection="web01" connection-id="3" checkout="12" ...
 * </pre>
 *
 * Messages are cut at {@link #MAX_BYTES}, what log servers accept by
 * default.
 */
public final class SyslogFormat {

    private SyslogFormat() {
    }

    public static final String DEFAULT_APP_NAME = "guacamole-pam";

    static final int MAX_APP_NAME = 48;

    private static final int MAX_HOSTNAME = 255;

    /**
     * Longest message, in bytes.
     */
    static final int MAX_BYTES = 8192;

    /**
     * Refuses what RFC 5424 does not allow as APP-NAME: printable ASCII
     * without spaces.
     */
    static void checkAppName(String name) {
        if (!isPrintable(name))
            throw new IllegalArgumentException("only letters, digits and punctuation, without spaces.");
    }

    /**
     * The message of an event, in UTF-8, without framing.
     */
    public static byte[] format(Event event, int facility, String appName) {

        StringBuilder message = new StringBuilder();
        message.append('<').append(facility * 8 + event.getType().getSeverity()).append(">1 ")
                .append(Instant.ofEpochMilli(event.getTime())).append(' ')
                .append(header(event.getServer(), MAX_HOSTNAME)).append(' ')
                .append(header(appName == null ? DEFAULT_APP_NAME : appName, MAX_APP_NAME))
                .append(" - ").append(event.getType().getId()).append(" - ")
                .append(oneLine(Summary.of(event)))
                .append(" event=\"").append(event.getType().getId()).append('"');

        for (Map.Entry<String, Object> field : event.getFields().entrySet())
            message.append(' ').append(field.getKey()).append("=\"")
                    .append(escape(oneLine(String.valueOf(field.getValue())))).append('"');

        return truncate(message.toString());

    }

    /**
     * A header field as RFC 5424 allows: printable ASCII, "-" if none is
     * left.
     */
    private static String header(String value, int max) {
        StringBuilder kept = new StringBuilder();
        for (char c : value.toCharArray()) {
            if (c > 32 && c < 127 && kept.length() < max)
                kept.append(c);
        }
        return kept.length() == 0 ? "-" : kept.toString();
    }

    private static boolean isPrintable(String value) {
        for (char c : value.toCharArray()) {
            if (c <= 32 || c >= 127)
                return false;
        }
        return !value.isEmpty();
    }

    /**
     * Line breaks and other control characters as spaces, so a message is
     * one line however it is framed.
     */
    private static String oneLine(String value) {
        StringBuilder line = new StringBuilder(value.length());
        for (char c : value.toCharArray())
            line.append(Character.isISOControl(c) ? ' ' : c);
        return line.toString();
    }

    private static String escape(String value) {
        return value.replace("\\", "\\\\").replace("\"", "\\\"");
    }

    /**
     * The message in UTF-8, cut at {@link #MAX_BYTES} between characters.
     */
    private static byte[] truncate(String message) {
        CharsetEncoder encoder = StandardCharsets.UTF_8.newEncoder()
                .onMalformedInput(CodingErrorAction.REPLACE).onUnmappableCharacter(CodingErrorAction.REPLACE);
        ByteBuffer bytes = ByteBuffer.allocate(MAX_BYTES);
        encoder.encode(CharBuffer.wrap(message), bytes, true);
        byte[] encoded = new byte[bytes.position()];
        bytes.flip();
        bytes.get(encoded);
        return encoded;
    }

}
