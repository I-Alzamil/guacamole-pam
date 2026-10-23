package io.github.ialzamil.guacamole.pam;

/**
 * Reading values as stored in Guacamole's tables and in platform settings,
 * where an empty value means unset.
 */
public final class Values {

    private Values() {
    }

    /**
     * The value trimmed, or null if it is missing or blank. For names,
     * hosts and other values whose surrounding spaces are typos.
     */
    public static String trimToNull(String value) {
        return value == null || value.trim().isEmpty() ? null : value.trim();
    }

    /**
     * A value for a log line, its control characters and line breaks as
     * spaces: names and reasons come from users, messages from servers, and
     * would otherwise start lines of their own.
     */
    public static String forLog(String value) {
        return value == null ? null : value.replaceAll("[\\p{Cntrl}\\u2028\\u2029]+", " ");
    }

    /**
     * The value, or null if it is missing or empty. For passwords and other
     * values whose spaces may be part of them.
     */
    public static String emptyToNull(String value) {
        return value == null || value.isEmpty() ? null : value;
    }

    /**
     * An identifier of Guacamole's tables, such as a connection's, as a
     * number, or null if it is not one.
     */
    public static Integer parseId(String identifier) {
        try {
            return identifier == null ? null : Integer.valueOf(identifier.trim());
        }
        catch (NumberFormatException e) {
            return null;
        }
    }

    /**
     * A port number, or null if the value is missing or not a port.
     */
    public static Integer toPort(String value) {
        Integer port = parseId(value);
        return port != null && port > 0 && port < 65536 ? port : null;
    }

    /**
     * A port number, or the given default if the value is missing or blank.
     *
     * @throws IllegalArgumentException
     *     If the value is set but is not a port.
     */
    public static int parsePort(String value, int defaultPort) {
        if (trimToNull(value) == null)
            return defaultPort;
        Integer port = toPort(value);
        if (port == null)
            throw new IllegalArgumentException("Invalid port: " + value.trim());
        return port;
    }

}
