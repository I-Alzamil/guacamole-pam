package io.github.ialzamil.guacamole.pam.ha;

import java.util.Map;

import org.apache.guacamole.GuacamoleClientTooManyException;
import org.apache.guacamole.GuacamoleException;
import org.apache.guacamole.GuacamoleResourceConflictException;
import org.apache.guacamole.environment.Environment;

/**
 * The limits of Guacamole's database authentication on the sessions of a
 * connection or a balancing connection group, applied to the sessions of
 * every server: its "max-connections" and "max-connections-per-user"
 * attributes, or else the defaults of guacamole.properties, and the
 * absolute maximum of all sessions. Zero is no limit, as in Guacamole. A
 * refusal is the one Guacamole gives, so users see the same message.
 */
final class Limits {

    /**
     * The attributes of connections and connection groups holding their
     * limits.
     */
    static final String MAX_CONNECTIONS = "max-connections";
    static final String MAX_CONNECTIONS_PER_USER = "max-connections-per-user";

    /**
     * The defaults of guacamole.properties, of one database.
     */
    static final class Defaults {

        private final int absolute;
        private final int connection;
        private final int connectionPerUser;
        private final int group;
        private final int groupPerUser;

        Defaults(int absolute, int connection, int connectionPerUser, int group, int groupPerUser) {
            this.absolute = absolute;
            this.connection = connection;
            this.connectionPerUser = connectionPerUser;
            this.group = group;
            this.groupPerUser = groupPerUser;
        }

        /**
         * The defaults of the given database, as Guacamole reads them: one
         * session per user through a balancing group, otherwise no limit.
         */
        static Defaults fromEnvironment(DatabaseType type, Environment environment) throws GuacamoleException {
            return new Defaults(
                    read(environment, type, "absolute-max-connections", 0),
                    read(environment, type, "default-max-connections", 0),
                    read(environment, type, "default-max-connections-per-user", 0),
                    read(environment, type, "default-max-group-connections", 0),
                    read(environment, type, "default-max-group-connections-per-user", 1));
        }

        private static int read(Environment environment, DatabaseType type, String name, int defaultValue)
                throws GuacamoleException {
            return environment.getProperty(Settings.integer(type.property(name)), defaultValue);
        }

    }

    private final Target.Kind kind;
    private final int absolute;
    private final int max;
    private final int maxPerUser;

    Limits(Target.Kind kind, int absolute, int max, int maxPerUser) {
        this.kind = kind;
        this.absolute = absolute;
        this.max = max;
        this.maxPerUser = maxPerUser;
    }

    /**
     * The limits of a connection or connection group with the given
     * attributes. An attribute missing, empty or not a number takes the
     * default.
     */
    static Limits of(Target.Kind kind, Map<String, String> attributes, Defaults defaults) {
        boolean group = kind == Target.Kind.CONNECTION_GROUP;
        return new Limits(kind, defaults.absolute,
                attribute(attributes, MAX_CONNECTIONS, group ? defaults.group : defaults.connection),
                attribute(attributes, MAX_CONNECTIONS_PER_USER,
                        group ? defaults.groupPerUser : defaults.connectionPerUser));
    }

    private static int attribute(Map<String, String> attributes, String name, int defaultValue) {
        String value = attributes == null ? null : attributes.get(name);
        if (value == null || value.trim().isEmpty())
            return defaultValue;
        try {
            return Integer.parseInt(value.trim());
        }
        catch (NumberFormatException e) {
            return defaultValue;
        }
    }

    /**
     * Refuses one more session given those open now, on every server, in
     * the order Guacamole checks: all sessions, then the user's, then all
     * of the connection's.
     *
     * @param total
     *     Sessions open, of anything.
     *
     * @param ofTarget
     *     Sessions open of this connection or group.
     *
     * @param ofUser
     *     Sessions of this connection or group opened by this user.
     *
     * @throws GuacamoleException
     *     If one more would go over a limit.
     */
    void check(int total, int ofTarget, int ofUser) throws GuacamoleException {

        if (absolute > 0 && total >= absolute)
            throw new GuacamoleResourceConflictException("Cannot connect. Overall maximum connections reached.");

        boolean group = kind == Target.Kind.CONNECTION_GROUP;

        if (maxPerUser > 0 && ofUser >= maxPerUser)
            throw new GuacamoleClientTooManyException(group
                    ? "Cannot connect. Connection group already in use by this user."
                    : "Cannot connect. Connection already in use by this user.");

        if (max > 0 && ofTarget >= max)
            throw new GuacamoleResourceConflictException(group
                    ? "Cannot connect. This connection group is in use."
                    : "Cannot connect. This connection is in use.");

    }

    /**
     * Whether any limit applies, so the sessions open must be counted
     * before one more opens.
     */
    boolean any() {
        return absolute > 0 || max > 0 || maxPerUser > 0;
    }

}
