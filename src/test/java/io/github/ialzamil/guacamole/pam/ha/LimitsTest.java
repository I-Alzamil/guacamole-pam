package io.github.ialzamil.guacamole.pam.ha;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

import org.apache.guacamole.GuacamoleClientTooManyException;
import org.apache.guacamole.GuacamoleException;
import org.apache.guacamole.GuacamoleResourceConflictException;
import org.junit.Test;

/**
 * The limits of Guacamole's database authentication, as it reads and
 * applies them.
 */
public class LimitsTest {

    private static final Limits.Defaults NONE = new Limits.Defaults(0, 0, 0, 0, 1);

    private static Map<String, String> attributes(String max, String perUser) {
        Map<String, String> attributes = new HashMap<>();
        attributes.put(Limits.MAX_CONNECTIONS, max);
        attributes.put(Limits.MAX_CONNECTIONS_PER_USER, perUser);
        return attributes;
    }

    private static void assertRefused(Limits limits, int total, int ofTarget, int ofUser,
            Class<? extends GuacamoleException> type, String message) {
        try {
            limits.check(total, ofTarget, ofUser);
            fail("Not refused: " + message);
        }
        catch (GuacamoleException e) {
            assertEquals(type, e.getClass());
            assertEquals(message, e.getMessage());
        }
    }

    @Test
    public void readsGuacamolesDefaults() throws GuacamoleException {
        Limits.Defaults defaults = Limits.Defaults.fromEnvironment(DatabaseType.MYSQL, new TestEnvironment());
        Limits connection = Limits.of(Target.Kind.CONNECTION, Collections.<String, String>emptyMap(), defaults);
        Limits group = Limits.of(Target.Kind.CONNECTION_GROUP, Collections.<String, String>emptyMap(), defaults);
        assertFalse("no limit on connections by default", connection.any());
        assertTrue("one session per user through a balancing group by default", group.any());
        assertRefused(group, 1, 1, 1, GuacamoleClientTooManyException.class,
                "Cannot connect. Connection group already in use by this user.");
    }

    @Test
    public void readsTheDefaultsOfItsDatabase() throws GuacamoleException {
        Limits.Defaults defaults = Limits.Defaults.fromEnvironment(DatabaseType.SQLSERVER, new TestEnvironment(
                "sqlserver-default-max-connections", "2", "postgresql-default-max-connections", "1"));
        Limits limits = Limits.of(Target.Kind.CONNECTION, null, defaults);
        limits.check(5, 1, 0);
        assertRefused(limits, 5, 2, 0, GuacamoleResourceConflictException.class,
                "Cannot connect. This connection is in use.");
    }

    @Test
    public void attributesOverrideDefaults() throws GuacamoleException {
        Limits.Defaults defaults = new Limits.Defaults(0, 1, 1, 0, 1);
        Limits unlimited = Limits.of(Target.Kind.CONNECTION, attributes("0", "0"), defaults);
        unlimited.check(100, 100, 100);
        Limits unset = Limits.of(Target.Kind.CONNECTION, attributes("", " "), defaults);
        assertRefused(unset, 1, 1, 0, GuacamoleResourceConflictException.class,
                "Cannot connect. This connection is in use.");
        Limits invalid = Limits.of(Target.Kind.CONNECTION, attributes("many", null), defaults);
        assertRefused(invalid, 1, 1, 0, GuacamoleResourceConflictException.class,
                "Cannot connect. This connection is in use.");
    }

    @Test
    public void refusesAsGuacamoleDoes() throws GuacamoleException {

        Limits connection = Limits.of(Target.Kind.CONNECTION, attributes("3", "1"), new Limits.Defaults(10, 0, 0,
                0, 1));
        connection.check(9, 2, 0);
        assertRefused(connection, 10, 0, 0, GuacamoleResourceConflictException.class,
                "Cannot connect. Overall maximum connections reached.");
        assertRefused(connection, 5, 3, 1, GuacamoleClientTooManyException.class,
                "Cannot connect. Connection already in use by this user.");
        assertRefused(connection, 5, 3, 0, GuacamoleResourceConflictException.class,
                "Cannot connect. This connection is in use.");

        Limits group = Limits.of(Target.Kind.CONNECTION_GROUP, attributes("2", "2"), NONE);
        group.check(1, 1, 1);
        assertRefused(group, 2, 2, 0, GuacamoleResourceConflictException.class,
                "Cannot connect. This connection group is in use.");

    }

}
