package io.github.ialzamil.guacamole.pam.ha;

import org.apache.guacamole.GuacamoleException;
import org.apache.guacamole.environment.LocalEnvironment;
import org.apache.guacamole.properties.BooleanGuacamoleProperty;
import org.apache.guacamole.properties.IntegerGuacamoleProperty;
import org.apache.guacamole.properties.StringGuacamoleProperty;
import org.slf4j.LoggerFactory;

/**
 * Properties of guacamole.properties read by name, such as those of
 * Guacamole's database authentication ("postgresql-hostname", ...), which
 * this extension reuses rather than defining its own.
 */
final class Settings {

    /**
     * Whether this server is one of several sharing their database
     * ("pam-ha"). Off by default: the HA module then starts nothing.
     */
    private static final BooleanGuacamoleProperty ENABLED = bool("pam-ha");

    private static Boolean enabled;

    private Settings() {
    }

    /**
     * Whether the HA module runs on this server, as guacamole.properties
     * said when first asked.
     */
    static synchronized boolean isEnabled() {
        if (enabled == null) {
            try {
                enabled = LocalEnvironment.getInstance().getProperty(ENABLED, false);
            }
            catch (GuacamoleException e) {
                LoggerFactory.getLogger(Settings.class).error("The HA module is off: {}", e.getMessage());
                enabled = false;
            }
        }
        return enabled;
    }

    static StringGuacamoleProperty string(String name) {
        return new StringGuacamoleProperty() {
            @Override
            public String getName() {
                return name;
            }
        };
    }

    static IntegerGuacamoleProperty integer(String name) {
        return new IntegerGuacamoleProperty() {
            @Override
            public String getName() {
                return name;
            }
        };
    }

    static BooleanGuacamoleProperty bool(String name) {
        return new BooleanGuacamoleProperty() {
            @Override
            public String getName() {
                return name;
            }
        };
    }

}
