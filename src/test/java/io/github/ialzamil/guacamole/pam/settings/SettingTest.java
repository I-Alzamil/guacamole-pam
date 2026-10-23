package io.github.ialzamil.guacamole.pam.settings;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.fail;

import org.apache.guacamole.GuacamoleClientException;
import org.junit.Test;

/**
 * Values of the shared settings, as given by the settings page (JSON) or
 * imported from guacamole.properties (text), and as read back. The live
 * suites test storing them.
 */
public class SettingTest {

    @Test
    public void readsYesNo() throws GuacamoleClientException {
        Setting setting = Setting.bool("t-bool", true);
        assertEquals("false", setting.normalize(false));
        assertEquals("true", setting.normalize(" TRUE "));
        assertNull(setting.normalize(null));
        assertNull(setting.normalize(" "));
        assertEquals(Boolean.FALSE, setting.parse("false"));
        assertEquals(Boolean.TRUE, setting.parse(null));
        refuses(setting, "yes", "\"t-bool\" must be true or false.");
        refuses(setting, 1, "\"t-bool\" must be true or false.");
    }

    @Test
    public void readsNumbersWithinBounds() throws GuacamoleClientException {
        Setting setting = Setting.integer("t-int", 2, 0, 20);
        assertEquals("0", setting.normalize(0));
        assertEquals("20", setting.normalize("20"));
        assertEquals("7", setting.normalize(" 07 "));
        assertEquals(7, setting.parse("7"));
        assertEquals(2, setting.parse(null));
        refuses(setting, -1, "\"t-int\" must be from 0 to 20.");
        refuses(setting, "21", "\"t-int\" must be from 0 to 20.");
        refuses(setting, "2.5", "\"t-int\" must be a whole number.");
        refuses(setting, true, "\"t-int\" must be a whole number.");
    }

    /**
     * A value stored by hand, or by another version, no longer valid: the
     * default applies, as for none.
     */
    @Test
    public void usesTheDefaultForInvalidStoredValues() {
        assertEquals(2, Setting.integer("t-int", 2, 0, 20).parse("99"));
        assertEquals(Boolean.TRUE, Setting.bool("t-bool", true).parse("maybe"));
    }

    @Test
    public void namesTheMovedProperties() {
        assertEquals("pam-admin-bypass-requests", PamSettings.ADMIN_BYPASS_REQUESTS.getName());
        assertEquals("pam-extensions-enabled", PamSettings.EXTENSIONS_ENABLED.getName());
        assertEquals("pam-max-extensions", PamSettings.MAX_EXTENSIONS.getName());
        assertEquals(Integer.valueOf(20), PamSettings.MAX_EXTENSIONS.getMaximum());
    }

    private static void refuses(Setting setting, Object value, String message) {
        try {
            setting.normalize(value);
            fail("\"" + value + "\" is accepted.");
        }
        catch (GuacamoleClientException e) {
            assertEquals(message, e.getMessage());
        }
    }

}
