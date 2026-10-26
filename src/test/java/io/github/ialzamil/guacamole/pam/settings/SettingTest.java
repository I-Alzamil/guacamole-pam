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
        Setting setting = Setting.bool(Setting.Section.GENERAL, "t-bool", true);
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
        Setting setting = Setting.integer(Setting.Section.GENERAL, "t-int", 2, 0, 20);
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

    @Test
    public void readsTextWithinItsLength() throws GuacamoleClientException {
        Setting setting = Setting.string(Setting.Section.SYSLOG, "t-text", 5, value -> {
            if (value.contains(" "))
                throw new IllegalArgumentException("no spaces.");
        });
        assertEquals("abc", setting.normalize(" abc "));
        assertNull(setting.normalize(""));
        assertNull(setting.parse(null));
        refuses(setting, "abcdef", "\"t-text\" is limited to 5 characters.");
        refuses(setting, "a b", "\"t-text\": no spaces.");
        refuses(setting, "a\nb", "\"t-text\" must be a single line.");
        assertEquals("a\nb", Setting.text(Setting.Section.SYSLOG, "t-lines", 5, null).normalize("a\nb\n"));
    }

    @Test
    public void readsOneOfTheOptions() throws GuacamoleClientException {
        Setting setting = Setting.options(Setting.Section.SYSLOG, "t-choice", "tls", "tcp", "udp");
        assertEquals("tls", setting.getDefaultValue());
        assertEquals("udp", setting.normalize("udp"));
        assertEquals("tls", setting.parse("other"));
        refuses(setting, "UDP", "\"t-choice\" must be one of tls, tcp, udp.");
    }

    /**
     * Secrets are kept as given, spaces included, and read back as stored
     * (encrypted): PamSettings decrypts them.
     */
    @Test
    public void keepsSecretsAsGiven() throws GuacamoleClientException {
        Setting setting = Setting.secret(Setting.Section.EMAIL, "t-secret", 8);
        assertEquals(" pass ", setting.normalize(" pass "));
        assertEquals("$enc$", setting.parse("$enc$"));
        assertNull(setting.parse(""));
        refuses(setting, "123456789", "\"t-secret\" is limited to 8 characters.");
    }

    /**
     * A value stored by hand, or by another version, no longer valid: the
     * default applies, as for none.
     */
    @Test
    public void usesTheDefaultForInvalidStoredValues() {
        assertEquals(2, Setting.integer(Setting.Section.GENERAL, "t-int", 2, 0, 20).parse("99"));
        assertEquals(Boolean.TRUE, Setting.bool(Setting.Section.GENERAL, "t-bool", true).parse("maybe"));
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
