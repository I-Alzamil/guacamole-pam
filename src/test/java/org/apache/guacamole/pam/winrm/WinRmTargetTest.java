package org.apache.guacamole.pam.winrm;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.util.HashMap;
import java.util.Map;

import org.junit.Test;

public class WinRmTargetTest {

    private static Map<String, String> settings(String... pairs) {
        Map<String, String> values = new HashMap<>();
        values.put(WinRmTarget.HOSTNAME, "host.example");
        values.put(WinRmTarget.USERNAME, "pamtest");
        for (int i = 0; i < pairs.length; i += 2)
            values.put(pairs[i], pairs[i + 1]);
        return values;
    }

    private static void assertRefused(Map<String, String> values, String expected) {
        try {
            WinRmTarget.fromParameters(values);
            fail("Accepted " + values);
        }
        catch (IllegalArgumentException e) {
            assertTrue(e.getMessage(), e.getMessage().contains(expected));
        }
    }

    @Test
    public void defaults() {
        WinRmTarget target = WinRmTarget.fromParameters(settings());
        assertEquals(5986, target.getPort());
        assertEquals("pamtest", target.getAccount().getName());
        assertEquals("", target.getAccount().getDomain());
        assertNull(target.getAdmin());
        assertNull(target.getCertificate());
    }

    /**
     * Spaces around a password are part of it.
     */
    @Test
    public void keepsPasswordsAsTyped() {
        WinRmTarget target = WinRmTarget.fromParameters(settings(WinRmTarget.PASSWORD, " Pw with spaces ",
                WinRmTarget.ADMIN_USERNAME, "admin", WinRmTarget.ADMIN_PASSWORD, " Admin pw "));
        assertEquals(" Pw with spaces ", target.getPassword());
        assertEquals(" Admin pw ", target.getAdminPassword());
    }

    @Test
    public void localAccountForms() {
        assertEquals("pamtest", WinRmTarget.fromParameters(settings(WinRmTarget.USERNAME, ".\\pamtest"))
                .getAccount().getName());
        assertEquals("", WinRmTarget.fromParameters(settings(WinRmTarget.USERNAME, ".\\pamtest"))
                .getAccount().getDomain());
    }

    @Test
    public void refusesDomainAccounts() {
        assertRefused(settings(WinRmTarget.USERNAME, "CORP\\bob"), "Only local accounts");
        assertRefused(settings(WinRmTarget.USERNAME, "bob@corp.example"), "Only local accounts");
    }

    /**
     * The account name goes into an ADSI path, so characters Windows
     * refuses in names (which could change that path) are refused here.
     */
    @Test
    public void refusesInvalidAccountNames() {
        for (String name : new String[] { "a/b", "a,user", "a[1]", "a:b", "a;b", "a|b", "a=b", "a+b", "a*", "a?",
                "a<b", "a>b", "a\"b", "a\nb" })
            assertRefused(settings(WinRmTarget.USERNAME, name), "Invalid Windows account name");
    }

    @Test
    public void adminForms() {
        WinRmTarget.Credentials admin = WinRmTarget.fromParameters(settings(WinRmTarget.ADMIN_USERNAME,
                "TEST\\Administrator", WinRmTarget.ADMIN_PASSWORD, "x")).getAdmin();
        assertEquals("TEST", admin.getDomain());
        assertEquals("Administrator", admin.getName());

        admin = WinRmTarget.fromParameters(settings(WinRmTarget.ADMIN_USERNAME, "Administrator@test.lab",
                WinRmTarget.ADMIN_PASSWORD, "x")).getAdmin();
        assertEquals("test.lab", admin.getDomain());
        assertEquals("Administrator", admin.getName());
    }

    @Test
    public void refusesMalformedAdmins() {
        assertRefused(settings(WinRmTarget.ADMIN_USERNAME, "TEST\\\\Administrator", WinRmTarget.ADMIN_PASSWORD,
                "x"), "Invalid administrator name");
        assertRefused(settings(WinRmTarget.ADMIN_USERNAME, "Administrator"), "no password");
    }

    @Test
    public void requiresHostAndUser() {
        Map<String, String> values = settings();
        values.remove(WinRmTarget.HOSTNAME);
        assertRefused(values, "no hostname");
        values = settings();
        values.remove(WinRmTarget.USERNAME);
        assertRefused(values, "no username");
    }

    @Test
    public void ports() {
        assertEquals(15986, WinRmTarget.fromParameters(settings(WinRmTarget.PORT, "15986")).getPort());
        assertRefused(settings(WinRmTarget.PORT, "0"), "Invalid port");
        assertRefused(settings(WinRmTarget.PORT, "65536"), "Invalid port");
        assertRefused(settings(WinRmTarget.PORT, "https"), "Invalid port");
    }

    @Test
    public void normalizesFingerprints() {
        String expected = "B8:9F:D6:DE:0D:72:5C:59:6D:66:25:97:96:32:58:C8:E5:2F:93:C3:BB:4A:EF:EC:3B:D2:EA:5C:3E:BE:F4:53";
        assertEquals(expected, WinRmTarget.normalize(expected.toLowerCase()));
        assertEquals(expected, WinRmTarget.normalize(expected.replace(":", "")));
        assertEquals(expected, WinRmTarget.normalize("sha256 Fingerprint=" + expected));
        assertTrue(WinRmTarget.isFingerprint(expected));
        assertNull(WinRmTarget.normalize("  "));
        try {
            WinRmTarget.normalize("AB:CD");
            fail("Accepted a short fingerprint");
        }
        catch (IllegalArgumentException e) {
            assertTrue(e.getMessage().contains("SHA-256"));
        }
    }

}
