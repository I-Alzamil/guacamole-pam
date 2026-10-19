package org.apache.guacamole.pam.ldap;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.util.HashMap;
import java.util.Map;

import org.junit.Test;

public class LdapTargetTest {

    private static Map<String, String> settings(String... pairs) {
        Map<String, String> values = new HashMap<>();
        values.put(LdapTarget.HOSTNAME, "ldap.example.org");
        values.put(LdapTarget.USER_DN, "uid=alice,ou=people,dc=example,dc=org");
        for (int i = 0; i < pairs.length; i += 2)
            values.put(pairs[i], pairs[i + 1]);
        return values;
    }

    private static void assertRefused(Map<String, String> values, String expected) {
        try {
            LdapTarget.fromParameters(values);
            fail("Accepted " + values);
        }
        catch (IllegalArgumentException e) {
            assertTrue(e.getMessage(), e.getMessage().contains(expected));
        }
    }

    @Test
    public void defaultsToLdaps() {
        LdapTarget target = LdapTarget.fromParameters(settings());
        assertEquals(LdapTarget.Encryption.LDAPS, target.getEncryption());
        assertEquals(636, target.getPort());
        assertNull(target.getAdminDn());
    }

    @Test
    public void startTlsUsesPort389() {
        LdapTarget target = LdapTarget.fromParameters(settings(LdapTarget.ENCRYPTION, LdapTarget.ENCRYPTION_STARTTLS));
        assertEquals(LdapTarget.Encryption.STARTTLS, target.getEncryption());
        assertEquals(389, target.getPort());
    }

    /**
     * A rotation account can usually change any password in the directory,
     * so its credentials never travel unencrypted.
     */
    @Test
    public void rotationAccountRequiresEncryption() {
        assertRefused(settings(LdapTarget.ENCRYPTION, LdapTarget.ENCRYPTION_NONE,
                LdapTarget.ADMIN_DN, "cn=admin,dc=example,dc=org", LdapTarget.ADMIN_PASSWORD, "x"), "must be encrypted");
        assertRefused(settings(LdapTarget.ADMIN_DN, "cn=admin,dc=example,dc=org"), "no password");
    }

    @Test
    public void activeDirectoryRequiresEncryption() {
        assertRefused(settings(LdapTarget.ENCRYPTION, LdapTarget.ENCRYPTION_NONE,
                LdapTarget.DIRECTORY_TYPE, LdapTarget.DIRECTORY_ACTIVE_DIRECTORY), "LDAPS or StartTLS");
    }

    @Test
    public void accountsMayChangeTheirOwnPasswordUnencrypted() {
        assertEquals(LdapTarget.Encryption.NONE, LdapTarget.fromParameters(
                settings(LdapTarget.ENCRYPTION, LdapTarget.ENCRYPTION_NONE)).getEncryption());
    }

    @Test
    public void requiresServerAndDn() {
        Map<String, String> values = settings();
        values.remove(LdapTarget.HOSTNAME);
        assertRefused(values, "hostname");
        values = settings();
        values.remove(LdapTarget.USER_DN);
        assertRefused(values, "DN");
        assertRefused(settings(LdapTarget.PORT, "ldaps"), "Invalid LDAP port");
    }

}
