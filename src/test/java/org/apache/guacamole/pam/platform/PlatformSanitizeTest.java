package org.apache.guacamole.pam.platform;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.util.HashMap;
import java.util.Map;

import org.apache.guacamole.GuacamoleClientException;
import org.apache.guacamole.pam.kerberos.KerberosTarget;
import org.apache.guacamole.pam.ldap.LdapTarget;
import org.junit.Test;

/**
 * A stored platform secret is only sent where it was entered for: changing
 * a field deciding where it goes needs it entered again.
 */
public class PlatformSanitizeTest {

    private static Platform ldap(String hostname, String password, String... settings) {
        Platform platform = new Platform();
        platform.setName("Directory");
        platform.setType("ldap");
        Map<String, String> values = new HashMap<>();
        values.put(LdapTarget.HOSTNAME, hostname);
        values.put(LdapTarget.ADMIN_DN, "cn=admin,dc=example,dc=org");
        values.put(LdapTarget.ADMIN_PASSWORD, password);
        for (int i = 0; i + 1 < settings.length; i += 2)
            values.put(settings[i], settings[i + 1]);
        platform.setSettings(values);
        return platform;
    }

    private static Platform stored(Platform platform) throws GuacamoleClientException {
        return PlatformRepository.sanitize(platform, null);
    }

    @Test
    public void keepsTheStoredPasswordWhenTheServerIsUnchanged() throws GuacamoleClientException {
        Platform stored = stored(ldap("dc.example.org", "Admin-Pw1!"));
        Platform saved = PlatformRepository.sanitize(ldap("dc.example.org", "",
                LdapTarget.ADMIN_DN, "cn=other,dc=example,dc=org"), stored);
        assertEquals("Admin-Pw1!", saved.getSecrets().get(LdapTarget.ADMIN_PASSWORD));
    }

    @Test
    public void refusesAnotherServerWithTheStoredPassword() throws GuacamoleClientException {
        Platform stored = stored(ldap("dc.example.org", "Admin-Pw1!"));
        try {
            PlatformRepository.sanitize(ldap("attacker.example.net", ""), stored);
            fail("The stored password would be sent to another server.");
        }
        catch (GuacamoleClientException e) {
            assertTrue(e.getMessage(), e.getMessage().contains(LdapTarget.HOSTNAME));
            assertTrue(e.getMessage(), e.getMessage().contains("enter it again"));
        }
    }

    @Test
    public void refusesWeakerEncryptionOrAnotherCertificateWithTheStoredPassword()
            throws GuacamoleClientException {
        Platform stored = stored(ldap("dc.example.org", "Admin-Pw1!"));
        for (String[] change : new String[][] {
                { LdapTarget.ENCRYPTION, LdapTarget.ENCRYPTION_NONE },
                { LdapTarget.CERTIFICATE, "AA:BB" },
                { LdapTarget.PORT, "1636" } }) {
            try {
                PlatformRepository.sanitize(ldap("dc.example.org", "", change), stored);
                fail("Changing " + change[0] + " kept the stored password.");
            }
            catch (GuacamoleClientException e) {
                assertTrue(e.getMessage(), e.getMessage().contains(change[0]));
            }
        }
    }

    @Test
    public void acceptsAnotherServerWithThePasswordEnteredAgain() throws GuacamoleClientException {
        Platform stored = stored(ldap("dc.example.org", "Admin-Pw1!"));
        Platform saved = PlatformRepository.sanitize(ldap("dc2.example.org", "Admin-Pw2!"), stored);
        assertEquals("Admin-Pw2!", saved.getSecrets().get(LdapTarget.ADMIN_PASSWORD));
        assertEquals("dc2.example.org", saved.getSettings().get(LdapTarget.HOSTNAME));
    }

    @Test
    public void refusesAnotherKdcWithTheStoredPassword() throws GuacamoleClientException {
        Platform kerberos = new Platform();
        kerberos.setName("Realm");
        kerberos.setType("kerberos");
        Map<String, String> values = new HashMap<>();
        values.put(KerberosTarget.REALM, "EXAMPLE.ORG");
        values.put(KerberosTarget.KDC, "kdc.example.org");
        values.put(KerberosTarget.ADMIN_PRINCIPAL, "admin/admin");
        values.put(KerberosTarget.ADMIN_PASSWORD, "Kdc-Pw1!");
        kerberos.setSettings(values);
        Platform stored = stored(kerberos);

        Map<String, String> moved = new HashMap<>(values);
        moved.put(KerberosTarget.KDC, "kdc.attacker.example.net");
        moved.put(KerberosTarget.ADMIN_PASSWORD, "");
        kerberos.setSettings(moved);
        try {
            PlatformRepository.sanitize(kerberos, stored);
            fail("The stored password would be sent to another KDC.");
        }
        catch (GuacamoleClientException e) {
            assertTrue(e.getMessage(), e.getMessage().contains(KerberosTarget.KDC));
        }
    }

}
