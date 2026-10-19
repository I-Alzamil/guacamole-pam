package org.apache.guacamole.pam.kerberos;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.util.HashMap;
import java.util.Map;

import org.junit.Test;

public class KerberosTargetTest {

    private static Map<String, String> settings(String... pairs) {
        Map<String, String> values = new HashMap<>();
        values.put(KerberosTarget.REALM, "EXAMPLE.ORG");
        values.put(KerberosTarget.KDC, "kdc.example.org");
        values.put(KerberosTarget.PRINCIPAL, "alice");
        for (int i = 0; i < pairs.length; i += 2)
            values.put(pairs[i], pairs[i + 1]);
        return values;
    }

    private static void assertRefused(Map<String, String> values, String expected) {
        try {
            KerberosTarget.fromParameters(values);
            fail("Accepted " + values);
        }
        catch (IllegalArgumentException e) {
            assertTrue(e.getMessage(), e.getMessage().contains(expected));
        }
    }

    @Test
    public void defaults() {
        KerberosTarget target = KerberosTarget.fromParameters(settings());
        assertEquals("alice@EXAMPLE.ORG", target.getPrincipal());
        assertEquals(88, target.getKdcPort());
        assertEquals("kdc.example.org", target.getKpasswdServer());
        assertEquals(464, target.getKpasswdPort());
        assertNull(target.getAdminPrincipal());
    }

    @Test
    public void keepsGivenRealmsAndQualifiesAdmins() {
        assertEquals("alice@OTHER.ORG", KerberosTarget.fromParameters(
                settings(KerberosTarget.PRINCIPAL, "alice@OTHER.ORG")).getPrincipal());
        assertEquals("admin/admin@EXAMPLE.ORG", KerberosTarget.fromParameters(settings(
                KerberosTarget.ADMIN_PRINCIPAL, "admin/admin", KerberosTarget.ADMIN_PASSWORD, "x")).getAdminPrincipal());
    }

    @Test
    public void separateKpasswdServer() {
        KerberosTarget target = KerberosTarget.fromParameters(settings(KerberosTarget.KPASSWD_SERVER, "kpw.example.org",
                KerberosTarget.KPASSWD_PORT, "1464", KerberosTarget.KDC_PORT, "1088"));
        assertEquals("kpw.example.org", target.getKpasswdServer());
        assertEquals(1464, target.getKpasswdPort());
        assertEquals(1088, target.getKdcPort());
    }

    @Test
    public void refusesIncompleteSettings() {
        Map<String, String> values = settings();
        values.remove(KerberosTarget.REALM);
        assertRefused(values, "no Kerberos realm");
        values = settings();
        values.remove(KerberosTarget.KDC);
        assertRefused(values, "no KDC");
        values = settings();
        values.remove(KerberosTarget.PRINCIPAL);
        assertRefused(values, "no Kerberos principal");
        assertRefused(settings(KerberosTarget.ADMIN_PRINCIPAL, "admin/admin"), "no password");
        assertRefused(settings(KerberosTarget.KDC_PORT, "99999"), "Invalid port");
    }

    @Test
    public void withPasswordKeepsEverythingElse() {
        KerberosTarget target = KerberosTarget.fromParameters(settings(KerberosTarget.PASSWORD, "old"));
        KerberosTarget changed = target.withPassword("new");
        assertEquals("new", changed.getPassword());
        assertEquals("old", target.getPassword());
        assertEquals(target.getPrincipal(), changed.getPrincipal());
    }

}
