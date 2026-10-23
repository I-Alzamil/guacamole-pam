package io.github.ialzamil.guacamole.pam.ldap;

import static org.junit.Assert.assertEquals;

import org.junit.Test;

/**
 * Messages of the LDAP SDK, shown to administrators without the SDK's
 * version and build.
 */
public class LdapClientTest {

    @Test
    public void leavesOutTheSdkVersion() {
        assertEquals("IOException(LDAPException(resultCode=91 (connect error), errorMessage='An error occurred:"
                + " ConnectException(Connection refused)'))",
                LdapClient.withoutVersion("IOException(LDAPException(resultCode=91 (connect error),"
                        + " errorMessage='An error occurred: ConnectException(Connection refused)',"
                        + " ldapSDKVersion=7.0.5, revision=cab6672f8ac284805956006bb1496f73c5e3e746))"));
    }

    @Test
    public void keepsOtherMessages() {
        assertEquals("No such object", LdapClient.withoutVersion("No such object"));
    }

}
