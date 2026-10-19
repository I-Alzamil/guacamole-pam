package org.apache.guacamole.pam.db;

import static org.junit.Assert.assertEquals;

import java.util.Collections;

import org.apache.guacamole.token.TokenFilter;
import org.junit.Test;

/**
 * Tokens standing for kept values, checked with Guacamole's own token
 * filter: a name it does not accept would reach guacd as the value.
 */
public class ConnectionSecretsTest {

    @Test
    public void namesParameterAndConnection() {
        assertEquals("PAM_SFTP_PRIVATE_KEY_17", ConnectionSecrets.tokenName("sftp-private-key", 17));
        assertEquals("${PAM_PASSWORD_4}", ConnectionSecrets.token("password", 4));
    }

    @Test
    public void everyTokenIsReplacedByGuacamole() {
        for (String parameter : ConnectionSecrets.SENSITIVE) {
            TokenFilter filter = new TokenFilter(Collections.singletonMap(
                    ConnectionSecrets.tokenName(parameter, 123), "secret $ value"));
            assertEquals(parameter, "secret $ value", filter.filter(ConnectionSecrets.token(parameter, 123)));
        }
    }

    @Test
    public void otherConnectionsTokensAreNotReplaced() {
        TokenFilter filter = new TokenFilter(Collections.singletonMap(ConnectionSecrets.tokenName("password", 1),
                "secret"));
        assertEquals("${PAM_PASSWORD_12}", filter.filter(ConnectionSecrets.token("password", 12)));
    }

}
