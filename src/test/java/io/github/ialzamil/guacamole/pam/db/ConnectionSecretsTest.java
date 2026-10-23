package io.github.ialzamil.guacamole.pam.db;

import static org.junit.Assert.assertEquals;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

import org.apache.guacamole.protocol.GuacamoleConfiguration;
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

    /**
     * A configuration loading its parameters only when asked for them, as
     * the database's do, counting how often.
     */
    private static final class LazyConfiguration extends GuacamoleConfiguration {

        private static final long serialVersionUID = 1L;

        int loads = 0;

        LazyConfiguration(Map<String, String> parameters) {
            setProtocol("ssh");
            super.setParameters(parameters);
        }

        @Override
        public Map<String, String> getParameters() {
            loads++;
            return super.getParameters();
        }

    }

    private static LazyConfiguration withToken() {
        Map<String, String> parameters = new HashMap<>();
        parameters.put("hostname", "server");
        parameters.put("password", ConnectionSecrets.token("password", 7));
        parameters.put("passphrase", ConnectionSecrets.token("passphrase", 8));
        return new LazyConfiguration(parameters);
    }

    @Test
    public void masksOnlyTheConnectionsOwnTokens() {
        GuacamoleConfiguration masked = ConnectionSecrets.masked(withToken(), 7);
        assertEquals(ConnectionSecrets.MASK, masked.getParameter("password"));
        assertEquals("${PAM_PASSPHRASE_8}", masked.getParameter("passphrase"));
        assertEquals("server", masked.getParameters().get("hostname"));
    }

    @Test
    public void readsNoParametersForTheProtocol() {
        LazyConfiguration configuration = withToken();
        assertEquals("ssh", ConnectionSecrets.masked(configuration, 7).getProtocol());
        assertEquals(0, configuration.loads);
    }

    @Test
    public void copiesMasked() {
        GuacamoleConfiguration copy = new GuacamoleConfiguration(ConnectionSecrets.masked(withToken(), 7));
        assertEquals(ConnectionSecrets.MASK, copy.getParameter("password"));
        assertEquals("server", copy.getParameter("hostname"));
        assertEquals("ssh", copy.getProtocol());
    }

}
