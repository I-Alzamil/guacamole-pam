package io.github.ialzamil.guacamole.pam.ha;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

import org.apache.guacamole.GuacamoleException;
import org.apache.guacamole.net.auth.AbstractUser;
import org.apache.guacamole.net.auth.AbstractUserContext;
import org.apache.guacamole.net.auth.AuthenticationProvider;
import org.apache.guacamole.net.auth.User;
import org.apache.guacamole.net.auth.UserContext;
import org.junit.Test;

/**
 * Which database accounts may be used now, as their account (Guacamole's
 * ModeledUser) tells.
 */
public class AccountsTest {

    /**
     * An account as Guacamole's database authentication gives it.
     */
    public static class Account extends AbstractUser {

        private final boolean disabled;
        private final boolean valid;
        private final boolean accessible;

        Account(boolean disabled, boolean valid, boolean accessible) {
            this.disabled = disabled;
            this.valid = valid;
            this.accessible = accessible;
        }

        public boolean isSkeleton() {
            return false;
        }

        public boolean isDisabled() {
            return disabled;
        }

        public boolean isAccountValid() {
            return valid;
        }

        public boolean isAccountAccessible() {
            return accessible;
        }

    }

    private static UserContext of(User user) {
        return new AbstractUserContext() {

            @Override
            public User self() {
                return user;
            }

            @Override
            public AuthenticationProvider getAuthenticationProvider() {
                return null;
            }

        };
    }

    private static String refusal(User user) throws GuacamoleException {
        return Accounts.refusal(of(user), null, "someone");
    }

    @Test
    public void acceptsAccountsThatMayBeUsed() throws GuacamoleException {
        assertNull(refusal(new Account(false, true, true)));
    }

    @Test
    public void refusesAccountsThatMayNotBeUsedNow() throws GuacamoleException {
        assertEquals("the account is disabled", refusal(new Account(true, true, true)));
        assertEquals("the account is no longer valid", refusal(new Account(false, false, true)));
        assertEquals("the account may not be used at this time", refusal(new Account(false, true, false)));
    }

    @Test
    public void refusesAccountsItCannotCheck() throws GuacamoleException {
        assertTrue(refusal(new AbstractUser() { }).startsWith("the account could not be checked"));
    }

}
