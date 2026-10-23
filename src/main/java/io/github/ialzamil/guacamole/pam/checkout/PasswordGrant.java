package io.github.ialzamil.guacamole.pam.checkout;

import com.fasterxml.jackson.annotation.JsonInclude;

/**
 * A checkout handed to its holder: with the password for an Account, or for
 * a connection showing its password when asked to, which is only ever
 * returned in a response marked as not cacheable and never logged; without
 * any secret for access to another connection.
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
public class PasswordGrant {

    private final int checkoutId;
    private final String identifier;
    private final String name;
    private final String accountName;
    private final String accountDn;
    private final String password;
    private final long expires;

    PasswordGrant(Checkout checkout, String accountName, String accountDn, String password) {
        this.checkoutId = checkout.getId();
        this.identifier = checkout.getConnectionIdentifier();
        this.name = checkout.getConnectionName();
        this.accountName = accountName;
        this.accountDn = accountDn;
        this.password = password;
        this.expires = checkout.getExpires();
    }

    public int getCheckoutId() {
        return checkoutId;
    }

    public String getIdentifier() {
        return identifier;
    }

    public String getName() {
        return name;
    }

    public String getAccountName() {
        return accountName;
    }

    public String getAccountDn() {
        return accountDn;
    }

    public String getPassword() {
        return password;
    }

    public long getExpires() {
        return expires;
    }

}
