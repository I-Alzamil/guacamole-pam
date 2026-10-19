package org.apache.guacamole.pam.checkout;

/**
 * Result of requesting a password: the password itself, or, when the
 * account needs approval, the request now awaiting it.
 */
public final class RequestOutcome {

    private final PasswordGrant grant;

    private final PasswordRequest pending;

    private RequestOutcome(PasswordGrant grant, PasswordRequest pending) {
        this.grant = grant;
        this.pending = pending;
    }

    static RequestOutcome granted(PasswordGrant grant) {
        return new RequestOutcome(grant, null);
    }

    static RequestOutcome pending(PasswordRequest request) {
        return new RequestOutcome(null, request);
    }

    /**
     * The password, or null if approval is pending.
     */
    public PasswordGrant getGrant() {
        return grant;
    }

    /**
     * The request awaiting approval, or null if the password was granted.
     */
    public PasswordRequest getPending() {
        return pending;
    }

}
