package org.apache.guacamole.pam.checkout;

import java.util.ArrayList;
import java.util.List;

import com.fasterxml.jackson.annotation.JsonInclude;

import org.apache.guacamole.pam.approval.ApprovalRequest;

/**
 * A connection as shown to a user who may request it (an Account's password,
 * or access to any other connection): what it is, and who currently holds
 * it. Contains no secrets, and nothing but the name for non-Accounts.
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
public class PasswordRequest {

    private final String identifier;
    private final String name;
    private final String accountName;
    private final String accountDn;
    private final String url;
    private final String notes;
    private final boolean managed;
    private final boolean exclusive;
    private final int durationMinutes;
    private final List<String> holders = new ArrayList<>();
    private final boolean heldExclusively;
    private final boolean mine;
    private final Long expires;
    private boolean account;
    private boolean bypass;
    private boolean noRequest;
    private int approvalsRequired;
    private ApprovalRequest pending;
    private String lastStatus;
    private String lastDecidedBy;
    private String lastDecisionReason;

    PasswordRequest(String identifier, String name, String accountName, String accountDn, String url,
            String notes, boolean managed, boolean exclusive, int durationMinutes, List<Checkout> active,
            String currentUser) {

        this.identifier = identifier;
        this.name = name;
        this.accountName = accountName;
        this.accountDn = accountDn;
        this.url = url;
        this.notes = notes;
        this.managed = managed;
        this.exclusive = exclusive;
        this.durationMinutes = durationMinutes;

        boolean anyExclusive = false;
        Checkout own = null;
        for (Checkout checkout : active) {
            anyExclusive |= checkout.isExclusive();
            if (checkout.getUsername().equals(currentUser))
                own = checkout;
            else
                holders.add(checkout.getUsername());
        }

        this.heldExclusively = anyExclusive;
        this.mine = own != null;

        // The user's own expiry, or when the exclusive holder's ends
        Long until = own == null ? null : own.getExpires();
        if (until == null && anyExclusive)
            until = active.get(0).getExpires();
        this.expires = until;

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

    /**
     * DN of a directory account, or null.
     */
    public String getAccountDn() {
        return accountDn;
    }

    public String getUrl() {
        return url;
    }

    public String getNotes() {
        return notes;
    }

    /**
     * Whether the password is rotated by this extension.
     */
    public boolean isManaged() {
        return managed;
    }

    /**
     * Whether a new checkout would exclude every other holder.
     */
    public boolean isExclusive() {
        return exclusive;
    }

    /**
     * How long a checkout of this password lasts.
     */
    public int getDurationMinutes() {
        return durationMinutes;
    }

    /**
     * Other users currently holding the password.
     */
    public List<String> getHolders() {
        return holders;
    }

    /**
     * Whether another user holds the password exclusively, so it cannot be
     * requested now.
     */
    public boolean isHeldExclusively() {
        return heldExclusively && !mine;
    }

    /**
     * Whether the current user holds the password.
     */
    public boolean isMine() {
        return mine;
    }

    /**
     * Sets whether this is an Account (checked out for its password) rather
     * than a connection checked out for access.
     */
    PasswordRequest withAccount(boolean account) {
        this.account = account;
        return this;
    }

    public boolean isAccount() {
        return account;
    }

    /**
     * Marks the current user as an administrator who bypasses requests
     * (with "pam-admin-bypass-requests"): they connect without a request.
     */
    PasswordRequest withBypass(boolean bypass) {
        this.bypass = bypass;
        return this;
    }

    public boolean isBypass() {
        return bypass;
    }

    PasswordRequest withNoRequest(boolean noRequest) {
        this.noRequest = noRequest;
        return this;
    }

    /**
     * Whether the Account may be checked out without a request (no reason
     * asked), its password then being shown as soon as it is opened.
     */
    public boolean isNoRequest() {
        return noRequest;
    }

    /**
     * Adds the approval state of the request for the current user.
     *
     * @param latest
     *     The user's most recent request, used to report a denial or expiry
     *     the user has not acted on since.
     */
    PasswordRequest withApproval(int approvalsRequired, ApprovalRequest pending, ApprovalRequest latest) {
        this.approvalsRequired = approvalsRequired;
        this.pending = pending;
        if (pending == null && !mine && latest != null
                && !ApprovalRequest.APPROVED.equals(latest.getStatus())
                && !ApprovalRequest.CANCELLED.equals(latest.getStatus())) {
            this.lastStatus = latest.getStatus();
            this.lastDecidedBy = latest.getDecidedBy();
            this.lastDecisionReason = latest.getDecisionReason();
        }
        return this;
    }

    /**
     * How many distinct approvers must approve a request, 0 if none.
     */
    public int getApprovalsRequired() {
        return approvalsRequired;
    }

    /**
     * The user's request awaiting approval, or null.
     */
    public ApprovalRequest getPending() {
        return pending;
    }

    /**
     * DENIED or EXPIRED if that is how the user's last request ended, so the
     * user can be told; otherwise null.
     */
    public String getLastStatus() {
        return lastStatus;
    }

    public String getLastDecidedBy() {
        return lastDecidedBy;
    }

    /**
     * Why the user's last request was denied, or null.
     */
    public String getLastDecisionReason() {
        return lastDecisionReason;
    }

    /**
     * When the user's own checkout ends, or the exclusive holder's.
     */
    public Long getExpires() {
        return expires;
    }

}
