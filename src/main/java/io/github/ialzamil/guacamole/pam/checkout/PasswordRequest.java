package io.github.ialzamil.guacamole.pam.checkout;

import java.util.ArrayList;
import java.util.List;

import com.fasterxml.jackson.annotation.JsonInclude;

import io.github.ialzamil.guacamole.pam.approval.ApprovalRequest;

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
    private boolean passwordShown;
    private int approvalsRequired;
    private ApprovalRequest pending;
    private String lastStatus;
    private String lastDecidedBy;
    private String lastDecisionReason;
    private ApprovalRequest reservation;
    private int maxPeriods = 1;
    private int extensionMinutes;
    private int extensionsLeft;
    private ApprovalRequest extension;
    private String reservedBy;
    private Long reservedFrom;
    private Long reservedUntil;

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

    PasswordRequest withPasswordShown(boolean passwordShown) {
        this.passwordShown = passwordShown;
        return this;
    }

    /**
     * Whether the holder of a connection, not an Account, may see its
     * password.
     */
    public boolean isPasswordShown() {
        return passwordShown;
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
     * Adds the reservations of the connection: the user's next one, and, if
     * checkouts of the connection are exclusive, the next one of anyone else.
     *
     * @param reservations
     *     The connection's reservations, the earliest first.
     */
    PasswordRequest withReservations(List<ApprovalRequest> reservations, String currentUser) {
        for (ApprovalRequest request : reservations) {
            if (request.getUsername().equals(currentUser)) {
                if (reservation == null)
                    reservation = request;
            }
            else if (exclusive && reservedBy == null) {
                reservedBy = request.getUsername();
                reservedFrom = request.getStarts();
                reservedUntil = request.getEnds();
            }
        }
        return this;
    }

    /**
     * Adds what the connection allows of extensions, and of the user's own
     * checkout (or null) how many extensions are left and its latest request
     * to extend it (or null).
     */
    PasswordRequest withExtensions(int maxPeriods, int extensionMinutes, Checkout own, ApprovalRequest extension) {
        this.maxPeriods = maxPeriods;
        this.extensionMinutes = extensionMinutes;
        this.extensionsLeft = own == null ? 0 : Math.max(0, own.getMaxExtensions() - own.getExtensions());
        this.extension = extension;
        return this;
    }

    /**
     * How many times its time limit a request may ask for at once: 1 if the
     * connection allows no extensions.
     */
    public int getMaxPeriods() {
        return maxPeriods;
    }

    /**
     * By how many minutes an extension extends a checkout.
     */
    public int getExtensionMinutes() {
        return extensionMinutes;
    }

    /**
     * How many more times the user's own checkout may be extended.
     */
    public int getExtensionsLeft() {
        return extensionsLeft;
    }

    /**
     * The latest request to extend the user's own checkout, whatever became
     * of it, or null.
     */
    public ApprovalRequest getExtension() {
        return extension;
    }

    /**
     * The user's next approved request made ahead of time, not used yet,
     * or null. From its start until its end, the user checks out with it.
     */
    public ApprovalRequest getReservation() {
        return reservation;
    }

    /**
     * Who else has the next reservation of a connection checked out alone,
     * or null. No one else checks it out during that time, and checkouts
     * end when it starts.
     */
    public String getReservedBy() {
        return reservedBy;
    }

    public Long getReservedFrom() {
        return reservedFrom;
    }

    public Long getReservedUntil() {
        return reservedUntil;
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
