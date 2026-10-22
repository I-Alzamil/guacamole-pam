package org.apache.guacamole.pam.checkout;

import java.util.ArrayList;
import java.util.List;

import com.fasterxml.jackson.annotation.JsonInclude;

import org.apache.guacamole.pam.approval.ApprovalRequest;

/**
 * A checkout: one user holding an Account's password, or access to a
 * connection, for a limited time. Times are milliseconds since the epoch.
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
public class Checkout {

    /**
     * Released by its holder.
     */
    public static final String RELEASED = "RELEASED";

    /**
     * Released automatically when its time limit passed.
     */
    public static final String EXPIRED = "EXPIRED";

    /**
     * Released by an administrator.
     */
    public static final String REVOKED = "REVOKED";

    /**
     * Withdrawn right after creation because a rotation was running. The
     * password was never shown.
     */
    public static final String CANCELLED = "CANCELLED";

    /**
     * Ended because its connection was deleted.
     */
    public static final String DELETED = "DELETED";

    private int id;
    private String connectionIdentifier;
    private String connectionName;
    private String username;
    private String remoteHost;
    private String reason;
    private long checkedOut;
    private long expires;
    private Long released;
    private String releaseReason;
    private String releasedBy;
    private int revealCount;
    private boolean exclusive;
    private List<String> approvedBy;
    private List<ApprovalRequest.Approval> approvals;
    private String releasedHost;
    private int extensions;
    private int maxExtensions;
    private final List<Extension> extensionHistory = new ArrayList<>();

    /**
     * An extension granted to the checkout: when it was requested and
     * granted, by how many minutes, why, from where, and who approved it
     * (nobody, where the connection needs no approval).
     */
    @JsonInclude(JsonInclude.Include.NON_NULL)
    public static class Extension {

        private final long requested;
        private final Long granted;
        private final int minutes;
        private final String reason;
        private final String remoteHost;
        private final List<ApprovalRequest.Approval> approvals = new ArrayList<>();

        Extension(long requested, Long granted, int minutes, String reason, String remoteHost) {
            this.requested = requested;
            this.granted = granted;
            this.minutes = minutes;
            this.reason = reason;
            this.remoteHost = remoteHost;
        }

        public long getRequested() {
            return requested;
        }

        public Long getGranted() {
            return granted;
        }

        public int getMinutes() {
            return minutes;
        }

        public String getReason() {
            return reason;
        }

        public String getRemoteHost() {
            return remoteHost;
        }

        public List<ApprovalRequest.Approval> getApprovals() {
            return approvals;
        }

    }

    public int getId() {
        return id;
    }

    void setId(int id) {
        this.id = id;
    }

    /**
     * The connection's identifier, or null once it was deleted.
     */
    public String getConnectionIdentifier() {
        return connectionIdentifier;
    }

    void setConnectionIdentifier(String connectionIdentifier) {
        this.connectionIdentifier = connectionIdentifier;
    }

    /**
     * The connection's name, or the one it had when it was deleted.
     */
    public String getConnectionName() {
        return connectionName;
    }

    void setConnectionName(String connectionName) {
        this.connectionName = connectionName;
    }

    /**
     * The Guacamole user holding the checkout.
     */
    public String getUsername() {
        return username;
    }

    void setUsername(String username) {
        this.username = username;
    }

    /**
     * Where the user requested the checkout from: the address they logged
     * in from, as Guacamole's connection history shows it. Null if unknown.
     */
    public String getRemoteHost() {
        return remoteHost;
    }

    void setRemoteHost(String remoteHost) {
        this.remoteHost = remoteHost;
    }

    public String getReason() {
        return reason;
    }

    void setReason(String reason) {
        this.reason = reason;
    }

    public long getCheckedOut() {
        return checkedOut;
    }

    void setCheckedOut(long checkedOut) {
        this.checkedOut = checkedOut;
    }

    public long getExpires() {
        return expires;
    }

    void setExpires(long expires) {
        this.expires = expires;
    }

    public Long getReleased() {
        return released;
    }

    void setReleased(Long released) {
        this.released = released;
    }

    /**
     * RELEASED, EXPIRED, REVOKED, CANCELLED or DELETED, or null while
     * active.
     */
    public String getReleaseReason() {
        return releaseReason;
    }

    void setReleaseReason(String releaseReason) {
        this.releaseReason = releaseReason;
    }

    public String getReleasedBy() {
        return releasedBy;
    }

    void setReleasedBy(String releasedBy) {
        this.releasedBy = releasedBy;
    }

    /**
     * How many times the password was shown during this checkout.
     */
    public int getRevealCount() {
        return revealCount;
    }

    void setRevealCount(int revealCount) {
        this.revealCount = revealCount;
    }

    /**
     * Whether this checkout excluded every other holder.
     */
    public boolean isExclusive() {
        return exclusive;
    }

    void setExclusive(boolean exclusive) {
        this.exclusive = exclusive;
    }

    /**
     * Who approved the request that started this checkout, or null if it
     * needed no approval.
     */
    public List<String> getApprovedBy() {
        return approvedBy;
    }

    void setApprovedBy(List<String> approvedBy) {
        this.approvedBy = approvedBy;
    }

    /**
     * The approvals of the request that started the checkout, with when and
     * from where each was given, or null if none started it.
     */
    public List<ApprovalRequest.Approval> getApprovals() {
        return approvals;
    }

    void setApprovals(List<ApprovalRequest.Approval> approvals) {
        this.approvals = approvals;
    }

    /**
     * How many times the checkout was extended.
     */
    public int getExtensions() {
        return extensions;
    }

    void setExtensions(int extensions) {
        this.extensions = extensions;
    }

    /**
     * How many times the checkout may be extended in all.
     */
    public int getMaxExtensions() {
        return maxExtensions;
    }

    void setMaxExtensions(int maxExtensions) {
        this.maxExtensions = maxExtensions;
    }

    /**
     * The extensions granted, in order.
     */
    public List<Extension> getExtensionHistory() {
        return extensionHistory;
    }

    /**
     * Where who released or revoked the checkout did so from, or null.
     */
    public String getReleasedHost() {
        return releasedHost;
    }

    void setReleasedHost(String releasedHost) {
        this.releasedHost = releasedHost;
    }

}
