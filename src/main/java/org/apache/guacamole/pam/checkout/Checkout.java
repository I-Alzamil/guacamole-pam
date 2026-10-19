package org.apache.guacamole.pam.checkout;

import java.util.List;

import com.fasterxml.jackson.annotation.JsonInclude;

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

    private int id;
    private String connectionIdentifier;
    private String connectionName;
    private String username;
    private String reason;
    private long checkedOut;
    private long expires;
    private Long released;
    private String releaseReason;
    private String releasedBy;
    private int revealCount;
    private boolean exclusive;
    private List<String> approvedBy;

    public int getId() {
        return id;
    }

    void setId(int id) {
        this.id = id;
    }

    public String getConnectionIdentifier() {
        return connectionIdentifier;
    }

    void setConnectionIdentifier(String connectionIdentifier) {
        this.connectionIdentifier = connectionIdentifier;
    }

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
     * RELEASED, EXPIRED or REVOKED, or null while active.
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

}
