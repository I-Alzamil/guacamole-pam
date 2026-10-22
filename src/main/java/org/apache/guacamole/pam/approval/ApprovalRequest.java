package org.apache.guacamole.pam.approval;

import java.util.ArrayList;
import java.util.List;

import com.fasterxml.jackson.annotation.JsonInclude;

/**
 * A request awaiting, or having received, approval: for access from its
 * final approval on, or, made ahead of time, for a given time (a
 * reservation, once approved, until its holder uses it), or to extend a
 * checkout. Times are
 * milliseconds since the epoch.
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
public class ApprovalRequest {

    public static final String PENDING = "PENDING";
    public static final String APPROVED = "APPROVED";
    public static final String DENIED = "DENIED";
    public static final String CANCELLED = "CANCELLED";
    public static final String EXPIRED = "EXPIRED";

    private int id;
    private String connectionIdentifier;
    private String connectionName;
    private String accountName;
    private String username;
    private String remoteHost;
    private String reason;
    private long requested;
    private int approvalsRequired;
    private String status;
    private Long decided;
    private String decidedBy;
    private String decisionReason;
    private Integer checkoutId;
    private Long starts;
    private Long ends;
    private int periods = 1;
    private Integer extendsCheckout;
    private Integer extensionMinutes;
    private String decidedHost;
    private List<String> approvers = new ArrayList<>();
    private List<Approval> approvals = new ArrayList<>();

    /**
     * An approval given to the request: by whom, when (milliseconds since
     * the epoch), and from where (or null if unknown).
     */
    @JsonInclude(JsonInclude.Include.NON_NULL)
    public static class Approval {

        private final String approver;
        private final long approved;
        private final String remoteHost;

        public Approval(String approver, long approved, String remoteHost) {
            this.approver = approver;
            this.approved = approved;
            this.remoteHost = remoteHost;
        }

        public String getApprover() {
            return approver;
        }

        public long getApproved() {
            return approved;
        }

        public String getRemoteHost() {
            return remoteHost;
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
     * Name of the account whose password is requested.
     */
    public String getAccountName() {
        return accountName;
    }

    void setAccountName(String accountName) {
        this.accountName = accountName;
    }

    /**
     * The Guacamole user who requested the password.
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

    /**
     * Where the user requested from, or null if unknown.
     */
    public String getRemoteHost() {
        return remoteHost;
    }

    void setRemoteHost(String remoteHost) {
        this.remoteHost = remoteHost;
    }

    public long getRequested() {
        return requested;
    }

    void setRequested(long requested) {
        this.requested = requested;
    }

    public int getApprovalsRequired() {
        return approvalsRequired;
    }

    void setApprovalsRequired(int approvalsRequired) {
        this.approvalsRequired = approvalsRequired;
    }

    /**
     * PENDING, APPROVED, DENIED, CANCELLED or EXPIRED.
     */
    public String getStatus() {
        return status;
    }

    void setStatus(String status) {
        this.status = status;
    }

    public Long getDecided() {
        return decided;
    }

    void setDecided(Long decided) {
        this.decided = decided;
    }

    /**
     * Who gave the final approval, denied, or cancelled the request.
     */
    public String getDecidedBy() {
        return decidedBy;
    }

    void setDecidedBy(String decidedBy) {
        this.decidedBy = decidedBy;
    }

    public Integer getCheckoutId() {
        return checkoutId;
    }

    void setCheckoutId(Integer checkoutId) {
        this.checkoutId = checkoutId;
    }

    /**
     * When the access asked for starts, for a request made ahead of time,
     * or null for access from the final approval on.
     */
    public Long getStarts() {
        return starts;
    }

    void setStarts(Long starts) {
        this.starts = starts;
    }

    /**
     * When the access asked for ahead of time ends, or null.
     */
    public Long getEnds() {
        return ends;
    }

    void setEnds(Long ends) {
        this.ends = ends;
    }

    /**
     * How many times the connection's time limit the access asked for
     * lasts: 1 unless more were asked for at once.
     */
    public int getPeriods() {
        return periods;
    }

    void setPeriods(int periods) {
        this.periods = periods;
    }

    /**
     * For a request to extend a checkout: the checkout's id, otherwise null.
     * Once approved, its checkout id is that same checkout.
     */
    public Integer getExtendsCheckout() {
        return extendsCheckout;
    }

    void setExtendsCheckout(Integer extendsCheckout) {
        this.extendsCheckout = extendsCheckout;
    }

    /**
     * By how many minutes an extension extends its checkout, or null for
     * any other request.
     */
    public Integer getExtensionMinutes() {
        return extensionMinutes;
    }

    void setExtensionMinutes(Integer extensionMinutes) {
        this.extensionMinutes = extensionMinutes;
    }

    /**
     * Why the request was denied, as given by the approver, or null.
     */
    public String getDecisionReason() {
        return decisionReason;
    }

    void setDecisionReason(String decisionReason) {
        this.decisionReason = decisionReason;
    }

    /**
     * Where who denied or cancelled the request did so from, or null.
     */
    public String getDecidedHost() {
        return decidedHost;
    }

    void setDecidedHost(String decidedHost) {
        this.decidedHost = decidedHost;
    }

    /**
     * The approvals given so far, in order.
     */
    public List<Approval> getApprovals() {
        return approvals;
    }

    /**
     * Users who approved the request so far, in order.
     */
    public List<String> getApprovers() {
        return approvers;
    }

    void setApprovers(List<String> approvers) {
        this.approvers = approvers;
    }

}
