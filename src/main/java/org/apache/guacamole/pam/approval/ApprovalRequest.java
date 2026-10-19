package org.apache.guacamole.pam.approval;

import java.util.ArrayList;
import java.util.List;

import com.fasterxml.jackson.annotation.JsonInclude;

/**
 * A request awaiting, or having received, approval. Times are
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
    private String reason;
    private long requested;
    private int approvalsRequired;
    private String status;
    private Long decided;
    private String decidedBy;
    private String decisionReason;
    private Integer checkoutId;
    private List<String> approvers = new ArrayList<>();

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
     * Why the request was denied, as given by the approver, or null.
     */
    public String getDecisionReason() {
        return decisionReason;
    }

    void setDecisionReason(String decisionReason) {
        this.decisionReason = decisionReason;
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
