package io.github.ialzamil.guacamole.pam.notification;

import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.Map;

import io.github.ialzamil.guacamole.pam.Values;

/**
 * Something PAM did, or saw, reported once to every output (see
 * {@link Events}). Set up with the fields that apply, then published; it
 * never holds a password.
 */
public final class Event {

    /**
     * The name of this server, as events report it.
     */
    static final String SERVER = Values.hostName();

    private final EventType type;
    private final long time = System.currentTimeMillis();
    private String actor;
    private String user;
    private String connectionIdentifier;
    private String connectionName;
    private Integer requestId;
    private Integer checkoutId;
    private String reason;
    private String detail;
    private String detailKey;
    private Integer minutes;
    private Integer approvals;
    private Integer approvalsRequired;
    private String remoteHost;
    private Long starts;
    private Long ends;

    private Event(EventType type) {
        this.type = type;
    }

    public static Event of(EventType type) {
        return new Event(type);
    }

    /**
     * Who did it: the user deciding, revoking or changing, if not the user
     * concerned.
     */
    public Event actor(String actor) {
        this.actor = actor;
        return this;
    }

    /**
     * Whose request, checkout or session it concerns.
     */
    public Event user(String user) {
        this.user = user;
        return this;
    }

    public Event connection(String identifier, String name) {
        this.connectionIdentifier = identifier;
        this.connectionName = name;
        return this;
    }

    public Event request(Integer id) {
        this.requestId = id;
        return this;
    }

    public Event checkout(Integer id) {
        this.checkoutId = id;
        return this;
    }

    /**
     * The reason given by the user, or for a denial by the approver.
     */
    public Event reason(String reason) {
        this.reason = reason;
        return this;
    }

    /**
     * What else to know: a rotation's outcome, why a server is on standby,
     * the settings changed.
     */
    public Event detail(String detail) {
        this.detail = detail;
        return this;
    }

    /**
     * What else to know, in words PAM has in every language: the message
     * of the given key (DETAIL_...), with the event's values. Emails show it
     * in the recipient's language; the detail is it in English unless set.
     */
    public Event detailMessage(String key) {
        this.detailKey = key;
        return this;
    }

    /**
     * The minutes a checkout is, or would be, extended by.
     */
    public Event minutes(Integer minutes) {
        this.minutes = minutes;
        return this;
    }

    /**
     * The approvals a request has, if known, and needs.
     */
    public Event approvals(Integer given, Integer required) {
        this.approvals = given;
        this.approvalsRequired = required;
        return this;
    }

    /**
     * Where the user acted from.
     */
    public Event remoteHost(String remoteHost) {
        this.remoteHost = remoteHost;
        return this;
    }

    /**
     * The time access starts or ends, in milliseconds since the epoch:
     * requested ahead, or until a checkout lasts.
     */
    public Event period(Long starts, Long ends) {
        this.starts = starts;
        this.ends = ends;
        return this;
    }

    public EventType getType() {
        return type;
    }

    public long getTime() {
        return time;
    }

    public String getServer() {
        return SERVER;
    }

    public String getActor() {
        return actor;
    }

    public String getUser() {
        return user;
    }

    public String getConnectionIdentifier() {
        return connectionIdentifier;
    }

    public String getConnectionName() {
        return connectionName;
    }

    public Integer getRequestId() {
        return requestId;
    }

    public Integer getCheckoutId() {
        return checkoutId;
    }

    public String getReason() {
        return reason;
    }

    /**
     * What else to know, in English.
     */
    public String getDetail() {
        return detail != null || detailKey == null ? detail : Summary.detail(this);
    }

    public String getDetailKey() {
        return detailKey;
    }

    public Integer getMinutes() {
        return minutes;
    }

    public Integer getApprovals() {
        return approvals;
    }

    public Integer getApprovalsRequired() {
        return approvalsRequired;
    }

    public String getRemoteHost() {
        return remoteHost;
    }

    public Long getStarts() {
        return starts;
    }

    public Long getEnds() {
        return ends;
    }

    /**
     * The fields set, by name, in a fixed order, as outputs list them:
     * "user", "connection", "request" and so on.
     */
    public Map<String, Object> getFields() {
        Map<String, Object> fields = new LinkedHashMap<>();
        put(fields, "user", user);
        put(fields, "actor", actor);
        put(fields, "connection", connectionName);
        put(fields, "connection-id", connectionIdentifier);
        put(fields, "request", requestId);
        put(fields, "checkout", checkoutId);
        put(fields, "minutes", minutes);
        put(fields, "approvals", approvals);
        put(fields, "approvals-required", approvalsRequired);
        put(fields, "starts", starts == null ? null : Instant.ofEpochMilli(starts).toString());
        put(fields, "ends", ends == null ? null : Instant.ofEpochMilli(ends).toString());
        put(fields, "remote-host", remoteHost);
        put(fields, "reason", reason);
        put(fields, "detail", getDetail());
        return fields;
    }

    private static void put(Map<String, Object> fields, String name, Object value) {
        if (value != null)
            fields.put(name, value);
    }

}
