package org.apache.guacamole.pam.platform;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonInclude;

/**
 * A platform: how passwords of a group of systems are managed. Its type
 * (SSH, LDAP, ...) decides which settings it has; its policy decides when
 * passwords are rotated.
 *
 * Secret settings are never serialized. Clients send new secret values in
 * {@link #getSettings()}; an empty value keeps the stored secret.
 */
@JsonIgnoreProperties(ignoreUnknown = true)
@JsonInclude(JsonInclude.Include.NON_NULL)
public class Platform {

    /**
     * Policy key: "never", "after-use" or "periodic".
     */
    public static final String POLICY_ROTATION_MODE = "rotation-mode";

    /**
     * Policy key: hours between periodic rotations.
     */
    public static final String POLICY_ROTATION_INTERVAL = "rotation-interval";

    /**
     * Policy key: length of generated passwords.
     */
    public static final String POLICY_PASSWORD_LENGTH = "password-length";

    public static final String MODE_NEVER = "never";
    public static final String MODE_AFTER_USE = "after-use";
    public static final String MODE_PERIODIC = "periodic";

    private Integer id;
    private String name;
    private String description;
    private String type;
    private Map<String, String> settings = new HashMap<>();
    private Map<String, String> secrets = new HashMap<>();
    private Map<String, String> policy = new HashMap<>();
    private Long lastModified;

    public Integer getId() {
        return id;
    }

    public void setId(Integer id) {
        this.id = id;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public String getDescription() {
        return description;
    }

    public void setDescription(String description) {
        this.description = description;
    }

    /**
     * Name of the management type, such as "ssh" or "ldap".
     */
    public String getType() {
        return type;
    }

    public void setType(String type) {
        this.type = type;
    }

    /**
     * Non-secret settings, by field name of the type's platform forms.
     */
    public Map<String, String> getSettings() {
        return settings;
    }

    public void setSettings(Map<String, String> settings) {
        this.settings = settings == null ? new HashMap<>() : settings;
    }

    /**
     * Secret settings. Only used server side.
     */
    @JsonIgnore
    public Map<String, String> getSecrets() {
        return secrets;
    }

    @JsonIgnore
    public void setSecrets(Map<String, String> secrets) {
        this.secrets = secrets == null ? new HashMap<>() : secrets;
    }

    /**
     * Settings and secrets together, as a type's targets read them. Not a
     * getter, so it is never serialized.
     */
    public Map<String, String> settingsWithSecrets() {
        Map<String, String> values = new HashMap<>(settings);
        values.putAll(secrets);
        return values;
    }

    /**
     * Names of the secrets that have a stored value, so clients can say so
     * without seeing them.
     */
    public List<String> getStoredSecrets() {
        List<String> names = new ArrayList<>();
        for (Map.Entry<String, String> secret : secrets.entrySet()) {
            if (secret.getValue() != null && !secret.getValue().isEmpty())
                names.add(secret.getKey());
        }
        return names;
    }

    public void setStoredSecrets(List<String> ignored) {
        // Read-only; accepted so clients can send platforms back unchanged
    }

    /**
     * Rotation policy, by the POLICY_* keys.
     */
    public Map<String, String> getPolicy() {
        return policy;
    }

    public void setPolicy(Map<String, String> policy) {
        this.policy = policy == null ? new HashMap<>() : policy;
    }

    public Long getLastModified() {
        return lastModified;
    }

    public void setLastModified(Long lastModified) {
        this.lastModified = lastModified;
    }

    /**
     * Returns a setting or secret, or null if unset or blank.
     */
    public String get(String field) {
        String value = secrets.containsKey(field) ? secrets.get(field) : settings.get(field);
        return value == null || value.trim().isEmpty() ? null : value;
    }

}
