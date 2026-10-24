package io.github.ialzamil.guacamole.pam.password;

import java.util.List;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonInclude;

/**
 * A named password policy: the rules of the passwords generated for the
 * platforms and connections choosing it. Listed with what uses it.
 */
@JsonIgnoreProperties(ignoreUnknown = true)
@JsonInclude(JsonInclude.Include.NON_NULL)
public final class PasswordPolicy {

    private Integer id;
    private String name;
    private String description;
    private PasswordRules rules = PasswordRules.defaults();
    private Long lastModified;
    private List<String> platforms;
    private List<String> connections;

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

    public PasswordRules getRules() {
        return rules;
    }

    public void setRules(PasswordRules rules) {
        this.rules = rules;
    }

    public Long getLastModified() {
        return lastModified;
    }

    public void setLastModified(Long lastModified) {
        this.lastModified = lastModified;
    }

    /**
     * Names of the platforms choosing it, when listed.
     */
    public List<String> getPlatforms() {
        return platforms;
    }

    public void setPlatforms(List<String> platforms) {
        this.platforms = platforms;
    }

    /**
     * Names of the connections choosing it themselves, when listed.
     */
    public List<String> getConnections() {
        return connections;
    }

    public void setConnections(List<String> connections) {
        this.connections = connections;
    }

}
