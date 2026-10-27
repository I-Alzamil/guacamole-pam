package io.github.ialzamil.guacamole.pam.notification.email;

import java.util.LinkedHashMap;
import java.util.Map;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonInclude;

/**
 * A language of emails, as the Email Templates tab edits it, and as its
 * files are exported and imported: its code ("en", "fr", "pt-BR"), its
 * name, the messages PAM fills templates with ({summary}, the labels of
 * {details}, {action}, {why}), by key, and a subject and body template
 * for each kind of email ("approval", "decision", "ended", "other"). What a
 * language leaves out is taken from English.
 */
@JsonIgnoreProperties(ignoreUnknown = true)
@JsonInclude(JsonInclude.Include.NON_NULL)
public final class EmailLanguage {

    /**
     * What files of languages say they are, and their version.
     */
    public static final String FORMAT = "guacamole-pam-email-language";
    public static final int VERSION = 1;

    /**
     * The subject and body of a kind of email.
     */
    @JsonIgnoreProperties(ignoreUnknown = true)
    public static final class Template {

        private String subject;
        private String body;

        public Template() {
        }

        Template(String subject, String body) {
            this.subject = subject;
            this.body = body;
        }

        public String getSubject() {
            return subject;
        }

        public void setSubject(String subject) {
            this.subject = subject;
        }

        public String getBody() {
            return body;
        }

        public void setBody(String body) {
            this.body = body;
        }

    }

    private String format = FORMAT;
    private Integer version = VERSION;
    private String code;
    private String name;
    private Map<String, String> messages = new LinkedHashMap<>();
    private Map<String, Template> templates = new LinkedHashMap<>();

    public String getFormat() {
        return format;
    }

    public void setFormat(String format) {
        this.format = format;
    }

    public Integer getVersion() {
        return version;
    }

    public void setVersion(Integer version) {
        this.version = version;
    }

    public String getCode() {
        return code;
    }

    public void setCode(String code) {
        this.code = code;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public Map<String, String> getMessages() {
        return messages;
    }

    public void setMessages(Map<String, String> messages) {
        this.messages = messages == null ? new LinkedHashMap<>() : messages;
    }

    public Map<String, Template> getTemplates() {
        return templates;
    }

    public void setTemplates(Map<String, Template> templates) {
        this.templates = templates == null ? new LinkedHashMap<>() : templates;
    }

    /**
     * This language with what it leaves out taken from the given one.
     */
    EmailLanguage over(EmailLanguage base) {

        EmailLanguage merged = new EmailLanguage();
        merged.code = code;
        merged.name = name;
        merged.messages.putAll(base.messages);
        merged.messages.putAll(messages);

        for (Map.Entry<String, Template> entry : base.templates.entrySet()) {
            Template own = templates.get(entry.getKey());
            merged.templates.put(entry.getKey(), new Template(
                    own != null && own.subject != null ? own.subject : entry.getValue().subject,
                    own != null && own.body != null ? own.body : entry.getValue().body));
        }
        return merged;

    }

    /**
     * The message of a key, or the key itself if there is none.
     */
    public String message(String key) {
        String message = messages.get(key);
        return message != null ? message : key;
    }

    /**
     * The template of a kind of email.
     */
    Template template(EmailTemplates.Kind kind) {
        return templates.get(kind.getName());
    }

}
