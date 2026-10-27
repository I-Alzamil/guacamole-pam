package io.github.ialzamil.guacamole.pam.notification.email;

import java.io.IOException;
import java.io.InputStream;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Timestamp;
import java.time.ZoneId;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import com.fasterxml.jackson.databind.ObjectMapper;

import org.apache.guacamole.GuacamoleClientException;
import org.apache.guacamole.GuacamoleException;
import org.apache.guacamole.GuacamoleResourceNotFoundException;
import org.apache.guacamole.GuacamoleServerException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import io.github.ialzamil.guacamole.pam.Values;
import io.github.ialzamil.guacamole.pam.coordination.Coordination;
import io.github.ialzamil.guacamole.pam.db.PamDatabase;
import io.github.ialzamil.guacamole.pam.db.SqlDialect;
import io.github.ialzamil.guacamole.pam.notification.Event;
import io.github.ialzamil.guacamole.pam.notification.EventType;
import io.github.ialzamil.guacamole.pam.notification.Events;

/**
 * The languages emails are written in, as the Email Templates tab manages
 * them: English, built into the extension ("email/en.json" in the jar),
 * which administrators may change and restore; and those they add or
 * import, kept in "pam_email_language", so every server has them. What a
 * language leaves out is taken from English. Read again after
 * {@link #CACHE_MILLIS}, so a change on another server applies within that
 * time.
 */
public class EmailLanguages {

    private static final Logger logger = LoggerFactory.getLogger(EmailLanguages.class);

    public static final String ENGLISH = "en";

    static final long CACHE_MILLIS = 5000;

    private static final ObjectMapper JSON = new ObjectMapper();

    /**
     * Longest code, as its columns hold.
     */
    static final int MAX_CODE = 16;

    private static final int MAX_NAME = 64;

    private static final int MAX_MESSAGE = 1000;

    private static final int MAX_SUBJECT = 300;

    private static final int MAX_BODY = 7000;

    /**
     * English, as built into the extension.
     */
    private static final EmailLanguage BUILT_IN = loadBuiltIn();

    private static final int MAX_USERNAME_LENGTH = 128;

    /**
     * A language as stored, with when and by whom.
     */
    public static final class Summary {

        private final String code;
        private final String name;
        private final boolean builtIn;
        private final boolean changed;
        private final Long modified;
        private final String modifiedBy;
        private final int users;

        Summary(String code, String name, boolean builtIn, boolean changed, Long modified, String modifiedBy,
                int users) {
            this.code = code;
            this.name = name;
            this.builtIn = builtIn;
            this.changed = changed;
            this.modified = modified;
            this.modifiedBy = modifiedBy;
            this.users = users;
        }

        public String getCode() {
            return code;
        }

        public String getName() {
            return name;
        }

        /**
         * Whether it is built into the extension: restored, never deleted.
         */
        public boolean isBuiltIn() {
            return builtIn;
        }

        /**
         * Whether it differs from what is built in, or was added.
         */
        public boolean isChanged() {
            return changed;
        }

        public Long getModified() {
            return modified;
        }

        public String getModifiedBy() {
            return modifiedBy;
        }

        /**
         * How many users chose it for their emails.
         */
        public int getUsers() {
            return users;
        }

    }

    /**
     * A row of "pam_email_language".
     */
    private static final class Row {

        final EmailLanguage language;
        final long modified;
        final String modifiedBy;

        Row(EmailLanguage language, long modified, String modifiedBy) {
            this.language = language;
            this.modified = modified;
            this.modifiedBy = modifiedBy;
        }

    }

    private final PamDatabase database;

    private final Coordination coordination;

    private final Events events;

    private volatile Map<String, Row> rows;

    private volatile long read = 0;

    public EmailLanguages(PamDatabase database, Coordination coordination, Events events) {
        this.database = database;
        this.coordination = coordination;
        this.events = events;
    }

    private static EmailLanguage loadBuiltIn() {
        try (InputStream input = EmailLanguages.class.getClassLoader().getResourceAsStream("email/en.json")) {
            if (input == null)
                throw new IllegalStateException("email/en.json is missing from the jar.");
            return JSON.readValue(input, EmailLanguage.class);
        }
        catch (IOException e) {
            throw new IllegalStateException("email/en.json cannot be read.", e);
        }
    }

    /**
     * English as built into the extension, for reference and to restore.
     */
    public static EmailLanguage getBuiltIn() {
        return BUILT_IN.over(BUILT_IN);
    }

    /**
     * Refuses what is not a language code: "en", "fr", "pt-BR".
     *
     * @throws IllegalArgumentException
     *     If it is not one.
     */
    public static void checkCode(String code) {
        if (code == null || code.length() > MAX_CODE || !code.matches("[a-z]{2,3}(-[A-Za-z0-9]{2,8}){0,2}"))
            throw new IllegalArgumentException("not a language code, such as en, fr or pt-BR, of at most " + MAX_CODE
                    + " characters.");
    }

    /**
     * The rows, read again once older than {@link #CACHE_MILLIS}.
     */
    private Map<String, Row> rows() throws GuacamoleException {

        Map<String, Row> current = rows;
        long now = System.currentTimeMillis();
        if (current != null && now - read < CACHE_MILLIS)
            return current;

        Map<String, Row> loaded = new LinkedHashMap<>();
        try (Connection connection = database.getConnection();
             PreparedStatement statement = connection.prepareStatement(
                 "SELECT code, name, content, modified, modified_by FROM pam_email_language");
             ResultSet results = statement.executeQuery()) {
            while (results.next()) {
                EmailLanguage language;
                try {
                    language = JSON.readValue(results.getString("content"), EmailLanguage.class);
                }
                catch (IOException e) {
                    logger.warn("Email language \"{}\" is ignored: it cannot be read ({}).", results.getString("code"),
                            e.getMessage());
                    continue;
                }
                language.setCode(results.getString("code"));
                language.setName(results.getString("name"));
                Timestamp modified = SqlDialect.getTimestamp(results, "modified");
                loaded.put(language.getCode(), new Row(language, modified == null ? 0 : modified.getTime(),
                        results.getString("modified_by")));
            }
        }
        catch (SQLException e) {
            throw new GuacamoleServerException("Unable to read the email languages.", e);
        }

        rows = Collections.unmodifiableMap(loaded);
        read = now;
        return loaded;

    }

    /**
     * English as in effect: as built in, or as changed.
     */
    private EmailLanguage english() throws GuacamoleException {
        Row row = rows().get(ENGLISH);
        return row == null ? getBuiltIn() : row.language.over(BUILT_IN);
    }

    /**
     * A language as in effect, what it leaves out taken from English, or
     * null if there is none of that code.
     */
    public EmailLanguage get(String code) throws GuacamoleException {
        if (ENGLISH.equals(code))
            return english();
        Row row = code == null ? null : rows().get(code);
        return row == null ? null : row.language.over(english());
    }

    /**
     * A language as in effect, English if there is none of that code.
     */
    EmailLanguage getOrEnglish(String code) throws GuacamoleException {
        EmailLanguage language = get(code);
        return language != null ? language : english();
    }

    public boolean isKnown(String code) throws GuacamoleException {
        return ENGLISH.equals(code) || (code != null && rows().containsKey(code));
    }

    /**
     * Each language's name, by code, English first, then by name.
     */
    public Map<String, String> getNames() throws GuacamoleException {
        Map<String, String> names = new LinkedHashMap<>();
        for (Summary summary : list(false))
            names.put(summary.getCode(), summary.getName());
        return names;
    }

    /**
     * Every language, English first, then by name, with how many users
     * chose each.
     */
    public List<Summary> list() throws GuacamoleException {
        return list(true);
    }

    private List<Summary> list(boolean counted) throws GuacamoleException {

        Map<String, Integer> users = counted ? countUsers() : Collections.<String, Integer>emptyMap();
        Map<String, Row> rows = rows();
        List<Summary> summaries = new ArrayList<>();

        Row english = rows.get(ENGLISH);
        summaries.add(new Summary(ENGLISH, english == null ? BUILT_IN.getName() : english.language.getName(), true,
                english != null, english == null ? null : english.modified,
                english == null ? null : english.modifiedBy, users.getOrDefault(ENGLISH, 0)));

        List<Row> added = new ArrayList<>();
        for (Row row : rows.values()) {
            if (!ENGLISH.equals(row.language.getCode()))
                added.add(row);
        }
        added.sort((a, b) -> a.language.getName().compareToIgnoreCase(b.language.getName()));
        for (Row row : added)
            summaries.add(new Summary(row.language.getCode(), row.language.getName(), false, true, row.modified,
                    row.modifiedBy, users.getOrDefault(row.language.getCode(), 0)));

        return summaries;

    }

    /**
     * How many users chose each language for their emails, among those
     * who still exist: preferences outlive deleted users.
     */
    private Map<String, Integer> countUsers() throws GuacamoleException {
        Map<String, Integer> users = new HashMap<>();
        try (Connection connection = database.getConnection();
             PreparedStatement statement = connection.prepareStatement(
                 "SELECT p.email_language, COUNT(*) FROM pam_user_preference p"
               + " JOIN guacamole_entity e ON e.name = p.username AND e.type = 'USER'"
               + " WHERE p.email_language IS NOT NULL GROUP BY p.email_language");
             ResultSet results = statement.executeQuery()) {
            while (results.next())
                users.put(results.getString(1), results.getInt(2));
        }
        catch (SQLException e) {
            throw new GuacamoleServerException("Unable to count the users of each email language.", e);
        }
        return users;
    }

    /**
     * Checks a language as given, by the tab or a file, keeping only what
     * it says: messages and templates left empty are taken from English.
     *
     * @throws GuacamoleClientException
     *     If it is not a language: an unknown format, code, message or kind
     *     of email, a placeholder that does not exist, or too long.
     */
    static EmailLanguage validate(EmailLanguage given) throws GuacamoleClientException {

        if (given == null)
            throw new GuacamoleClientException("No language was given.");
        if (given.getFormat() != null && !EmailLanguage.FORMAT.equals(given.getFormat()))
            throw new GuacamoleClientException("This is not a file of an email language (its format is \""
                    + Values.forLog(given.getFormat()) + "\").");
        if (given.getVersion() != null && given.getVersion() > EmailLanguage.VERSION)
            throw new GuacamoleClientException("This file is of a later version of the extension (version "
                    + given.getVersion() + ").");

        try {
            checkCode(given.getCode());
        }
        catch (IllegalArgumentException e) {
            throw new GuacamoleClientException("The code is " + e.getMessage());
        }

        String name = given.getName() == null ? "" : given.getName().trim();
        if (name.isEmpty() || name.length() > MAX_NAME || !name.equals(Values.forLog(name)))
            throw new GuacamoleClientException("The name must be one line of at most " + MAX_NAME + " characters.");

        EmailLanguage valid = new EmailLanguage();
        valid.setCode(given.getCode());
        valid.setName(name);

        for (Map.Entry<String, String> message : given.getMessages().entrySet()) {
            if (!BUILT_IN.getMessages().containsKey(message.getKey()))
                throw new GuacamoleClientException("There is no message \"" + Values.forLog(message.getKey())
                        + "\".");
            String text = message.getValue() == null ? "" : message.getValue().trim();
            if (text.isEmpty())
                continue;
            if (text.length() > MAX_MESSAGE || !text.equals(Values.forLog(text)))
                throw new GuacamoleClientException("Message \"" + message.getKey() + "\" must be one line of at most "
                        + MAX_MESSAGE + " characters.");
            check("Message \"" + message.getKey() + "\"", text);
            valid.getMessages().put(message.getKey(), text);
        }

        for (Map.Entry<String, EmailLanguage.Template> entry : given.getTemplates().entrySet()) {
            if (EmailTemplates.Kind.named(entry.getKey()) == null)
                throw new GuacamoleClientException("There is no kind of email \"" + Values.forLog(entry.getKey())
                        + "\".");
            EmailLanguage.Template template = entry.getValue();
            String subject = template == null || template.getSubject() == null ? "" : template.getSubject().trim();
            String body = template == null || template.getBody() == null ? "" : template.getBody().trim();
            if (subject.length() > MAX_SUBJECT || !subject.equals(Values.forLog(subject)))
                throw new GuacamoleClientException("The subject of \"" + entry.getKey() + "\" must be one line of at"
                        + " most " + MAX_SUBJECT + " characters.");
            if (body.length() > MAX_BODY)
                throw new GuacamoleClientException("The text of \"" + entry.getKey() + "\" is limited to " + MAX_BODY
                        + " characters.");
            check("The subject of \"" + entry.getKey() + "\"", subject);
            check("The text of \"" + entry.getKey() + "\"", body);
            if (!subject.isEmpty() || !body.isEmpty())
                valid.getTemplates().put(entry.getKey(), new EmailLanguage.Template(
                        subject.isEmpty() ? null : subject, body.isEmpty() ? null : body));
        }

        return valid;

    }

    private static void check(String what, String text) throws GuacamoleClientException {
        try {
            EmailTemplates.check(text);
        }
        catch (IllegalArgumentException e) {
            throw new GuacamoleClientException(what + " has an " + e.getMessage());
        }
    }

    /**
     * Saves a language, adding it, or replacing the one of its code; for
     * English, its changes to what is built in.
     *
     * @throws GuacamoleClientException
     *     If it is not valid (see {@link #validate}), or this server is on
     *     standby.
     */
    public EmailLanguage save(EmailLanguage given, String username) throws GuacamoleException {

        coordination.requireActive();
        EmailLanguage language = validate(given);
        EmailLanguage content = new EmailLanguage();
        content.setFormat(null);
        content.setVersion(null);
        content.setMessages(language.getMessages());
        content.setTemplates(language.getTemplates());

        String by = username.length() > MAX_USERNAME_LENGTH ? username.substring(0, MAX_USERNAME_LENGTH) : username;
        boolean existed = rows().containsKey(language.getCode());

        SqlDialect dialect = database.getDialect();
        Map<String, String> columns = new LinkedHashMap<>();
        columns.put("code", "?");
        columns.put("name", "?");
        columns.put("content", "?");
        columns.put("modified", dialect.now());
        columns.put("modified_by", "?");
        try (Connection connection = database.getConnection();
             PreparedStatement statement = connection.prepareStatement(dialect.upsert("pam_email_language",
                 Collections.singletonList("code"), columns, "name = EXCLUDED.name, content = EXCLUDED.content,"
                 + " modified = EXCLUDED.modified, modified_by = EXCLUDED.modified_by"))) {
            statement.setString(1, language.getCode());
            statement.setString(2, language.getName());
            statement.setString(3, JSON.writeValueAsString(content));
            statement.setString(4, by);
            statement.executeUpdate();
        }
        catch (IOException | SQLException e) {
            throw new GuacamoleServerException("Unable to save the email language.", e);
        }
        finally {
            rows = null;
        }

        logger.info("User \"{}\" {} email language \"{}\" ({}).", by, existed ? "changed" : "added",
                language.getCode(), Values.forLog(language.getName()));
        events.publish(Event.of(EventType.SETTINGS_CHANGED).actor(by).detail("Email language \""
                + language.getCode() + "\" " + (existed ? "changed" : "added") + "."));
        return get(language.getCode());

    }

    /**
     * Deletes an added language, whose users then receive the default one;
     * for English, restores what is built in.
     *
     * @throws GuacamoleResourceNotFoundException
     *     If there is no such language.
     */
    public void delete(String code, String username) throws GuacamoleException {

        coordination.requireActive();
        if (!isKnown(code))
            throw new GuacamoleResourceNotFoundException("No such email language.");

        String by = username.length() > MAX_USERNAME_LENGTH ? username.substring(0, MAX_USERNAME_LENGTH) : username;
        try (Connection connection = database.getConnection();
             PreparedStatement statement = connection.prepareStatement(
                 "DELETE FROM pam_email_language WHERE code = ?")) {
            statement.setString(1, code);
            statement.executeUpdate();
        }
        catch (SQLException e) {
            throw new GuacamoleServerException("Unable to delete the email language.", e);
        }
        finally {
            rows = null;
        }

        String what = ENGLISH.equals(code) ? "restored the built-in" : "deleted";
        logger.info("User \"{}\" {} email language \"{}\".", by, what, code);
        events.publish(Event.of(EventType.SETTINGS_CHANGED).actor(by).detail("Email language \"" + code + "\" "
                + (ENGLISH.equals(code) ? "restored as built in" : "deleted") + "."));

    }

    /**
     * The subject and text of a kind of email in a language as given,
     * unsaved, for a sample event: "subject" and "body".
     *
     * @throws GuacamoleClientException
     *     If the language is not valid, or there is no such kind.
     */
    public Map<String, String> preview(EmailLanguage given, String kindName, String link, ZoneId zone)
            throws GuacamoleException {

        EmailTemplates.Kind kind = EmailTemplates.Kind.named(kindName);
        if (kind == null)
            throw new GuacamoleClientException("There is no kind of email \"" + Values.forLog(kindName) + "\".");
        EmailText text = new EmailText(validate(given).over(english()), kind, link, zone);

        long now = System.currentTimeMillis();
        Event event;
        Audience.Role role;
        switch (kind) {
            case APPROVAL:
                event = Event.of(EventType.REQUEST_SUBMITTED).user("alice").connection("12", "web01").request(42)
                        .reason("Ticket 1234").remoteHost("10.0.0.5");
                role = Audience.Role.APPROVER;
                break;
            case DECISION:
                event = Event.of(EventType.REQUEST_GRANTED).user("alice").actor("bob").connection("12", "web01")
                        .request(42).remoteHost("10.0.0.6");
                role = Audience.Role.OWN;
                break;
            case ENDED:
                event = Event.of(EventType.CHECKOUT_EXPIRED).user("alice").connection("12", "web01").checkout(7)
                        .period(now - 3600000, now);
                role = Audience.Role.OWN;
                break;
            default:
                event = Event.of(EventType.ROTATION_FAILED).connection("12", "web01")
                        .detail("Rotation (periodic): FAILED: the host refused the password.");
                role = Audience.Role.ADMINISTRATOR;
                break;
        }

        Map<String, String> preview = new LinkedHashMap<>();
        preview.put("subject", text.subject(event, role));
        preview.put("body", text.body(event, role));
        return preview;

    }

}
