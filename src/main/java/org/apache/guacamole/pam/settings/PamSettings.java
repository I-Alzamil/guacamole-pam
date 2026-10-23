package org.apache.guacamole.pam.settings;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Timestamp;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;

import org.apache.guacamole.GuacamoleClientException;
import org.apache.guacamole.GuacamoleException;
import org.apache.guacamole.GuacamoleServerException;
import org.apache.guacamole.environment.Environment;
import org.apache.guacamole.pam.Values;
import org.apache.guacamole.pam.db.PamDatabase;
import org.apache.guacamole.pam.db.SqlDialect;
import org.apache.guacamole.properties.StringGuacamoleProperty;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Settings of the extension shared by every Guacamole server using the
 * database, in "pam_setting", so servers sharing it never disagree, and a
 * change applies to all of them without a restart. Each server reads them
 * again after {@link #CACHE_MILLIS}, so a change made on another one applies
 * here within that time.
 *
 * They were guacamole.properties settings: a value still set there is
 * imported once, by the first server reading the settings, unless the
 * setting was decided in the database already; it is ignored from then on,
 * which is logged. Settings needed to reach the database, or protecting its
 * contents (the encryption keys), stay in guacamole.properties.
 */
public class PamSettings {

    private static final Logger logger = LoggerFactory.getLogger(PamSettings.class);

    /**
     * Whether administrators connect, and check out Accounts, without a
     * request. Otherwise they only skip approvals, and give a reason like
     * anyone else.
     */
    public static final Setting ADMIN_BYPASS_REQUESTS = Setting.bool("pam-admin-bypass-requests", false);

    /**
     * Whether holders may extend their checkouts, unless a connection says
     * otherwise.
     */
    public static final Setting EXTENSIONS_ENABLED = Setting.bool("pam-extensions-enabled", true);

    /**
     * How many times a checkout may be extended, unless a connection says
     * otherwise.
     */
    public static final Setting MAX_EXTENSIONS = Setting.integer("pam-max-extensions", 2, 0, 20);

    /**
     * Every setting, in the order the settings page shows them.
     */
    public static final List<Setting> ALL = Collections.unmodifiableList(Arrays.asList(
            ADMIN_BYPASS_REQUESTS, EXTENSIONS_ENABLED, MAX_EXTENSIONS));

    /**
     * How long values read are used before being read again.
     */
    static final long CACHE_MILLIS = 5000;

    /**
     * Longest username kept as who changed a setting, as the column holds.
     */
    private static final int MAX_USERNAME_LENGTH = 128;

    /**
     * A setting as decided in the database, for the settings page.
     */
    public static final class Entry {

        private final Setting setting;
        private final Object value;
        private final boolean stored;
        private final Long modified;
        private final String modifiedBy;

        Entry(Setting setting, Object value, boolean stored, Long modified, String modifiedBy) {
            this.setting = setting;
            this.value = value;
            this.stored = stored;
            this.modified = modified;
            this.modifiedBy = modifiedBy;
        }

        public String getName() {
            return setting.getName();
        }

        public Setting.Type getType() {
            return setting.getType();
        }

        /**
         * The value in effect: the one set, or the default.
         */
        public Object getValue() {
            return value;
        }

        public Object getDefaultValue() {
            return setting.getDefaultValue();
        }

        /**
         * Whether a value is set, rather than the default used.
         */
        public boolean isSet() {
            return stored;
        }

        public Integer getMinimum() {
            return setting.getMinimum();
        }

        public Integer getMaximum() {
            return setting.getMaximum();
        }

        /**
         * When the setting was last decided, in milliseconds since the
         * epoch, or null if never.
         */
        public Long getModified() {
            return modified;
        }

        /**
         * Who last decided it, or null if never, or imported from
         * guacamole.properties (then {@link #isImported}).
         */
        public String getModifiedBy() {
            return modifiedBy;
        }

        public boolean isImported() {
            return modified != null && modifiedBy == null;
        }

    }

    /**
     * A row of "pam_setting": the value stored (null for the default), when
     * and by whom.
     */
    private static final class Row {

        final String value;
        final long modified;
        final String modifiedBy;

        Row(String value, long modified, String modifiedBy) {
            this.value = value;
            this.modified = modified;
            this.modifiedBy = modifiedBy;
        }

    }

    /**
     * The rows read last, by name, and when.
     */
    private static final class Snapshot {

        final Map<String, Row> rows;
        final long read;

        Snapshot(Map<String, Row> rows, long read) {
            this.rows = rows;
            this.read = read;
        }

    }

    private final PamDatabase database;

    private final Environment environment;

    private volatile Snapshot snapshot;

    /**
     * Whether this server imported its guacamole.properties values yet.
     */
    private volatile boolean imported = false;

    public PamSettings(PamDatabase database, Environment environment) {
        this.database = database;
        this.environment = environment;
    }

    public boolean isAdminBypassRequests() throws GuacamoleException {
        return (Boolean) get(ADMIN_BYPASS_REQUESTS);
    }

    public boolean isExtensionsEnabled() throws GuacamoleException {
        return (Boolean) get(EXTENSIONS_ENABLED);
    }

    public int getMaxExtensions() throws GuacamoleException {
        return (Integer) get(MAX_EXTENSIONS);
    }

    /**
     * The value in effect of a setting.
     */
    public Object get(Setting setting) throws GuacamoleException {
        Row row = rows().get(setting.getName());
        return setting.parse(row == null ? null : row.value);
    }

    /**
     * Every setting, as decided in the database, read again now.
     */
    public List<Entry> list() throws GuacamoleException {
        snapshot = null;
        Map<String, Row> rows = rows();
        List<Entry> entries = new ArrayList<>();
        for (Setting setting : ALL) {
            Row row = rows.get(setting.getName());
            entries.add(new Entry(setting, setting.parse(row == null ? null : row.value),
                    row != null && row.value != null, row == null ? null : row.modified,
                    row == null ? null : row.modifiedBy));
        }
        return entries;
    }

    /**
     * Changes settings, all or none, as one administrator: each by name, to
     * a value, or to null for its default. Settings not given, or given
     * their current value, are left as they are.
     *
     * @throws GuacamoleClientException
     *     If a setting is unknown, or a value invalid.
     */
    public void update(Map<String, Object> values, String username) throws GuacamoleException {

        if (values == null || values.isEmpty())
            return;

        Map<String, Setting> byName = new HashMap<>();
        for (Setting setting : ALL)
            byName.put(setting.getName(), setting);

        Map<Setting, String> normalized = new LinkedHashMap<>();
        for (Map.Entry<String, Object> value : values.entrySet()) {
            Setting setting = byName.get(value.getKey());
            if (setting == null)
                throw new GuacamoleClientException("Unknown setting \"" + Values.forLog(value.getKey()) + "\".");
            normalized.put(setting, setting.normalize(value.getValue()));
        }

        snapshot = null;
        Map<String, Row> current = rows();
        String by = username.length() > MAX_USERNAME_LENGTH ? username.substring(0, MAX_USERNAME_LENGTH) : username;

        SqlDialect dialect = database.getDialect();
        Map<String, String> columns = new LinkedHashMap<>();
        columns.put("name", "?");
        columns.put("value", "?");
        columns.put("modified", dialect.now());
        columns.put("modified_by", "?");

        try (Connection connection = database.getConnection()) {

            connection.setAutoCommit(false);
            try (PreparedStatement statement = connection.prepareStatement(dialect.upsert("pam_setting",
                    Collections.singletonList("name"), columns,
                    "value = EXCLUDED.value, modified = EXCLUDED.modified, modified_by = EXCLUDED.modified_by"))) {

                for (Map.Entry<Setting, String> change : normalized.entrySet()) {
                    Setting setting = change.getKey();
                    Row row = current.get(setting.getName());
                    if (row != null && Objects.equals(row.value, change.getValue()))
                        continue;
                    statement.setString(1, setting.getName());
                    statement.setString(2, change.getValue());
                    statement.setString(3, by);
                    statement.executeUpdate();
                    logger.info("User \"{}\" set \"{}\" to {} (was {}).", by, setting.getName(),
                            describe(setting, change.getValue()), describe(setting, row == null ? null : row.value));
                }
                connection.commit();

            }
            catch (SQLException e) {
                connection.rollback();
                throw e;
            }

        }
        catch (SQLException e) {
            throw new GuacamoleServerException("Unable to save the settings.", e);
        }
        finally {
            snapshot = null;
        }

    }

    private static String describe(Setting setting, String value) {
        return value == null ? "the default (" + setting.getDefaultValue() + ")" : value;
    }

    /**
     * The rows of the settings, read again once older than
     * {@link #CACHE_MILLIS}, importing guacamole.properties values first if
     * this server did not yet.
     */
    private Map<String, Row> rows() throws GuacamoleException {

        Snapshot current = snapshot;
        long now = System.currentTimeMillis();
        if (current != null && now - current.read < CACHE_MILLIS)
            return current.rows;

        if (!imported) {
            importProperties();
            imported = true;
        }

        Map<String, Row> rows = new HashMap<>();
        try (Connection connection = database.getConnection();
             PreparedStatement statement = connection.prepareStatement(
                 "SELECT name, value, modified, modified_by FROM pam_setting");
             ResultSet results = statement.executeQuery()) {
            while (results.next()) {
                Timestamp modified = SqlDialect.getTimestamp(results, "modified");
                rows.put(results.getString("name"), new Row(results.getString("value"),
                        modified == null ? 0 : modified.getTime(), results.getString("modified_by")));
            }
        }
        catch (SQLException e) {
            throw new GuacamoleServerException("Unable to read the settings.", e);
        }

        snapshot = new Snapshot(Collections.unmodifiableMap(rows), now);
        return rows;

    }

    /**
     * Imports each setting still in this server's guacamole.properties,
     * unless decided in the database already (by another server, or on the
     * settings page), in which case the property is ignored, which is
     * logged. An invalid property is ignored too.
     */
    private void importProperties() throws GuacamoleException {

        for (Setting setting : ALL) {

            String property = environment.getProperty(new StringGuacamoleProperty() {
                @Override
                public String getName() { return setting.getName(); }
            });
            if (property == null || property.trim().isEmpty())
                continue;

            String value;
            try {
                value = setting.normalize(property);
            }
            catch (GuacamoleClientException e) {
                logger.warn("\"{}\" in guacamole.properties is ignored: {}", setting.getName(), e.getMessage());
                continue;
            }

            try (Connection connection = database.getConnection()) {

                String stored = null;
                boolean decided;
                try (PreparedStatement statement = connection.prepareStatement(
                        "SELECT value FROM pam_setting WHERE name = ?")) {
                    statement.setString(1, setting.getName());
                    try (ResultSet results = statement.executeQuery()) {
                        decided = results.next();
                        if (decided)
                            stored = results.getString(1);
                    }
                }

                if (!decided) {
                    try (PreparedStatement statement = connection.prepareStatement(
                            "INSERT INTO pam_setting (name, value) VALUES (?, ?)")) {
                        statement.setString(1, setting.getName());
                        statement.setString(2, value);
                        statement.executeUpdate();
                        logger.info("\"{}\" was imported from guacamole.properties ({}); it is now set on the PAM"
                                + " settings page, for every server.", setting.getName(), value);
                        continue;
                    }
                    catch (SQLException e) {
                        // Another server imported its own just now
                        if (database.getDialect().isUniqueViolation(e))
                            continue;
                        throw e;
                    }
                }

                if (!value.equals(stored))
                    logger.warn("\"{}\" in guacamole.properties ({}) is ignored: it is set on the PAM settings page,"
                            + " for every server ({}). Remove it from guacamole.properties.", setting.getName(), value,
                            describe(setting, stored));

            }
            catch (SQLException e) {
                throw new GuacamoleServerException("Unable to import the settings from guacamole.properties.", e);
            }

        }

    }

}
