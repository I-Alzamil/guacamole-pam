package io.github.ialzamil.guacamole.pam.settings;

import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import org.apache.guacamole.GuacamoleClientException;

/**
 * One setting of the extension shared by every server, as the settings
 * page shows it, in its section: a yes/no, a whole number within bounds, a
 * line of text, several lines, one of a few options, or a secret (stored
 * encrypted, and never shown again), with its default. Named as its
 * guacamole.properties property would be, from which it is imported once.
 */
public final class Setting {

    public enum Type { BOOLEAN, INTEGER, STRING, TEXT, ENUM, SECRET }

    /**
     * Part of the settings page showing a setting.
     */
    public enum Section { GENERAL, SYSLOG, EMAIL }

    /**
     * Further checks of a text value, beyond its length.
     */
    @FunctionalInterface
    public interface Check {

        /**
         * @throws IllegalArgumentException
         *     If the value is not valid, saying why.
         */
        void check(String value);

    }

    private final Section section;
    private final String name;
    private final Type type;
    private final Object defaultValue;
    private final Integer minimum;
    private final Integer maximum;
    private final List<String> options;
    private final Check check;
    private final Setting requiredWhen;

    private Setting(Section section, String name, Type type, Object defaultValue, Integer minimum, Integer maximum,
            List<String> options, Check check, Setting requiredWhen) {
        this.section = section;
        this.name = name;
        this.type = type;
        this.defaultValue = defaultValue;
        this.minimum = minimum;
        this.maximum = maximum;
        this.options = options;
        this.check = check;
        this.requiredWhen = requiredWhen;
    }

    public static Setting bool(Section section, String name, boolean defaultValue) {
        return new Setting(section, name, Type.BOOLEAN, defaultValue, null, null, null, null, null);
    }

    public static Setting integer(Section section, String name, int defaultValue, int minimum, int maximum) {
        return new Setting(section, name, Type.INTEGER, defaultValue, minimum, maximum, null, null, null);
    }

    /**
     * A line of text of at most the given length, none by default.
     */
    public static Setting string(Section section, String name, int maxLength, Check check) {
        return new Setting(section, name, Type.STRING, null, null, maxLength, null, check, null);
    }

    /**
     * Several lines of text, such as certificates in PEM, none by default.
     */
    public static Setting text(Section section, String name, int maxLength, Check check) {
        return new Setting(section, name, Type.TEXT, null, null, maxLength, null, check, null);
    }

    /**
     * One of the given options, the first by default, as the page lists
     * them.
     */
    public static Setting options(Section section, String name, String... options) {
        return new Setting(section, name, Type.ENUM, options[0], null, null,
                Collections.unmodifiableList(Arrays.asList(options)), null, null);
    }

    /**
     * A secret of at most the given length, none by default.
     */
    public static Setting secret(Section section, String name, int maxLength) {
        return new Setting(section, name, Type.SECRET, null, null, maxLength, null, null, null);
    }

    /**
     * This setting, needing a value while the given yes/no is on.
     */
    public Setting requiredWhen(Setting toggle) {
        return new Setting(section, name, type, defaultValue, minimum, maximum, options, check, toggle);
    }

    /**
     * The yes/no that, while on, needs this setting to have a value, or
     * null.
     */
    public Setting getRequiredWhen() {
        return requiredWhen;
    }

    public Section getSection() {
        return section;
    }

    public String getName() {
        return name;
    }

    public Type getType() {
        return type;
    }

    public Object getDefaultValue() {
        return defaultValue;
    }

    /**
     * Least value of a number, or null for anything else.
     */
    public Integer getMinimum() {
        return minimum;
    }

    /**
     * Greatest value of a number, or longest text; null for anything else.
     */
    public Integer getMaximum() {
        return maximum;
    }

    /**
     * The options of a choice, or null for anything else.
     */
    public List<String> getOptions() {
        return options;
    }

    /**
     * Whether the value is text: a line, several, or a secret.
     */
    boolean isText() {
        return type == Type.STRING || type == Type.TEXT || type == Type.SECRET;
    }

    /**
     * The value given, as stored ("true", "3", "text"), or null for the
     * default. Accepts what JSON or guacamole.properties give: a boolean or
     * number, or its text. Text is trimmed, a secret excepted.
     *
     * @throws GuacamoleClientException
     *     If it is not a value of this setting.
     */
    String normalize(Object value) throws GuacamoleClientException {

        if (value == null || value.toString().trim().isEmpty())
            return null;
        String text = type == Type.SECRET ? value.toString() : value.toString().trim();

        if (type == Type.BOOLEAN) {
            if (text.equalsIgnoreCase("true") || text.equalsIgnoreCase("false"))
                return text.toLowerCase();
            throw new GuacamoleClientException("\"" + name + "\" must be true or false.");
        }

        if (type == Type.ENUM) {
            if (options.contains(text))
                return text;
            throw new GuacamoleClientException("\"" + name + "\" must be one of " + String.join(", ", options) + ".");
        }

        if (isText()) {
            if (text.length() > maximum)
                throw new GuacamoleClientException("\"" + name + "\" is limited to " + maximum + " characters.");
            if (type == Type.STRING && (text.indexOf('\n') >= 0 || text.indexOf('\r') >= 0))
                throw new GuacamoleClientException("\"" + name + "\" must be a single line.");
            if (check != null) {
                try {
                    check.check(text);
                }
                catch (IllegalArgumentException e) {
                    throw new GuacamoleClientException("\"" + name + "\": " + e.getMessage());
                }
            }
            return text;
        }

        int number;
        try {
            number = Integer.parseInt(text);
        }
        catch (NumberFormatException e) {
            throw new GuacamoleClientException("\"" + name + "\" must be a whole number.");
        }
        if (number < minimum || number > maximum)
            throw new GuacamoleClientException("\"" + name + "\" must be from " + minimum + " to " + maximum + ".");
        return Integer.toString(number);

    }

    /**
     * A stored value as its type, or the default for null or a value no
     * longer valid (written by hand, or by another version). A secret is
     * returned as stored, so encrypted.
     */
    Object parse(String stored) {
        if (type == Type.SECRET)
            return stored == null || stored.isEmpty() ? null : stored;
        try {
            String value = normalize(stored);
            if (value == null)
                return defaultValue;
            if (type == Type.BOOLEAN)
                return Boolean.valueOf(value);
            if (type == Type.INTEGER)
                return Integer.valueOf(value);
            return value;
        }
        catch (GuacamoleClientException e) {
            return defaultValue;
        }
    }

}
