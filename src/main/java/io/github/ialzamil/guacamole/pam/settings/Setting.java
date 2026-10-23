package io.github.ialzamil.guacamole.pam.settings;

import org.apache.guacamole.GuacamoleClientException;

/**
 * One setting of the extension shared by every server, as the settings
 * page shows it: a yes/no or a whole number within bounds, with its default.
 * Named as its guacamole.properties property was, from which it is imported
 * once.
 */
public final class Setting {

    public enum Type { BOOLEAN, INTEGER }

    private final String name;
    private final Type type;
    private final Object defaultValue;
    private final Integer minimum;
    private final Integer maximum;

    private Setting(String name, Type type, Object defaultValue, Integer minimum, Integer maximum) {
        this.name = name;
        this.type = type;
        this.defaultValue = defaultValue;
        this.minimum = minimum;
        this.maximum = maximum;
    }

    static Setting bool(String name, boolean defaultValue) {
        return new Setting(name, Type.BOOLEAN, defaultValue, null, null);
    }

    static Setting integer(String name, int defaultValue, int minimum, int maximum) {
        return new Setting(name, Type.INTEGER, defaultValue, minimum, maximum);
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
     * Least value of a number, or null for a yes/no.
     */
    public Integer getMinimum() {
        return minimum;
    }

    /**
     * Greatest value of a number, or null for a yes/no.
     */
    public Integer getMaximum() {
        return maximum;
    }

    /**
     * The value given, as stored ("true", "3"), or null for the default.
     * Accepts what JSON or guacamole.properties give: a boolean or number,
     * or its text.
     *
     * @throws GuacamoleClientException
     *     If it is not a value of this setting.
     */
    String normalize(Object value) throws GuacamoleClientException {

        if (value == null || value.toString().trim().isEmpty())
            return null;
        String text = value.toString().trim();

        if (type == Type.BOOLEAN) {
            if (text.equalsIgnoreCase("true") || text.equalsIgnoreCase("false"))
                return text.toLowerCase();
            throw new GuacamoleClientException("\"" + name + "\" must be true or false.");
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
     * longer valid (written by hand, or by another version).
     */
    Object parse(String stored) {
        try {
            String value = normalize(stored);
            if (value == null)
                return defaultValue;
            return type == Type.BOOLEAN ? (Object) Boolean.valueOf(value) : (Object) Integer.valueOf(value);
        }
        catch (GuacamoleClientException e) {
            return defaultValue;
        }
    }

}
