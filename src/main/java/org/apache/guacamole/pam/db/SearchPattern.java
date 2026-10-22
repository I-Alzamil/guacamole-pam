package org.apache.guacamole.pam.db;

import java.util.Locale;

/**
 * Searching text columns for a term, ignoring case, in SQL every database
 * accepts: "LOWER(column) LIKE ? ESCAPE '!'". The escape character is not
 * the usual backslash, which MySQL reads as an escape within the literal
 * itself.
 */
public final class SearchPattern {

    private SearchPattern() {
    }

    /**
     * The condition that the value of the given column (or expression)
     * matches a pattern from {@link #contains}, given as a parameter.
     */
    public static String matches(String column) {
        return "LOWER(" + column + ") LIKE ? ESCAPE '!'";
    }

    /**
     * Pattern matching text that contains the given term anywhere, ignoring
     * case. The term is matched literally: its "%", "_", "[" and "!" are
     * not wildcards ("[" is one on SQL Server).
     */
    public static String contains(String term) {
        return "%" + term.trim().toLowerCase(Locale.ROOT)
                .replace("!", "!!").replace("%", "!%").replace("_", "!_").replace("[", "![") + "%";
    }

}
