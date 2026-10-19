package org.apache.guacamole.pam.db;

/**
 * Patterns for searching text columns with "ILIKE ? ESCAPE '\'".
 */
public final class SearchPattern {

    private SearchPattern() {
    }

    /**
     * Pattern matching text that contains the given term anywhere, ignoring
     * case. The term is matched literally: its "%", "_" and "\" are not
     * wildcards.
     */
    public static String contains(String term) {
        return "%" + term.trim().replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%";
    }

}
