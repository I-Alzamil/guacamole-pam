package io.github.ialzamil.guacamole.pam.ha;

import java.util.Objects;

/**
 * What a session is opened to: a connection, or a balancing connection
 * group, by its identifier.
 */
final class Target {

    enum Kind {

        CONNECTION("connection_id"),
        CONNECTION_GROUP("connection_group_id");

        private final String column;

        Kind(String column) {
            this.column = column;
        }

        /**
         * The column of pam_ha_session holding the identifier.
         */
        String getColumn() {
            return column;
        }

    }

    private final Kind kind;

    private final String identifier;

    Target(Kind kind, String identifier) {
        this.kind = Objects.requireNonNull(kind);
        this.identifier = Objects.requireNonNull(identifier);
    }

    Kind getKind() {
        return kind;
    }

    String getIdentifier() {
        return identifier;
    }

    @Override
    public boolean equals(Object other) {
        return other instanceof Target && ((Target) other).kind == kind
                && ((Target) other).identifier.equals(identifier);
    }

    @Override
    public int hashCode() {
        return Objects.hash(kind, identifier);
    }

}
