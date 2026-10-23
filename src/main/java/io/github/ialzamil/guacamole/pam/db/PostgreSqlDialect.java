package io.github.ialzamil.guacamole.pam.db;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.Collection;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * PostgreSQL. Locks are advisory locks in their two-key form.
 */
class PostgreSqlDialect extends SqlDialect {

    private static final String UNIQUE_VIOLATION = "23505";

    private static final String INSUFFICIENT_PRIVILEGE = "42501";

    @Override
    public String getName() {
        return "postgresql";
    }

    @Override
    public String getDisplayName() {
        return "PostgreSQL";
    }

    @Override
    public String now() {
        return "CURRENT_TIMESTAMP";
    }

    @Override
    public String plusSeconds(String time, String seconds) {
        return "(" + time + " + make_interval(secs => " + seconds + "))";
    }

    @Override
    public String bool(boolean value) {
        return value ? "TRUE" : "FALSE";
    }

    @Override
    public String limit() {
        return " LIMIT ?";
    }

    @Override
    public String upsert(String table, List<String> keys, Map<String, String> values, String updates) {
        return "INSERT INTO " + table + " (" + String.join(", ", values.keySet()) + ")"
                + " VALUES (" + String.join(", ", values.values()) + ")"
                + " ON CONFLICT (" + String.join(", ", keys) + ") DO UPDATE SET " + updates;
    }

    @Override
    public boolean isUniqueViolation(SQLException e) {
        return UNIQUE_VIOLATION.equals(e.getSQLState());
    }

    @Override
    public boolean isPermissionDenied(SQLException e) {
        return INSUFFICIENT_PRIVILEGE.equals(e.getSQLState());
    }

    @Override
    public boolean hasTable(Connection connection, String table) throws SQLException {
        try (PreparedStatement statement = connection.prepareStatement("SELECT to_regclass(?) IS NOT NULL")) {
            statement.setString(1, table);
            try (ResultSet results = statement.executeQuery()) {
                return results.next() && results.getBoolean(1);
            }
        }
    }

    @Override
    public boolean tryLock(Connection connection, int namespace, int key) throws SQLException {
        try (PreparedStatement statement = connection.prepareStatement("SELECT pg_try_advisory_lock(?, ?)")) {
            statement.setInt(1, namespace);
            statement.setInt(2, key);
            try (ResultSet results = statement.executeQuery()) {
                return results.next() && results.getBoolean(1);
            }
        }
    }

    @Override
    public Set<Integer> getLocked(Connection connection, int namespace, Collection<Integer> keys)
            throws SQLException {

        Set<Integer> locked = new HashSet<>();
        if (keys.isEmpty())
            return locked;

        try (PreparedStatement statement = connection.prepareStatement(
                "SELECT objid FROM pg_locks WHERE locktype = 'advisory'"
              + " AND objsubid = 2 AND classid = ?::oid AND granted"
              + " AND database = (SELECT oid FROM pg_database WHERE datname = current_database())")) {
            statement.setInt(1, namespace);
            try (ResultSet results = statement.executeQuery()) {
                while (results.next()) {
                    int key = (int) results.getLong(1);
                    if (keys.contains(key))
                        locked.add(key);
                }
            }
        }

        return locked;

    }

    @Override
    public String getManualSchemaInstructions(String username) {
        return "Create them once as the database owner, by running schema/postgresql.sql from the extension's"
                + " jar (\"unzip -p guacamole-pam-*.jar schema/postgresql.sql | psql ...\"), then grant them to"
                + " Guacamole's user as for Guacamole's own tables:"
                + " GRANT SELECT,INSERT,UPDATE,DELETE ON ALL TABLES IN SCHEMA public TO \"" + username + "\";"
                + " GRANT SELECT,USAGE ON ALL SEQUENCES IN SCHEMA public TO \"" + username + "\";";
    }

}
