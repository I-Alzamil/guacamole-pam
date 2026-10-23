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
 * MySQL and MariaDB. Sessions use UTC as their time zone (see
 * {@link #SESSION_SETUP}), so times are stored in UTC. Locks are named
 * locks, whose names are shared by every database of the server, so they
 * include a digest of the database's name.
 */
class MySqlDialect extends SqlDialect {

    /**
     * Run on every new database session.
     */
    static final String SESSION_SETUP = "SET time_zone = '+00:00'";

    private static final int DUPLICATE_ENTRY = 1062;

    private static final int DUPLICATE_ENTRY_WITH_KEY_NAME = 1586;

    private static final int DATABASE_ACCESS_DENIED = 1044;

    private static final int TABLE_ACCESS_DENIED = 1142;

    private static final String LOCK_NAME = "CONCAT('pam.', LEFT(SHA1(DATABASE()), 16), '.', ?, '.', ?)";

    @Override
    public String getName() {
        return "mysql";
    }

    @Override
    public String getDisplayName() {
        return "MySQL";
    }

    @Override
    public String now() {
        return "CURRENT_TIMESTAMP(3)";
    }

    @Override
    public String plusSeconds(String time, String seconds) {
        return "TIMESTAMPADD(SECOND, " + seconds + ", " + time + ")";
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
        // Within ON DUPLICATE KEY UPDATE, the keys need not be named, and
        // VALUES(column) is the value that would have been inserted
        return "INSERT INTO " + table + " (" + String.join(", ", values.keySet()) + ")"
                + " VALUES (" + String.join(", ", values.values()) + ")"
                + " ON DUPLICATE KEY UPDATE " + updates.replaceAll("\\bEXCLUDED\\.(\\w+)", "VALUES($1)");
    }

    @Override
    public boolean isUniqueViolation(SQLException e) {
        return e.getErrorCode() == DUPLICATE_ENTRY || e.getErrorCode() == DUPLICATE_ENTRY_WITH_KEY_NAME;
    }

    @Override
    public boolean isPermissionDenied(SQLException e) {
        return e.getErrorCode() == TABLE_ACCESS_DENIED || e.getErrorCode() == DATABASE_ACCESS_DENIED;
    }

    @Override
    public boolean hasTable(Connection connection, String table) throws SQLException {
        try (PreparedStatement statement = connection.prepareStatement(
                "SELECT 1 FROM information_schema.tables WHERE table_schema = DATABASE() AND table_name = ?")) {
            statement.setString(1, table);
            try (ResultSet results = statement.executeQuery()) {
                return results.next();
            }
        }
    }

    @Override
    public boolean tryLock(Connection connection, int namespace, int key) throws SQLException {
        try (PreparedStatement statement = connection.prepareStatement("SELECT GET_LOCK(" + LOCK_NAME + ", 0)")) {
            statement.setInt(1, namespace);
            statement.setInt(2, key);
            try (ResultSet results = statement.executeQuery()) {
                return results.next() && results.getInt(1) == 1;
            }
        }
    }

    @Override
    public Set<Integer> getLocked(Connection connection, int namespace, Collection<Integer> keys)
            throws SQLException {

        Set<Integer> locked = new HashSet<>();

        try (PreparedStatement statement = connection.prepareStatement(
                "SELECT IS_USED_LOCK(" + LOCK_NAME + ") IS NOT NULL")) {
            for (int key : keys) {
                statement.setInt(1, namespace);
                statement.setInt(2, key);
                try (ResultSet results = statement.executeQuery()) {
                    if (results.next() && results.getBoolean(1))
                        locked.add(key);
                }
            }
        }

        return locked;

    }

    @Override
    public String getManualSchemaInstructions(String username) {
        return "Create them once as a user who may, by running schema/mysql.sql from the extension's jar"
                + " (\"unzip -p guacamole-pam-*.jar schema/mysql.sql | mysql ...\"). The grants of Guacamole's"
                + " installation guide (SELECT, INSERT, UPDATE and DELETE on the whole database) then cover"
                + " them; otherwise grant those on the tables named pam_* to '" + username + "'.";
    }

}
