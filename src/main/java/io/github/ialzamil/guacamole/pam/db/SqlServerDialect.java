package io.github.ialzamil.guacamole.pam.db;

import java.sql.CallableStatement;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Types;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * SQL Server. Times are stored in UTC. Locks are application locks owned by
 * the session.
 */
class SqlServerDialect extends SqlDialect {

    private static final int DUPLICATE_KEY = 2627;

    private static final int DUPLICATE_INDEX_KEY = 2601;

    private static final int CREATE_PERMISSION_DENIED = 262;

    private static final int OBJECT_PERMISSION_DENIED = 229;

    @Override
    public String getName() {
        return "sqlserver";
    }

    @Override
    public String getDisplayName() {
        return "SQL Server";
    }

    @Override
    public String now() {
        return "SYSUTCDATETIME()";
    }

    @Override
    public String plusSeconds(String time, String seconds) {
        return "DATEADD(second, " + seconds + ", " + time + ")";
    }

    @Override
    public String bool(boolean value) {
        return value ? "1" : "0";
    }

    @Override
    public String limit() {
        return " OFFSET 0 ROWS FETCH NEXT ? ROWS ONLY";
    }

    @Override
    public String lockingRead(String table) {
        return table + " WITH (UPDLOCK, ROWLOCK)";
    }

    @Override
    public String forUpdate() {
        return "";
    }

    @Override
    public String upsert(String table, List<String> keys, Map<String, String> values, String updates) {

        List<String> matches = new ArrayList<>();
        for (String key : keys)
            matches.add(table + "." + key + " = EXCLUDED." + key);

        List<String> inserted = new ArrayList<>();
        for (String column : values.keySet())
            inserted.add("EXCLUDED." + column);

        // HOLDLOCK keeps a concurrent MERGE from inserting the same key
        return "MERGE INTO " + table + " WITH (HOLDLOCK)"
                + " USING (VALUES (" + String.join(", ", values.values()) + "))"
                + " AS EXCLUDED (" + String.join(", ", values.keySet()) + ")"
                + " ON " + String.join(" AND ", matches)
                + " WHEN MATCHED THEN UPDATE SET " + updates
                + " WHEN NOT MATCHED THEN INSERT (" + String.join(", ", values.keySet()) + ")"
                + " VALUES (" + String.join(", ", inserted) + ");";

    }

    @Override
    public boolean isUniqueViolation(SQLException e) {
        return e.getErrorCode() == DUPLICATE_KEY || e.getErrorCode() == DUPLICATE_INDEX_KEY;
    }

    @Override
    public boolean isPermissionDenied(SQLException e) {
        return e.getErrorCode() == CREATE_PERMISSION_DENIED || e.getErrorCode() == OBJECT_PERMISSION_DENIED;
    }

    @Override
    public boolean hasTable(Connection connection, String table) throws SQLException {
        try (PreparedStatement statement = connection.prepareStatement(
                "SELECT CASE WHEN OBJECT_ID(?, 'U') IS NULL THEN 0 ELSE 1 END")) {
            statement.setString(1, table);
            try (ResultSet results = statement.executeQuery()) {
                return results.next() && results.getInt(1) == 1;
            }
        }
    }

    private static String resource(int namespace, int key) {
        return "pam." + namespace + "." + key;
    }

    @Override
    public boolean tryLock(Connection connection, int namespace, int key) throws SQLException {
        // sp_getapplock(@Resource, @LockMode, @LockOwner, @LockTimeout):
        // 0 or more once granted
        try (CallableStatement statement = connection.prepareCall("{? = call sp_getapplock(?, ?, ?, ?)}")) {
            statement.registerOutParameter(1, Types.INTEGER);
            statement.setString(2, resource(namespace, key));
            statement.setString(3, "Exclusive");
            statement.setString(4, "Session");
            statement.setInt(5, 0);
            statement.execute();
            return statement.getInt(1) >= 0;
        }
    }

    @Override
    public Set<Integer> getLocked(Connection connection, int namespace, Collection<Integer> keys)
            throws SQLException {

        // 0 if this session could not take it: another one holds it. A
        // column per key, in one query per part of them
        Set<Integer> locked = new HashSet<>();
        for (List<Integer> part : parts(keys)) {
            List<String> columns = new ArrayList<>();
            for (int i = 0; i < part.size(); i++)
                columns.add("APPLOCK_TEST('public', ?, 'Exclusive', 'Session')");
            try (PreparedStatement statement = connection.prepareStatement("SELECT " + String.join(", ", columns))) {
                for (int i = 0; i < part.size(); i++)
                    statement.setString(i + 1, resource(namespace, part.get(i)));
                try (ResultSet results = statement.executeQuery()) {
                    if (results.next()) {
                        for (int column = 0; column < part.size(); column++) {
                            if (results.getInt(column + 1) == 0)
                                locked.add(part.get(column));
                        }
                    }
                }
            }
        }

        return locked;

    }

    @Override
    public String getManualSchemaInstructions(String username) {
        return "Create them once as the database owner, by running schema/sqlserver.sql from the extension's"
                + " jar (\"unzip -p guacamole-pam-*.jar schema/sqlserver.sql > pam.sql; sqlcmd ... -i pam.sql\")."
                + " The roles of Guacamole's installation guide (db_datareader and db_datawriter) then cover"
                + " them; otherwise grant SELECT, INSERT, UPDATE and DELETE on the tables named pam_* to ["
                + username + "].";
    }

}
