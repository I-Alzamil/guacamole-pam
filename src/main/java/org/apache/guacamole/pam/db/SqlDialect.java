package org.apache.guacamole.pam.db;

import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Timestamp;
import java.util.Calendar;
import java.util.Collection;
import java.util.Collections;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TimeZone;

/**
 * What SQL is written differently on each database Guacamole stores its data
 * in: PostgreSQL, MySQL (or MariaDB) and SQL Server. Everything else is
 * written once, in SQL all of them accept.
 *
 * Times are taken from the database's clock, so Guacamole servers sharing it
 * agree on them. Where the column type has no time zone (MySQL, SQL Server),
 * they are stored in UTC, and are read with {@link #getTimestamp}.
 */
public abstract class SqlDialect {

    private static final TimeZone UTC = TimeZone.getTimeZone("UTC");

    /**
     * Name of the database, and of the identifier and properties prefix of
     * Guacamole's authentication storing data in it: "postgresql", "mysql"
     * or "sqlserver".
     */
    public abstract String getName();

    /**
     * Name of the database, as shown to administrators.
     */
    public abstract String getDisplayName();

    /**
     * The current time.
     */
    public abstract String now();

    /**
     * A time shifted by a number of seconds, given as an expression (usually
     * a parameter, "?").
     */
    public abstract String plusSeconds(String time, String seconds);

    /**
     * A boolean literal, as compared with boolean columns.
     */
    public abstract String bool(boolean value);

    /**
     * Ends a query sorted by ORDER BY, keeping only as many rows as the last
     * parameter says.
     */
    public abstract String limit();

    /**
     * The table to read in a SELECT locking the rows it reads until the end
     * of the transaction, which {@link #forUpdate} ends.
     */
    public String lockingRead(String table) {
        return table;
    }

    /**
     * Ends a SELECT locking the rows it reads (see {@link #lockingRead}).
     */
    public String forUpdate() {
        return " FOR UPDATE";
    }

    /**
     * Inserts a row, or updates the row with the same key.
     *
     * @param values
     *     Every column inserted and its value, as an expression.
     *
     * @param updates
     *     What to set if the row exists, as "column = expression, ...",
     *     where "EXCLUDED.column" is the value that would have been inserted
     *     and "table.column" the existing value.
     */
    public abstract String upsert(String table, List<String> keys, Map<String, String> values, String updates);

    /**
     * Whether the error is a violation of a unique index or key.
     */
    public abstract boolean isUniqueViolation(SQLException e);

    /**
     * Whether the error is a refusal by lack of privilege, such as to create
     * a table.
     */
    public abstract boolean isPermissionDenied(SQLException e);

    /**
     * Whether a table of that name exists, where the database user's
     * unqualified names lead.
     */
    public abstract boolean hasTable(Connection connection, String table) throws SQLException;

    /**
     * Takes a lock held by the connection's database session until the
     * connection closes, unless another session holds it. Locks are
     * identified by two numbers: a namespace and a key within it.
     *
     * @return
     *     Whether the lock was taken.
     */
    public abstract boolean tryLock(Connection connection, int namespace, int key) throws SQLException;

    /**
     * Returns the keys among the given ones whose lock (see {@link #tryLock})
     * any session holds.
     */
    public abstract Set<Integer> getLocked(Connection connection, int namespace, Collection<Integer> keys)
            throws SQLException;

    /**
     * How a database owner creates the tables by hand, and grants them to
     * the given database user.
     */
    public abstract String getManualSchemaInstructions(String username);

    /**
     * The first line of an error message: some databases add details on
     * further lines.
     */
    public static String firstLine(String message) {
        if (message == null)
            return "";
        int end = message.indexOf('\n');
        return end < 0 ? message : message.substring(0, end);
    }

    /**
     * Reads a time written by {@link #now}.
     */
    public static Timestamp getTimestamp(ResultSet results, int column) throws SQLException {
        return results.getTimestamp(column, Calendar.getInstance(UTC));
    }

    /**
     * Reads a time written by {@link #now}.
     */
    public static Timestamp getTimestamp(ResultSet results, String column) throws SQLException {
        return results.getTimestamp(column, Calendar.getInstance(UTC));
    }

    /**
     * Lists numbers for "IN": "(1, 2, 3)", or "(NULL)", matching nothing.
     * Being numbers, they are safe to write into the statement, which holds
     * any number of them, unlike parameters.
     */
    public static String in(Collection<Integer> numbers) {
        if (numbers.isEmpty())
            return "(NULL)";
        StringBuilder list = new StringBuilder("(");
        for (Iterator<Integer> i = numbers.iterator(); i.hasNext(); ) {
            list.append(i.next().intValue());
            if (i.hasNext())
                list.append(", ");
        }
        return list.append(")").toString();
    }

    /**
     * Parameters for "IN": "(?, ?, ?)" for three, or "(NULL)" for none.
     */
    public static String parameters(int count) {
        return count == 0 ? "(NULL)" : "(" + String.join(", ", Collections.nCopies(count, "?")) + ")";
    }

}
