package io.github.ialzamil.guacamole.pam.ha;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.SQLException;
import java.sql.Types;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.List;

/**
 * Small helpers for the SQL of this extension, which is the same on every
 * database but for its timestamps (see {@link DatabaseType}).
 */
final class Sql {

    /**
     * How many values an "IN (...)" lists at most, well within the limits
     * of every database.
     */
    static final int MAX_IN = 100;

    /**
     * A NULL of an integer column, which needs its type in PostgreSQL.
     */
    static final Object NULL_INTEGER = new Object();

    private Sql() {
    }

    /**
     * Runs an update with the given parameters: strings, integers, longs,
     * timestamps, booleans (as 0 or 1), null for a string, or
     * {@link #NULL_INTEGER}. Returns the rows changed.
     */
    static int update(Connection connection, String sql, Object... parameters) throws SQLException {
        try (PreparedStatement statement = connection.prepareStatement(sql)) {
            bind(statement, parameters);
            return statement.executeUpdate();
        }
    }

    static void bind(PreparedStatement statement, Object... parameters) throws SQLException {
        for (int i = 0; i < parameters.length; i++) {
            Object parameter = parameters[i];
            if (parameter == null)
                statement.setNull(i + 1, Types.VARCHAR);
            else if (parameter == NULL_INTEGER)
                statement.setNull(i + 1, Types.INTEGER);
            else if (parameter instanceof Boolean)
                statement.setInt(i + 1, (Boolean) parameter ? 1 : 0);
            else if (parameter instanceof Integer)
                statement.setInt(i + 1, (Integer) parameter);
            else if (parameter instanceof Long)
                statement.setLong(i + 1, (Long) parameter);
            else if (parameter instanceof java.sql.Timestamp)
                statement.setTimestamp(i + 1, (java.sql.Timestamp) parameter);
            else
                statement.setString(i + 1, parameter.toString());
        }
    }

    /**
     * "?, ?, ..." for the given number of values.
     */
    static String marks(int count) {
        return String.join(", ", Collections.nCopies(count, "?"));
    }

    /**
     * The given values in lists of at most {@link #MAX_IN}.
     */
    static <T> List<List<T>> chunks(Collection<T> values) {
        List<List<T>> chunks = new ArrayList<>();
        List<T> chunk = new ArrayList<>(MAX_IN);
        for (T value : values) {
            chunk.add(value);
            if (chunk.size() == MAX_IN) {
                chunks.add(chunk);
                chunk = new ArrayList<>(MAX_IN);
            }
        }
        if (!chunk.isEmpty())
            chunks.add(chunk);
        return chunks;
    }

    /**
     * The SHA-256 of a secret, in hexadecimal: what is stored of tokens and
     * share keys, so reading the database does not give them away.
     */
    static String sha256(String value) {
        try {
            byte[] digest = MessageDigest.getInstance("SHA-256").digest(value.getBytes(StandardCharsets.UTF_8));
            StringBuilder hex = new StringBuilder(digest.length * 2);
            for (byte b : digest)
                hex.append(Character.forDigit((b >> 4) & 0xF, 16)).append(Character.forDigit(b & 0xF, 16));
            return hex.toString();
        }
        catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 is not available.", e);
        }
    }

    /**
     * An integer identifier of Guacamole's own tables, or null if the given
     * one is not a number.
     */
    static Integer id(String identifier) {
        if (identifier == null)
            return null;
        try {
            return Integer.valueOf(identifier);
        }
        catch (NumberFormatException e) {
            return null;
        }
    }

}
