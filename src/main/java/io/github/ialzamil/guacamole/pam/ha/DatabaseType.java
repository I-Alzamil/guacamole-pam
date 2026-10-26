package io.github.ialzamil.guacamole.pam.ha;

import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.Calendar;
import java.util.Date;
import java.util.TimeZone;

/**
 * The databases Guacamole's database authentication supports, named by the
 * identifier of their data source, which is also the prefix of their
 * properties ("mysql-hostname", ...). Each knows the SQL its schema and
 * timestamps are written in. Timestamps are always the database's, never a
 * server's, so servers whose clocks differ still agree on which servers
 * were heard from lately.
 */
public enum DatabaseType {

    POSTGRESQL("postgresql", 5432, false) {

        @Override
        String now() {
            return "CURRENT_TIMESTAMP";
        }

        @Override
        String secondsAgo(int seconds) {
            return "CURRENT_TIMESTAMP - INTERVAL '" + seconds + " seconds'";
        }

    },

    /**
     * MySQL and MariaDB, whose timestamps are kept in UTC: their own depend
     * on the time zone of each database session.
     */
    MYSQL("mysql", 3306, true) {

        @Override
        String now() {
            return "UTC_TIMESTAMP(3)";
        }

        @Override
        String secondsAgo(int seconds) {
            return "UTC_TIMESTAMP(3) - INTERVAL " + seconds + " SECOND";
        }

    },

    /**
     * SQL Server, whose timestamps are kept in UTC, as for MySQL.
     */
    SQLSERVER("sqlserver", 1433, true) {

        @Override
        String now() {
            return "SYSUTCDATETIME()";
        }

        @Override
        String secondsAgo(int seconds) {
            return "DATEADD(second, -" + seconds + ", SYSUTCDATETIME())";
        }

    };

    private final String identifier;

    private final int defaultPort;

    /**
     * Whether timestamps are kept in UTC without a time zone, and read as
     * such.
     */
    private final boolean utc;

    DatabaseType(String identifier, int defaultPort, boolean utc) {
        this.identifier = identifier;
        this.defaultPort = defaultPort;
        this.utc = utc;
    }

    /**
     * The identifier of the data source of Guacamole's authentication for
     * this database, and the prefix of its properties.
     */
    public String getIdentifier() {
        return identifier;
    }

    int getDefaultPort() {
        return defaultPort;
    }

    /**
     * The name of a property of Guacamole's authentication for this
     * database, such as "mysql-hostname" for "hostname".
     */
    String property(String name) {
        return identifier + "-" + name;
    }

    /**
     * Classpath resource holding the schema of this extension's tables.
     */
    String getSchemaResource() {
        return "/schema/ha/" + identifier + ".sql";
    }

    /**
     * SQL for the current time, as stored in this extension's timestamps.
     */
    abstract String now();

    /**
     * SQL for the time the given number of seconds ago, comparable with
     * this extension's timestamps.
     */
    abstract String secondsAgo(int seconds);

    /**
     * A timestamp of this extension's tables, as read from the given
     * column, or null.
     */
    Date timestamp(ResultSet results, int column) throws SQLException {
        return utc ? results.getTimestamp(column, Calendar.getInstance(TimeZone.getTimeZone("UTC")))
                : results.getTimestamp(column);
    }

    /**
     * The type with the given data source identifier, or null.
     */
    public static DatabaseType forIdentifier(String identifier) {
        for (DatabaseType type : values()) {
            if (type.identifier.equals(identifier))
                return type;
        }
        return null;
    }

}
