#!/bin/bash
# The test database, in the container myguacdbtest: PostgreSQL (the default),
# MySQL, MariaDB or SQL Server. Sourced by lab.sh, seed.sh and the test
# suites.
#
# PAM_DB chooses it (postgresql, mysql, mariadb or sqlserver) when lab.sh
# starts it; otherwise the running container's image tells.
# Each keeps its own data: PostgreSQL in lab/db, the others in podman
# volumes (pam-mysql-data, pam-mariadb-data, pam-sqlserver-data), created
# with Guacamole's schema and its guacadmin user on first start. MySQL,
# MariaDB and SQL Server run 3 hours ahead of UTC (unlike Guacamole), so
# tests would show the extension not storing times in UTC there.
#
#   PAM_DB              the database
#   PAM_DATA_SOURCE     Guacamole's data source for it (postgresql, mysql or
#                       sqlserver)
#   db_start            starts it, creating its schema if new
#   db_wait             waits until it answers
#   db_guacamole_env    the options ("-e", and "-v" on SQL Server) of a
#                       Guacamole container using it
#   db_reset            removes its data
#   sql QUERY           runs QUERY, printing rows with tab-separated values,
#                       NULL as empty
#   sql_now             SQL for the current time, as the extension stores it
#   sql_ago SECONDS     SQL for that many seconds ago
#   sql_in SECONDS      SQL for that many seconds from now

PAM_DB_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PAM_GUACAMOLE_IMAGE=docker.io/guacamole/guacamole:1.6.0

# Passwords of the test setup only
PAM_DB_PASSWORD=mysecretpassword
PAM_SQLSERVER_SA_PASSWORD='Pam-Test-Sa1!'
PAM_SQLSERVER_PASSWORD='Pam-Test-Guac1!'

if [ -z "$PAM_DB" ]; then
    case "$(podman inspect -f '{{.ImageName}}' myguacdbtest 2>/dev/null)" in
        *mysql*) PAM_DB=mysql;;
        *mariadb*) PAM_DB=mariadb;;
        *mssql*) PAM_DB=sqlserver;;
        *) PAM_DB=postgresql;;
    esac
fi

case "$PAM_DB" in
    postgresql|sqlserver) PAM_DATA_SOURCE=$PAM_DB;;
    mysql|mariadb) PAM_DATA_SOURCE=mysql;;
    *) echo "PAM_DB must be postgresql, mysql, mariadb or sqlserver, not \"$PAM_DB\"." >&2; exit 2;;
esac
# For the tools the suites start (tests/session.py, seed.sh)
export PAM_DB PAM_DATA_SOURCE

# The schema Guacamole's image creates for a database, made once
guacamole_schema() {
    local file="$PAM_DB_DIR/init/guacamole-$1.sql"
    [ -s "$file" ] || podman run --rm --entrypoint /opt/guacamole/bin/initdb.sh "$PAM_GUACAMOLE_IMAGE" "--$1" > "$file"
    printf '%s\n' "$file"
}

# Guacamole 1.6.0's SQL Server authentication does not start: two of its
# MyBatis mappers are not valid XML (<test> where <otherwise> belongs, and
# <hen> for <when>). Its jar, with those two fixed, made once
guacamole_sqlserver_jar() {
    local jar="$PAM_DB_DIR/init/guacamole-auth-jdbc-sqlserver-fixed.jar"
    local permissions=org/apache/guacamole/auth/jdbc/permission/UserGroupPermissionMapper.xml
    local records=org/apache/guacamole/auth/jdbc/connection/ConnectionRecordMapper.xml
    if [ ! -s "$jar" ]; then
        local work
        work=$(mktemp -d)
        podman run --rm --entrypoint cat "$PAM_GUACAMOLE_IMAGE" \
            /opt/guacamole/extensions/guacamole-auth-jdbc/sqlserver/guacamole-auth-jdbc-sqlserver.jar > "$work/auth.jar"
        (cd "$work" && unzip -q auth.jar "$permissions" "$records" \
            && sed -i 's|<test>|<otherwise>|; s|</test>|</otherwise>|' "$permissions" \
            && sed -i 's|<hen test=|<when test=|' "$records" \
            && zip -q auth.jar "$permissions" "$records") && mv "$work/auth.jar" "$jar"
        rm -rf "$work"
    fi
    printf '%s\n' "$jar"
}

sql() {
    case "$PAM_DB" in
        postgresql)
            podman exec myguacdbtest psql -U postgres -tA -F $'\t' -c "$1";;
        mysql|mariadb)
            # The extension stores times in UTC, as its sessions see them
            podman exec myguacdbtest "$([ "$PAM_DB" = mysql ] && echo mysql || echo mariadb)" \
                -uroot -p"$PAM_DB_PASSWORD" guacamole -N -B --raw \
                --init-command="SET time_zone = '+00:00'" -e "$1" 2>/dev/null | null_as_empty;;
        sqlserver)
            podman exec myguacdbtest /opt/mssql-tools18/bin/sqlcmd -C -S localhost -U sa \
                -P "$PAM_SQLSERVER_SA_PASSWORD" -d guacamole -b -y 0 -s $'\t' \
                -Q "SET NOCOUNT ON; $1" | null_as_empty;;
    esac
}

null_as_empty() { awk 'BEGIN { FS = OFS = "\t" } { for (i = 1; i <= NF; i++) if ($i == "NULL") $i = ""; print }'; }

sql_now() {
    case "$PAM_DB" in
        postgresql) echo "CURRENT_TIMESTAMP";;
        mysql|mariadb) echo "CURRENT_TIMESTAMP(3)";;
        sqlserver) echo "SYSUTCDATETIME()";;
    esac
}

sql_ago() {
    case "$PAM_DB" in
        postgresql) echo "(CURRENT_TIMESTAMP - make_interval(secs => $1))";;
        mysql|mariadb) echo "TIMESTAMPADD(SECOND, -$1, CURRENT_TIMESTAMP(3))";;
        sqlserver) echo "DATEADD(second, -$1, SYSUTCDATETIME())";;
    esac
}

sql_in() {
    case "$PAM_DB" in
        postgresql) echo "(CURRENT_TIMESTAMP + make_interval(secs => $1))";;
        mysql|mariadb) echo "TIMESTAMPADD(SECOND, $1, CURRENT_TIMESTAMP(3))";;
        sqlserver) echo "DATEADD(second, $1, SYSUTCDATETIME())";;
    esac
}

db_ready() {
    case "$PAM_DB" in
        postgresql)
            sql "SELECT 1" >/dev/null 2>&1;;
        mysql|mariadb)
            # Not the server creating a new database, listening on no port
            podman logs myguacdbtest 2>&1 | grep -q "port: 3306";;
        sqlserver)
            # Whether or not the database exists yet
            podman exec myguacdbtest /opt/mssql-tools18/bin/sqlcmd -C -S localhost -U sa \
                -P "$PAM_SQLSERVER_SA_PASSWORD" -b -Q "SELECT 1" >/dev/null 2>&1;;
    esac
}

db_wait() {
    local i
    for i in $(seq 90); do
        db_ready && return 0
        sleep 2
    done
    echo "The $PAM_DB database did not start." >&2
    return 1
}

db_start() {
    case "$PAM_DB" in
        postgresql)
            local init=()
            # A new database gets Guacamole's schema
            [ -z "$(ls -A "$PAM_DB_DIR/db/pgdata" 2>/dev/null)" ] \
                && init=(-v "$PAM_DB_DIR/init/initdb.sql:/docker-entrypoint-initdb.d/initdb.sql:Z")
            podman run --rm -d --name myguacdbtest --hostname myguacdbtest --net myguacnet \
                -e POSTGRES_PASSWORD="$PAM_DB_PASSWORD" \
                -e PGDATA=/var/lib/postgresql/data/pgdata \
                -v "$PAM_DB_DIR/db:/var/lib/postgresql/data:Z" "${init[@]}" \
                docker.io/postgres:18.4;;
        mysql|mariadb)
            local image=docker.io/library/mysql:8.4
            [ "$PAM_DB" = mariadb ] && image=docker.io/library/mariadb:11.4
            podman run --rm -d --name myguacdbtest --hostname myguacdbtest --net myguacnet \
                -e MYSQL_ROOT_PASSWORD="$PAM_DB_PASSWORD" -e MYSQL_DATABASE=guacamole \
                -e MYSQL_USER=guacamole -e MYSQL_PASSWORD="$PAM_DB_PASSWORD" \
                -v "pam-$PAM_DB-data:/var/lib/mysql" \
                -v "$(guacamole_schema mysql):/docker-entrypoint-initdb.d/guacamole.sql:Z" \
                "$image" --default-time-zone=+03:00;;
        sqlserver)
            podman run --rm -d --name myguacdbtest --hostname myguacdbtest --net myguacnet \
                -e ACCEPT_EULA=Y -e MSSQL_SA_PASSWORD="$PAM_SQLSERVER_SA_PASSWORD" -e TZ=Asia/Riyadh \
                -v pam-sqlserver-data:/var/opt/mssql \
                mcr.microsoft.com/mssql/server:2022-latest
            db_wait || return 1
            if [ "$(sql "SELECT 1" 2>/dev/null)" != 1 ]; then
                # New: the database, Guacamole's login owning it, the schema
                local schema
                schema=$(guacamole_schema sqlserver)
                podman exec myguacdbtest /opt/mssql-tools18/bin/sqlcmd -C -S localhost -U sa \
                    -P "$PAM_SQLSERVER_SA_PASSWORD" -b -Q "CREATE DATABASE guacamole;
                    CREATE LOGIN guacamole WITH PASSWORD = '$PAM_SQLSERVER_PASSWORD';" >/dev/null
                podman exec myguacdbtest /opt/mssql-tools18/bin/sqlcmd -C -S localhost -U sa \
                    -P "$PAM_SQLSERVER_SA_PASSWORD" -d guacamole -b -Q "CREATE USER guacamole FOR LOGIN guacamole;
                    ALTER ROLE db_owner ADD MEMBER guacamole;" >/dev/null
                podman cp "$schema" myguacdbtest:/tmp/guacamole.sql
                podman exec myguacdbtest /opt/mssql-tools18/bin/sqlcmd -C -S localhost -U sa \
                    -P "$PAM_SQLSERVER_SA_PASSWORD" -d guacamole -b -i /tmp/guacamole.sql >/dev/null
            fi;;
    esac
}

db_guacamole_env() {
    case "$PAM_DB" in
        postgresql)
            printf '%s\n' -e POSTGRESQL_HOSTNAME=myguacdbtest -e POSTGRESQL_DATABASE=postgres \
                -e POSTGRESQL_USERNAME=postgres -e POSTGRESQL_PASSWORD="$PAM_DB_PASSWORD";;
        mysql|mariadb)
            printf '%s\n' -e MYSQL_HOSTNAME=myguacdbtest -e MYSQL_DATABASE=guacamole \
                -e MYSQL_USERNAME=guacamole -e MYSQL_PASSWORD="$PAM_DB_PASSWORD";;
        sqlserver)
            printf '%s\n' -e SQLSERVER_HOSTNAME=myguacdbtest -e SQLSERVER_DATABASE=guacamole \
                -e SQLSERVER_USERNAME=guacamole -e SQLSERVER_PASSWORD="$PAM_SQLSERVER_PASSWORD" \
                -v "$(guacamole_sqlserver_jar):/opt/guacamole/extensions/guacamole-auth-jdbc/sqlserver/guacamole-auth-jdbc-sqlserver.jar:ro,Z";;
    esac
}

db_reset() {
    case "$PAM_DB" in
        postgresql) sudo rm -rf "${PAM_DB_DIR:?}/db/"*;;
        *) podman volume rm -f "pam-$PAM_DB-data" >/dev/null;;
    esac
}
