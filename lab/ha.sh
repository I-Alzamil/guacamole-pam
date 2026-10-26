#!/bin/bash
# The lab of the HA module: for each database, the database and two
# Guacamole servers sharing it, with the extension and "pam-ha" on, plus an
# SSH server for their sessions and a guacd for each server, recording where
# its server finds recordings (lab/ha-rec/a and lab/ha-rec/b). The servers
# also have the ban, TOTP and history recording storage extensions, whose
# state the module shares. Containers are named "mypamha-*", on their own
# network, apart from lab.sh's.
#
#   lab/ha.sh start DATABASE...   # postgresql, mysql, mariadb, sqlserver
#   lab/ha.sh stop [DATABASE...]  # every database if none is given
#   lab/ha.sh restart-server DATABASE a|b
#
# Guacamole's servers listen on localhost: 8090 and 8091 (PostgreSQL), 8092
# and 8093 (MySQL), 8094 and 8095 (MariaDB), 8096 and 8097 (SQL Server).
# Build the extension first (build.sh). With HA=off, servers start with the
# module off, to see tests/ha/run.sh fail as Guacamole alone does (one of
# each two then on standby for PAM). Stopping
# the last database running also removes the recordings.

set -e
cd "$(dirname "$0")"
source ./database.sh

NET=mypamhanet
REC=$PWD/ha-rec
DB_PASSWORD='Guac-Test-Pw1'
HA_SECRET='t2-pam-ha-secret'

# Failed logins before an address is banned, and for how long (seconds)
BAN_ATTEMPTS=3
BAN_SECONDS=20

port_of() {
    case "$1" in
        postgresql) echo 8090;; mysql) echo 8092;; mariadb) echo 8094;; sqlserver) echo 8096;;
        *) echo "Unknown database $1" >&2; exit 1;;
    esac
}

# The environment of Guacamole's database authentication for DATABASE
guacamole_env() {
    case "$1" in
        postgresql) echo "-e POSTGRESQL_HOSTNAME=mypamha-postgresql -e POSTGRESQL_DATABASE=guacamole
            -e POSTGRESQL_USER=guacamole -e POSTGRESQL_PASSWORD=$DB_PASSWORD";;
        mysql|mariadb) echo "-e MYSQL_HOSTNAME=mypamha-$1 -e MYSQL_DATABASE=guacamole
            -e MYSQL_USER=guacamole -e MYSQL_PASSWORD=$DB_PASSWORD";;
        sqlserver) echo "-e SQLSERVER_HOSTNAME=mypamha-sqlserver -e SQLSERVER_DATABASE=guacamole
            -e SQLSERVER_USER=sa -e SQLSERVER_PASSWORD=$DB_PASSWORD
            -e SQLSERVER_TRUST_ALL_SERVER_CERTIFICATES=true
            -v $(guacamole_sqlserver_jar):/opt/guacamole/extensions/guacamole-auth-jdbc/sqlserver/guacamole-auth-jdbc-sqlserver.jar:Z";;
    esac
}

running() { [ "$(podman inspect -f '{{.State.Running}}' "$1" 2>/dev/null)" = true ]; }

# wait_for DESCRIPTION SECONDS COMMAND...
wait_for() {
    local description=$1 seconds=$2; shift 2
    for _ in $(seq "$seconds"); do "$@" >/dev/null 2>&1 && return 0; sleep 1; done
    echo "Timed out waiting for $description" >&2; return 1
}

start_common() {
    podman network exists $NET || podman network create $NET >/dev/null
    local which
    for which in a b; do
        mkdir -p "$REC/$which" && chmod 777 "$REC/$which"
        running "mypamha-guacd-$which" || podman run --rm -d --name "mypamha-guacd-$which" --net $NET \
            -v "$REC/$which:/var/lib/guacamole/recordings:z" docker.io/guacamole/guacd:1.6.0 >/dev/null
    done
    running mypamha-ssh || podman run --rm -d --name mypamha-ssh --net $NET \
        -e USER_NAME=t2user -e USER_PASSWORD=t2-ssh-pw -e PASSWORD_ACCESS=true \
        docker.io/linuxserver/openssh-server:version-10.2_p1-r0 >/dev/null
}

start_database() {
    local db=$1 name=mypamha-$1 schema
    running "$name" && return 0
    case "$db" in
        postgresql)
            schema=$(guacamole_schema postgresql)
            podman run --rm -d --name "$name" --net $NET -e POSTGRES_DB=guacamole -e POSTGRES_USER=guacamole \
                -e POSTGRES_PASSWORD="$DB_PASSWORD" -v "$schema:/docker-entrypoint-initdb.d/init.sql:Z" \
                docker.io/library/postgres:18.4 >/dev/null
            wait_for "PostgreSQL" 60 podman exec "$name" psql -U guacamole -d guacamole -tAc \
                "SELECT 1 FROM guacamole_user LIMIT 1";;
        mysql|mariadb)
            schema=$(guacamole_schema mysql)
            local image=docker.io/library/mysql:8.4 client=mysql
            [ "$db" = mariadb ] && image=docker.io/library/mariadb:11.4 client=mariadb
            podman run --rm -d --name "$name" --net $NET -e MYSQL_ROOT_PASSWORD="$DB_PASSWORD" \
                -e MYSQL_DATABASE=guacamole -e MYSQL_USER=guacamole -e MYSQL_PASSWORD="$DB_PASSWORD" \
                -v "$schema:/docker-entrypoint-initdb.d/init.sql:Z" "$image" >/dev/null
            # Over TCP: the server the image runs while initializing only listens locally
            wait_for "$db" 120 podman exec "$name" $client -h127.0.0.1 --protocol=TCP -uguacamole \
                -p"$DB_PASSWORD" guacamole -e "SELECT 1 FROM guacamole_user LIMIT 1";;
        sqlserver)
            schema=$(guacamole_schema sqlserver)
            podman run --rm -d --name "$name" --net $NET -e ACCEPT_EULA=Y -e MSSQL_SA_PASSWORD="$DB_PASSWORD" \
                -v "$schema:/init.sql:Z" mcr.microsoft.com/mssql/server:2022-latest >/dev/null
            wait_for "SQL Server" 120 sqlserver_query "SELECT 1"
            sqlserver_query "IF DB_ID('guacamole') IS NULL CREATE DATABASE guacamole" >/dev/null
            podman exec "$name" /opt/mssql-tools18/bin/sqlcmd -C -S localhost -U sa -P "$DB_PASSWORD" \
                -d guacamole -b -i /init.sql >/dev/null;;
    esac
    disable_admin_totp "$db"
}

# db_query DATABASE SQL: runs SQL on the Guacamole database of DATABASE
db_query() {
    case "$1" in
        postgresql) podman exec mypamha-postgresql psql -U guacamole -d guacamole -tAc "$2";;
        mysql|mariadb) podman exec "mypamha-$1" "$([ "$1" = mariadb ] && echo mariadb || echo mysql)" \
            -uguacamole -p"$DB_PASSWORD" guacamole -N -e "$2" 2>/dev/null;;
        sqlserver) sqlserver_query "USE guacamole; $2";;
    esac
}

# guacadmin, which the tests administer with, logs in without TOTP
disable_admin_totp() {
    db_query "$1" "INSERT INTO guacamole_user_attribute (user_id, attribute_name, attribute_value)
        SELECT u.user_id, 'guac-totp-disabled', 'true' FROM guacamole_user u
        JOIN guacamole_entity e ON u.entity_id = e.entity_id WHERE e.name = 'guacadmin'" >/dev/null
}

sqlserver_query() {
    podman exec mypamha-sqlserver /opt/mssql-tools18/bin/sqlcmd -C -S localhost -U sa -P "$DB_PASSWORD" \
        -h -1 -W -Q "SET NOCOUNT ON; $1"
}

start_server() {
    local db=$1 which=$2 port jar
    port=$(port_of "$db"); [ "$which" = b ] && port=$((port + 1))
    local name=mypamha-$db-$which
    running "$name" && return 0
    jar=$(./extension-jar.sh) || exit 1
    # The server reads the recordings its guacd writes, readable by guacd's group
    # shellcheck disable=SC2046
    podman run --rm -d --name "$name" --net $NET -e GUACD_HOSTNAME="mypamha-guacd-$which" \
        -e WEBAPP_CONTEXT=ROOT $(guacamole_env "$db") -p "$port:8080" \
        -e BAN_ENABLED=true -e BAN_MAX_INVALID_ATTEMPTS=$BAN_ATTEMPTS -e BAN_ADDRESS_DURATION=$BAN_SECONDS \
        -e TOTP_ENABLED=true -e RECORDING_ENABLED=true -e REMOTE_IP_VALVE_ENABLED=true \
        -v "$REC/$which:/var/lib/guacamole/recordings:z" --group-add 1000 \
        -e PAM_HA="$([ "$HA" = off ] && echo false || echo true)" \
        -e PAM_HA_URL="http://$name:8080" -e PAM_HA_SECRET="$HA_SECRET" \
        -v "$jar:/opt/guacamole/extensions/guacamole-pam.jar:Z" \
        -v ./entrypoint.d/855-add-pam.sh:/opt/guacamole/entrypoint.d/855-add-pam.sh:Z \
        "$PAM_GUACAMOLE_IMAGE" >/dev/null
    wait_for "Guacamole on port $port" 120 curl -sf -o /dev/null "http://localhost:$port/api/languages"
}

stop_database() {
    local db=$1 other
    podman stop --ignore -t 5 "mypamha-$db-a" "mypamha-$db-b" "mypamha-$db" >/dev/null
    # A fresh database numbers its history from 1 again, which recordings
    # left by another would match: once no database's servers run, they go
    for other in postgresql mysql mariadb sqlserver; do
        running "mypamha-$other-a" && return 0
    done
    [ -d "$REC" ] && podman unshare find "$REC" -mindepth 2 -delete
    return 0
}

case "$1" in
    start)
        shift
        start_common
        for db in "$@"; do
            start_database "$db"
            start_server "$db" a
            start_server "$db" b
            echo "$db: http://localhost:$(port_of "$db") and http://localhost:$(($(port_of "$db") + 1))"
        done;;
    stop)
        shift
        for db in ${@:-postgresql mysql mariadb sqlserver}; do stop_database "$db"; done
        if [ $# -eq 0 ]; then
            podman stop --ignore -t 5 mypamha-guacd-a mypamha-guacd-b mypamha-ssh >/dev/null
            [ -d "$REC" ] && podman unshare rm -rf "$REC"
        fi;;
    restart-server)
        podman stop --ignore -t 10 "mypamha-$2-$3" >/dev/null
        podman wait "mypamha-$2-$3" >/dev/null 2>&1 || true
        start_server "$2" "$3";;
    *)
        sed -n '2,19p' "$0" | sed 's/^# \{0,1\}//'; exit 1;;
esac
