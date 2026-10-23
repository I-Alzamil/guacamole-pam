#!/bin/bash
# Database platforms: PostgreSQL, MySQL, MariaDB and SQL Server accounts,
# rotated by an administrator account and by the account itself, over TLS
# with the server's certificate checked against the test CA, each new
# password checked with the database's own client. Also what each
# administrator needs, passwords kept out of the servers' statement logs,
# MySQL account hosts, untrusted certificates, and the Test button.

CA_PEM=$(cat "$(dirname "${BASH_SOURCE[0]}")/../../lab/targets/certs/ca.crt")

# db_platform NAME KIND HOST [ADMIN PASSWORD] [EXTRA-SETTINGS-JSON]: a
# Database platform, trusting the test CA unless the extra settings say
# otherwise
db_platform() {
    python3 -I - "$CA_PEM" "$@" <<'PY'
import json, sys
ca, name, kind, host = sys.argv[1:5]
admin = sys.argv[5] if len(sys.argv) > 5 else ''
password = sys.argv[6] if len(sys.argv) > 6 else ''
extra = json.loads(sys.argv[7]) if len(sys.argv) > 7 and sys.argv[7] else {}
settings = {"database-type": kind, "database-hostname": host, "database-ca-certificates": ca}
if admin:
    settings.update({"database-admin-username": admin, "database-admin-password": password})
settings.update(extra)
print(json.dumps({"name": name, "type": "database", "settings": settings, "policy": {}}))
PY
}

# db_account VARIABLE NAME PLATFORM USERNAME PASSWORD [ATTRIBUTES-JSON]
db_account() {
    create_connection "$1" "{\"name\":\"$2\",\"parentIdentifier\":\"ROOT\",\"protocol\":\"pam-account\",
        \"parameters\":{\"username\":\"$4\",\"password\":\"$5\"},\"attributes\":{\"pam-platform\":\"$3\"${6:+,$6}}}"
}

# ---------------------------------------------------------------- PostgreSQL
section "Database: PostgreSQL"

db_sql postgresql "CREATE ROLE t2db LOGIN PASSWORD 'T2-Db-Start1!'" >/dev/null
on_cleanup "db_sql postgresql 'DROP ROLE IF EXISTS t2db' >/dev/null; db_sql postgresql 'DROP ROLE IF EXISTS t2dbrot' >/dev/null"
check "precondition: test role created" yes "$(db_accepts postgresql t2db 'T2-Db-Start1!')"

create_platform PG_ADMIN "$(db_platform "t2 pg admin" postgresql mypgtarget postgres PgAdm1n-Pass)"
create_platform PG_SELF "$(db_platform "t2 pg self" postgresql mypgtarget)"
db_account PG_C "t2 pg" "$PG_ADMIN" t2db 'T2-Db-Start1!'

rotate_and_verify "$PG_C" "PostgreSQL, superuser" "db_accepts postgresql" t2db
use_platform "$PG_C" "$PG_SELF"; rotate_and_verify "$PG_C" "PostgreSQL, role itself" "db_accepts postgresql" t2db

# Logging every statement, to see what reaches the server
db_sql postgresql "ALTER SYSTEM SET log_statement = 'all'" >/dev/null; db_sql postgresql "SELECT pg_reload_conf()" >/dev/null
rotate "$PG_C" >/dev/null
NEW=$(parameter "$PG_C" password)
db_sql postgresql "ALTER SYSTEM RESET log_statement" >/dev/null; db_sql postgresql "SELECT pg_reload_conf()" >/dev/null
LOGGED=$(podman logs --since 1m mypgtarget 2>&1 | grep "ALTER ROLE CURRENT_USER")
check_contains "the server is given a SCRAM verifier" "PASSWORD 'SCRAM-SHA-256\$4096:" "$LOGGED"
check "...never the password itself" no "$(case "$LOGGED" in *"$NEW"*) echo yes;; *) echo no;; esac)"

db_sql postgresql "CREATE ROLE t2dbrot LOGIN CREATEROLE PASSWORD 'T2-Db-Rot1!'" >/dev/null
create_platform PG_ROT "$(db_platform "t2 pg createrole" postgresql mypgtarget t2dbrot 'T2-Db-Rot1!')"
use_platform "$PG_C" "$PG_ROT"; RESULT=$(rotate "$PG_C")
check_contains "CREATEROLE without the ADMIN option on the role: refused, saying so" \
    "the ADMIN option on the role" "$RESULT"
db_sql postgresql "GRANT t2db TO t2dbrot WITH ADMIN OPTION" >/dev/null
rotate_and_verify "$PG_C" "PostgreSQL, CREATEROLE with the ADMIN option" "db_accepts postgresql" t2db 1

# ---------------------------------------------------------------- MySQL
section "Database: MySQL"

db_sql mysql "CREATE USER 't2db'@'%' IDENTIFIED BY 'T2-Db-Start1!'"
on_cleanup "db_sql mysql \"DROP USER IF EXISTS 't2db'@'%', 't2dbhost'@'10.%', 't2dbrot'@'%'\""
check "precondition: test account created" yes "$(db_accepts mysql t2db 'T2-Db-Start1!')"

create_platform MY_ADMIN "$(db_platform "t2 mysql admin" mysql mymysqltarget root MyAdm1n-Pass)"
create_platform MY_SELF "$(db_platform "t2 mysql self" mysql mymysqltarget)"
db_account MY_C "t2 mysql" "$MY_ADMIN" t2db 'T2-Db-Start1!'

rotate_and_verify "$MY_C" "MySQL, root" "db_accepts mysql" t2db
use_platform "$MY_C" "$MY_SELF"; rotate_and_verify "$MY_C" "MySQL, account itself" "db_accepts mysql" t2db 1

db_sql mysql "SET PERSIST password_require_current = ON"
rotate_and_verify "$MY_C" "MySQL, account itself, with password_require_current" "db_accepts mysql" t2db 1
db_sql mysql "SET PERSIST password_require_current = OFF"

db_sql mysql "CREATE USER 't2dbrot'@'%' IDENTIFIED BY 'T2-Db-Rot1!'"
create_platform MY_ROT "$(db_platform "t2 mysql rotator" mysql mymysqltarget t2dbrot 'T2-Db-Rot1!')"
use_platform "$MY_C" "$MY_ROT"; RESULT=$(rotate "$MY_C")
check_contains "an administrator without CREATE USER: refused, saying so" "It needs CREATE USER." "$RESULT"
db_sql mysql "GRANT CREATE USER ON *.* TO 't2dbrot'@'%'"
rotate_and_verify "$MY_C" "MySQL, an administrator with CREATE USER only" "db_accepts mysql" t2db 1

# An account for another host than '%'
db_sql mysql "CREATE USER 't2dbhost'@'10.%' IDENTIFIED BY 'T2-Db-Host1!'"
db_account MYH_C "t2 mysql host" "$MY_ADMIN" t2dbhost 'T2-Db-Host1!' '"pam-database-account-host":"10.%"'
rotate_and_verify "$MYH_C" "MySQL, an account of host '10.%'" "db_accepts mysql" t2dbhost 1
edit_connection "$ADMIN" "$MYH_C" '' '{"pam-database-account-host":"192.0.2.1"}' >/dev/null
check_contains "...not found under another host, saying so" "'t2dbhost'@'192.0.2.1' does not exist" "$(rotate "$MYH_C")"

# ---------------------------------------------------------------- MariaDB
section "Database: MariaDB"

db_sql mariadb "CREATE USER 't2db'@'%' IDENTIFIED BY 'T2-Db-Start1!'"
on_cleanup "db_sql mariadb \"DROP USER IF EXISTS 't2db'@'%', 't2dbrot'@'%'\""
check "precondition: test account created" yes "$(db_accepts mariadb t2db 'T2-Db-Start1!')"

create_platform MA_ADMIN "$(db_platform "t2 mariadb admin" mysql mymariadbtarget root MariaAdm1n-Pass)"
create_platform MA_SELF "$(db_platform "t2 mariadb self" mysql mymariadbtarget)"
db_account MA_C "t2 mariadb" "$MA_ADMIN" t2db 'T2-Db-Start1!'

rotate_and_verify "$MA_C" "MariaDB, root" "db_accepts mariadb" t2db
use_platform "$MA_C" "$MA_SELF"; rotate_and_verify "$MA_C" "MariaDB, account itself (no privileges)" "db_accepts mariadb" t2db

db_sql mariadb "TRUNCATE mysql.general_log; SET GLOBAL log_output = 'TABLE'; SET GLOBAL general_log = ON"
rotate "$MA_C" >/dev/null
use_platform "$MA_C" "$MA_ADMIN"; rotate "$MA_C" >/dev/null
NEW=$(parameter "$MA_C" password)
db_sql mariadb "SET GLOBAL general_log = OFF"
LOGGED=$(db_sql mariadb "SELECT CONVERT(argument USING utf8) FROM mysql.general_log WHERE argument LIKE 'SET PASSWORD%'
    OR argument LIKE 'ALTER USER%'")
check_contains "the server is given password hashes" "IDENTIFIED BY PASSWORD '*" "$LOGGED"
check "...never the password itself, in its general log" no "$(case "$LOGGED" in *"$NEW"*) echo yes;; *) echo no;; esac)"
check "...yet it accepts it" yes "$(db_accepts mariadb t2db "$NEW")"

# Its authentication method is kept, rather than replaced by
# mysql_native_password, which MariaDB does unless told otherwise. MySQL
# Connector/J (the Docker image's driver) cannot sign in with ed25519, so
# such accounts are left unchanged: MariaDB Connector/J is needed for them
mariadb_plugin() { db_sql mariadb "SELECT JSON_VALUE(Priv, '\$.plugin') FROM mysql.global_priv WHERE User = '$1'"; }
db_sql mariadb "INSTALL SONAME 'auth_ed25519'" >/dev/null 2>&1
db_sql mariadb "CREATE USER 't2dbed'@'%' IDENTIFIED VIA ed25519 USING PASSWORD('T2-Db-Ed1!')"
on_cleanup "db_sql mariadb \"DROP USER IF EXISTS 't2dbed'@'%'\""
db_account MAE_C "t2 mariadb ed25519" "$MA_ADMIN" t2dbed 'T2-Db-Ed1!'
RESULT=$(rotate "$MAE_C")
check_contains "an ed25519 account, with MySQL Connector/J: refused before any change, saying which driver is needed" \
    "FAILED: Password unchanged. The account uses MariaDB's ed25519 authentication, which MySQL Connector/J cannot sign in with" "$RESULT"
check "...unchanged, still ed25519" "yes ed25519" "$(db_accepts mariadb t2dbed 'T2-Db-Ed1!') $(mariadb_plugin t2dbed)"
use_platform "$MAE_C" "$MA_SELF"
check_contains "...and as the account itself, which cannot sign in" "put MariaDB Connector/J (mariadb-java-client-*.jar) in GUACAMOLE_HOME/lib" \
    "$(rotate "$MAE_C")"
use_platform "$MAE_C" "$MA_ADMIN"

db_sql mariadb "CREATE USER 't2dbrot'@'%' IDENTIFIED BY 'T2-Db-Rot1!'; GRANT CREATE USER ON *.* TO 't2dbrot'@'%'"
create_platform MA_ROT "$(db_platform "t2 mariadb rotator" mysql mymariadbtarget t2dbrot 'T2-Db-Rot1!')"
use_platform "$MA_C" "$MA_ROT"; RESULT=$(rotate "$MA_C")
check_contains "an administrator unable to read accounts' methods: refused, saying what it needs" \
    "Grant the administrator account SELECT on mysql.global_priv." "$RESULT"
db_sql mariadb "GRANT SELECT ON mysql.global_priv TO 't2dbrot'@'%'"
rotate_and_verify "$MA_C" "MariaDB, CREATE USER and SELECT on mysql.global_priv" "db_accepts mariadb" t2db 1
use_platform "$MA_C" "$MA_ADMIN"

# ---------------------------------------------------------------- SQL Server
section "Database: SQL Server"

db_sql sqlserver "CREATE LOGIN t2db WITH PASSWORD = 'T2-Db-Start1!'" >/dev/null
on_cleanup "db_sql sqlserver \"DROP LOGIN t2db; DROP LOGIN t2dbsys; DROP LOGIN t2dbrot\" >/dev/null 2>&1"
check "precondition: test login created" yes "$(db_accepts sqlserver t2db 'T2-Db-Start1!')"

create_platform SQ_ADMIN "$(db_platform "t2 mssql admin" sqlserver mymssqltarget sa 'SqlAdm1n-Pass!')"
create_platform SQ_SELF "$(db_platform "t2 mssql self" sqlserver mymssqltarget)"
db_account SQ_C "t2 mssql" "$SQ_ADMIN" t2db 'T2-Db-Start1!'

rotate_and_verify "$SQ_C" "SQL Server, sa" "db_accepts sqlserver" t2db
use_platform "$SQ_C" "$SQ_SELF"; rotate_and_verify "$SQ_C" "SQL Server, login itself" "db_accepts sqlserver" t2db

db_sql sqlserver "CREATE LOGIN t2dbrot WITH PASSWORD = 'T2-Db-Rot1!'; GRANT ALTER ANY LOGIN TO t2dbrot;
    CREATE LOGIN t2dbsys WITH PASSWORD = 'T2-Db-Sys1!'; ALTER SERVER ROLE sysadmin ADD MEMBER t2dbsys" >/dev/null
create_platform SQ_ROT "$(db_platform "t2 mssql alter any login" sqlserver mymssqltarget t2dbrot 'T2-Db-Rot1!')"
use_platform "$SQ_C" "$SQ_ROT"; rotate_and_verify "$SQ_C" "SQL Server, ALTER ANY LOGIN" "db_accepts sqlserver" t2db 1
db_account SQS_C "t2 mssql sysadmin" "$SQ_ROT" t2dbsys 'T2-Db-Sys1!'
check_contains "a sysadmin login with ALTER ANY LOGIN only: refused, saying so" "a sysadmin login CONTROL SERVER" \
    "$(rotate "$SQS_C")"
check "...and unchanged" yes "$(db_accepts sqlserver t2dbsys 'T2-Db-Sys1!')"

# ---------------------------------------------------------------- trust
section "Database: certificates"

OTHER_CA=$(openssl req -x509 -newkey rsa:2048 -nodes -days 1 -subj "/CN=t2 other CA" -keyout /dev/null 2>/dev/null)
for target in "postgresql mypgtarget PG_C" "mysql mymysqltarget MY_C" "sqlserver mymssqltarget SQ_C"; do
    # Not "set --": suites share run.sh's arguments
    read -r kind host connection <<< "$target"
    create_platform OTHER "$(db_platform "t2 $kind other ca" "$kind" "$host" '' '' \
        "$(python3 -I -c 'import json,sys;print(json.dumps({"database-ca-certificates":sys.argv[1]}))' "$OTHER_CA")")"
    use_platform "${!connection}" "$OTHER"; RESULT=$(rotate "${!connection}")
    check_contains "$kind: a certificate of another CA: rotation fails, untrusted" "FAILED: Password unchanged. Unable to trust" "$RESULT"
    create_platform UNVERIFIED "$(db_platform "t2 $kind unverified" "$kind" "$host" '' '' \
        '{"database-encryption":"unverified","database-ca-certificates":""}')"
    use_platform "${!connection}" "$UNVERIFIED"; RESULT=$(rotate "${!connection}")
    check "$kind: ...accepted unverified" SUCCESS "${RESULT%%:*}"
    # Back on a platform created before it, deleted after it at cleanup
    use_platform "${!connection}" "$PG_SELF"
done

# ---------------------------------------------------------------- JDBC URLs
section "Database: driver options in hostnames and database names"

# Written into JDBC URLs, they would set other options of the driver, such
# as MySQL's reading of local files for the server
RESULT=$(api POST "$PAM/platforms" "$ADMIN" "$(db_platform "t2 mysql url host" mysql \
    'mymysqltarget:3306/x?allowLoadLocalInfile=true&' root MyAdm1n-Pass)")
check_contains "options after the hostname: refused" "Invalid database hostname" "$(message_of "$RESULT")"
RESULT=$(api POST "$PAM/platforms" "$ADMIN" "$(db_platform "t2 mysql url database" mysql mymysqltarget root \
    MyAdm1n-Pass '{"database-name":"x?allowLoadLocalInfile=true"}')")
check_contains "options after the database name: refused" "Invalid database name" "$(message_of "$RESULT")"
RESULT=$(api POST "$PAM/platforms/test" "$ADMIN" "$(db_platform "t2 mssql url host" sqlserver \
    'mymssqltarget;trustServerCertificate=true' sa 'SqlAdm1n-Pass!')")
check_contains "...nor tested" "Invalid database hostname" "$(message_of "$RESULT")"
check "...and none was created" "" "$(platform_id "t2 mysql url host")$(platform_id "t2 mysql url database")"

# ---------------------------------------------------------------- Test button
section "Database: testing platforms"

summary() {
    json_get "${1#* }" "('passed' if d['success'] else 'failed') + ': ' + ' | '.join(s['status'] + ' ' + s['text'] for s in d['steps'])"
}
test_db() { summary "$(api POST "$PAM/platforms/test" "$ADMIN" "$(db_platform "t2 test db" "$@")")"; }

check_contains "PostgreSQL superuser: passed" "passed: PASSED The administrator account \"postgres\" signed in to the PostgreSQL server mypgtarget:5432" \
    "$(test_db postgresql mypgtarget postgres PgAdm1n-Pass)"
check_contains "...over TLS, its certificate checked, as a superuser" "over TLS, its certificate checked. | PASSED It is a superuser" \
    "$(test_db postgresql mypgtarget postgres PgAdm1n-Pass)"
check_contains "PostgreSQL CREATEROLE: passed, naming the ADMIN option" "PASSED It has CREATEROLE. Since PostgreSQL 16" \
    "$(test_db postgresql mypgtarget t2dbrot 'T2-Db-Rot1!')"
check_contains "a wrong administrator password: failed" "failed: FAILED The PostgreSQL server mypgtarget:5432 refused the administrator account" \
    "$(test_db postgresql mypgtarget postgres wrong)"
check "without an administrator: passed, as unknown accounts are refused" \
    "passed: PASSED The MySQL or MariaDB server mymysqltarget:3306 answers over TLS, its certificate checked, and refuses unknown accounts. | INFO No administrator account: each account changes its own password." \
    "$(test_db mysql mymysqltarget)"
db_sql mysql "REVOKE CREATE USER ON *.* FROM 't2dbrot'@'%'"
check_contains "MySQL without CREATE USER: failed, saying so" "FAILED It lacks CREATE USER" "$(test_db mysql mymysqltarget t2dbrot 'T2-Db-Rot1!')"
check_contains "SQL Server ALTER ANY LOGIN: passed, except sysadmin logins" "PASSED It has ALTER ANY LOGIN, so it may change logins' passwords, except those of sysadmin logins" \
    "$(test_db sqlserver mymssqltarget t2dbrot 'T2-Db-Rot1!')"
check_contains "an unknown server: failed" "failed: FAILED Unable to connect to the SQL Server server t2-no-such-host:1433" \
    "$(test_db sqlserver t2-no-such-host sa x)"
