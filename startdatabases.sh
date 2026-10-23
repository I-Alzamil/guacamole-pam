#!/bin/bash
# Start the databases to test Database password rotation against, over TLS
# with certificates of a test CA naming each server (generated the first
# time into podman/targets/certs, the CA certificate being ca.crt there):
#   mypgtarget       PostgreSQL 18, port 5432, admin "postgres" / "PgAdm1n-Pass"
#   mymysqltarget    MySQL 8.4,     port 3306, admin "root" / "MyAdm1n-Pass"
#   mymariadbtarget  MariaDB 11.4,  port 3306, admin "root" / "MariaAdm1n-Pass"
#   mymssqltarget    SQL Server 2022, port 1433, admin "sa" / "SqlAdm1n-Pass!"
# Each has a test account "dbtest" / "P@ssw0rd-Db1" ('dbtest'@'%' on MySQL and
# MariaDB). These are not Guacamole's own database.
cd "$(dirname "$0")" || exit 1
CERTS=podman/targets/certs
TARGETS="mypgtarget mymysqltarget mymariadbtarget mymssqltarget"

# The test CA, and a certificate for each server
mkdir -p "$CERTS"
if [ ! -s "$CERTS/ca.crt" ]; then
    openssl req -x509 -newkey rsa:2048 -nodes -days 3650 -subj "/CN=guacamole-pam test CA" \
        -keyout "$CERTS/ca.key" -out "$CERTS/ca.crt" 2>/dev/null || exit 1
fi
for host in $TARGETS; do
    [ -s "$CERTS/$host.crt" ] && continue
    openssl req -newkey rsa:2048 -nodes -subj "/CN=$host" -keyout "$CERTS/$host.key" -out "$CERTS/$host.csr" 2>/dev/null
    openssl x509 -req -in "$CERTS/$host.csr" -CA "$CERTS/ca.crt" -CAkey "$CERTS/ca.key" -CAcreateserial -days 3650 \
        -extfile <(printf 'subjectAltName=DNS:%s\nextendedKeyUsage=serverAuth\n' "$host") -out "$CERTS/$host.crt" 2>/dev/null
    rm -f "$CERTS/$host.csr"
done
# Read by each server's own user, so world-readable: test keys only
chmod 644 "$CERTS"/*.key

running() { [ "$(podman inspect -f '{{.State.Running}}' "$1" 2>/dev/null)" = true ]; }

# Copies the certificate where the server's own user can read it, then
# starts the server as the image would
copy_certs='mkdir -p /etc/pam-certs && cp /certs/ca.crt /certs/$HOST.crt /certs/$HOST.key /etc/pam-certs/ && chown -R $OWNER /etc/pam-certs && chmod 600 /etc/pam-certs/$HOST.key'

running mypgtarget || podman run --rm -d --name mypgtarget --hostname mypgtarget --net myguacnet \
    -e POSTGRES_PASSWORD='PgAdm1n-Pass' -e HOST=mypgtarget -e OWNER=postgres -v "./$CERTS:/certs:ro,Z" \
    --entrypoint bash docker.io/library/postgres:18.4 -c "$copy_certs && exec docker-entrypoint.sh postgres \
        -c ssl=on -c ssl_cert_file=/etc/pam-certs/mypgtarget.crt -c ssl_key_file=/etc/pam-certs/mypgtarget.key" >/dev/null

running mymysqltarget || podman run --rm -d --name mymysqltarget --hostname mymysqltarget --net myguacnet \
    -e MYSQL_ROOT_PASSWORD='MyAdm1n-Pass' -e HOST=mymysqltarget -e OWNER=mysql -v "./$CERTS:/certs:ro,Z" \
    --entrypoint bash docker.io/library/mysql:8.4 -c "$copy_certs && exec docker-entrypoint.sh mysqld \
        --ssl-ca=/etc/pam-certs/ca.crt --ssl-cert=/etc/pam-certs/mymysqltarget.crt \
        --ssl-key=/etc/pam-certs/mymysqltarget.key" >/dev/null

running mymariadbtarget || podman run --rm -d --name mymariadbtarget --hostname mymariadbtarget --net myguacnet \
    -e MARIADB_ROOT_PASSWORD='MariaAdm1n-Pass' -e HOST=mymariadbtarget -e OWNER=mysql -v "./$CERTS:/certs:ro,Z" \
    --entrypoint bash docker.io/library/mariadb:11.4 -c "$copy_certs && exec docker-entrypoint.sh mariadbd \
        --ssl-ca=/etc/pam-certs/ca.crt --ssl-cert=/etc/pam-certs/mymariadbtarget.crt \
        --ssl-key=/etc/pam-certs/mymariadbtarget.key" >/dev/null

# SQL Server runs as its own user from the start: its certificate is read
# where it is mounted
printf '[network]\ntlscert = /certs/mymssqltarget.crt\ntlskey = /certs/mymssqltarget.key\ntlsprotocols = 1.2\nforceencryption = 0\n' \
    > podman/targets/mssql.conf
running mymssqltarget || podman run --rm -d --name mymssqltarget --hostname mymssqltarget --net myguacnet \
    -e ACCEPT_EULA=Y -e MSSQL_SA_PASSWORD='SqlAdm1n-Pass!' -v "./$CERTS:/certs:ro,Z" \
    -v ./podman/targets/mssql.conf:/var/opt/mssql/mssql.conf:ro,Z mcr.microsoft.com/mssql/server:2022-latest >/dev/null

# Wait for each, then add its test account (unless present)
pg() { podman exec mypgtarget psql -U postgres -tAq -c "$1"; }
my() { podman exec mymysqltarget mysql -uroot -pMyAdm1n-Pass -N -e "$1" 2>/dev/null; }
ma() { podman exec mymariadbtarget mariadb -uroot -pMariaAdm1n-Pass -N -e "$1" 2>/dev/null; }
sq() { podman exec mymssqltarget /opt/mssql-tools18/bin/sqlcmd -C -S localhost -U sa -P 'SqlAdm1n-Pass!' -h -1 -b \
    -Q "SET NOCOUNT ON; $1" 2>/dev/null; }

until [ "$(pg 'SELECT 1' 2>/dev/null)" = 1 ] && podman logs mypgtarget 2>&1 | grep -q "PostgreSQL init process complete\|ready to accept connections"; do sleep 2; done
until podman logs mymysqltarget 2>&1 | grep -q "port: 3306" && [ "$(my 'SELECT 1')" = 1 ]; do sleep 2; done
until [ "$(ma 'SELECT 1')" = 1 ]; do sleep 2; done
until [ "$(sq 'SELECT 1' | tr -d ' ')" = 1 ]; do sleep 2; done

pg "DO \$\$ BEGIN IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'dbtest') THEN
    CREATE ROLE dbtest LOGIN PASSWORD 'P@ssw0rd-Db1'; END IF; END \$\$"
my "CREATE USER IF NOT EXISTS 'dbtest'@'%' IDENTIFIED BY 'P@ssw0rd-Db1'"
ma "CREATE USER IF NOT EXISTS 'dbtest'@'%' IDENTIFIED BY 'P@ssw0rd-Db1'"
sq "IF SUSER_ID('dbtest') IS NULL CREATE LOGIN dbtest WITH PASSWORD = 'P@ssw0rd-Db1'"
echo "Test databases ready: $TARGETS"
