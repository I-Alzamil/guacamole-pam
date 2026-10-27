#!/bin/bash
# The test lab: Guacamole with the extension, and the servers it manages, in
# podman containers on the network "myguacnet". For development only: every
# password is a fixed test one. Build the jar first with build.sh.
#
#   lab.sh app [--ha|--ha=off]
#       (Re)starts Guacamole's database, guacd and Guacamole with the built
#       jar, on http://localhost:8080. --ha also starts a second Guacamole
#       sharing them, on http://localhost:8081, with the HA module on in
#       both (tests/suites/40-servers.sh); --ha=off starts both with it off,
#       as PAM alone shares them. Given alone, either restarts both servers
#       that way, keeping the database and guacd running.
#   lab.sh services
#       Starts the servers seed.sh and the suites manage accounts on, keeping
#       those already running:
#         mysshtest        SSH, user "mysshtest" / "P@ssw0rd", with a host
#                          certificate of a test SSH CA (lab/targets/certs/
#                          ssh_ca.pub)
#         myldaptest       OpenLDAP, "uid=ldaptest,ou=people,dc=example,dc=org"
#                          / "P@ssw0rd", admin "cn=admin,dc=example,dc=org" /
#                          "LdapAdm1n"
#         myadtest         Samba AD, realm AD.EXAMPLE.ORG, "adtest" /
#                          "P@ssw0rd-AD1", admin "Administrator" / "AdAdm1n-Pass"
#         mykdctest        MIT Kerberos KDC, realm EXAMPLE.ORG, "kdctest" /
#                          "P@ssw0rd-KDC1", admin "admin/admin" / "KdcAdm1n-Pass"
#         mytacacstest     tac_plus-ng, shared secret "TacacsSecr3t", "tactest" /
#                          "P@ssw0rd-Tac1"
#         mypgtarget       PostgreSQL 18, admin "postgres" / "PgAdm1n-Pass"
#         mymysqltarget    MySQL 8.4, admin "root" / "MyAdm1n-Pass"
#         mymariadbtarget  MariaDB 11.4, admin "root" / "MariaAdm1n-Pass"
#         mymssqltarget    SQL Server 2022, admin "sa" / "SqlAdm1n-Pass!"
#       The databases (not Guacamole's own) use TLS with certificates of a
#       test CA, generated the first time into lab/targets/certs (ca.crt
#       there), and each has an account "dbtest" / "P@ssw0rd-Db1".
#         mysyslogtest     syslog receiver: TLS on 6514 (a certificate of the
#                          same CA), TCP and UDP on 514, writing what it
#                          receives to /tmp/tls.log, tcp.log and udp.log
#         mymailtest       Mailpit mail server: SMTP on 1025 requiring
#                          STARTTLS (a certificate of the same CA) and the
#                          login "pammail" / "P@ssw0rd-Mail1"; what it
#                          receives at http://localhost:8025/api/v1/ inside
#   lab.sh seed
#       Adds the test platforms, connections, users and group (seed.sh).
#   lab.sh reset
#       Recreates Guacamole's database with only Guacamole's schema and
#       guacadmin / guacadmin, stopping Guacamole.
#   lab.sh stop
#       Stops every container of the lab.
#
# Commands run in the order given: "lab.sh reset app services seed"
# starts afresh.
#
# Guacamole's database is PostgreSQL unless PAM_DB says mysql, mariadb or
# sqlserver when it is started (see database.sh). Stored secrets are
# encrypted with a fixed test key; set PAM_ENCRYPTION_KEY= to store them
# unencrypted.

cd "$(dirname "$0")" || exit 1
source ./database.sh

PAM_TEST_ENCRYPTION_KEY="${PAM_ENCRYPTION_KEY-um/hqZa6cc89CtHmc9vYOuoDd8S1jY8IaASlz5S00iY=}"
LAB_CONTAINERS="myguactest myguactest2 myguacdtest myguacdbtest mysshtest myldaptest myadtest mykdctest
    mytacacstest mypgtarget mymysqltarget mymariadbtarget mymssqltarget mysyslogtest mymailtest"

running() { [ "$(podman inspect -f '{{.State.Running}}' "$1" 2>/dev/null)" = true ]; }

# Stops the given containers, if running
stop() { podman stop --ignore "$@" >/dev/null; }

# Starts a Guacamole server with the extension: NAME PORT
run_guacamole() {
    local jar
    jar=$(./extension-jar.sh) || { echo "Build the jar first with build.sh." >&2; return 1; }
    mapfile -t DB_ENV < <(db_guacamole_env)
    podman run --rm -d \
        --name "$1" \
        --hostname "$1" \
        --net myguacnet \
        -e GUACD_HOSTNAME=myguacdtest \
        "${DB_ENV[@]}" \
        -e WEBAPP_CONTEXT=ROOT \
        -e PAM_ENCRYPTION_KEY="$PAM_TEST_ENCRYPTION_KEY" \
        -e PAM_HA=$ha_module -e PAM_HA_URL="http://$1:8080" -e PAM_HA_SECRET=t2-pam-ha-secret \
        -p "$2":8080 \
        -v "$jar":/opt/guacamole/extensions/guacamole-pam.jar:Z \
        -v ./entrypoint.d/855-add-pam.sh:/opt/guacamole/entrypoint.d/855-add-pam.sh:Z \
        "$PAM_GUACAMOLE_IMAGE" >/dev/null
}

start_guacamole() {
    ./extension-jar.sh >/dev/null || { echo "Build the jar first with build.sh." >&2; return 1; }
    stop myguactest myguactest2 myguacdtest myguacdbtest
    db_start >/dev/null || return 1
    db_wait || return 1
    podman run --rm -d \
        --name myguacdtest \
        --hostname myguacdtest \
        --net myguacnet \
        docker.io/guacamole/guacd:1.6.0 >/dev/null || return 1
    run_guacamole myguactest 8080 && echo "Guacamole: http://localhost:8080 ($PAM_DB$ha_note)"
}

# Waits until the Guacamole server on PORT answers
wait_up() {
    for _ in $(seq 120); do curl -sf -o /dev/null "http://localhost:$1/api/languages" && return 0; sleep 1; done
    echo "Guacamole on port $1 did not start." >&2; return 1
}

start_second() {
    stop myguactest2
    # Without the HA module, the first server to start works and the other
    # is on standby: the first one, as on port 8080
    [ "$ha_module" = true ] || wait_up 8080 || return 1
    run_guacamole myguactest2 8081 && echo "Second Guacamole: http://localhost:8081${ha_note:+ (${ha_note#, })}"
}

# Both servers again, as --ha or --ha=off says, on the database and guacd
# already running
restart_ha() {
    running myguacdbtest && running myguacdtest || { echo "Start the lab first: lab.sh app --ha." >&2; return 1; }
    stop myguactest myguactest2
    run_guacamole myguactest 8080 && echo "Guacamole: http://localhost:8080 ($PAM_DB$ha_note)" && start_second
}

reset() {
    stop myguactest myguactest2 myguacdtest myguacdbtest
    db_reset
    db_start >/dev/null && db_wait && echo "Guacamole's $PAM_DB database recreated."
}

# SSH server. sshd runs as an unprivileged user in this image, so the
# container is allowed to bind ports below 1024 (in its own network
# namespace only)
start_ssh() {
    running mysshtest && { certify_ssh; return; }
    podman run --rm -d \
        --name mysshtest \
        --hostname mysshtest \
        --net myguacnet \
        --sysctl net.ipv4.ip_unprivileged_port_start=0 \
        -e PUID=1000 \
        -e PGID=1000 \
        -e PASSWORD_ACCESS=true \
        -e LISTEN_PORT=22 \
        -e USER_NAME=mysshtest \
        -e USER_PASSWORD=P@ssw0rd \
        docker.io/linuxserver/openssh-server:version-10.2_p1-r0 >/dev/null || return 1
    certify_ssh
}

# A host certificate for mysshtest's ECDSA key, which it then presents to
# clients asking for one, signed by a test SSH CA generated the first time
# into lab/targets/certs (ssh_ca.pub there)
certify_ssh() {
    local certs=targets/certs keys=/config/ssh_host_keys
    mkdir -p "$certs"
    [ -s "$certs/ssh_ca" ] || ssh-keygen -q -t ed25519 -N '' -C "guacamole-pam test SSH CA" -f "$certs/ssh_ca" \
        || return 1
    podman exec mysshtest test -s "$keys/ssh_host_ecdsa_key-cert.pub" && return 0
    # The image generates its host keys as it starts
    for _ in $(seq 30); do podman exec mysshtest test -s /config/sshd.pid && break; sleep 1; done
    podman cp "mysshtest:$keys/ssh_host_ecdsa_key.pub" "$certs/mysshtest_ecdsa.pub" || return 1
    ssh-keygen -q -s "$certs/ssh_ca" -I mysshtest -h -n mysshtest "$certs/mysshtest_ecdsa.pub" || return 1
    podman cp "$certs/mysshtest_ecdsa-cert.pub" "mysshtest:$keys/ssh_host_ecdsa_key-cert.pub" || return 1
    podman exec mysshtest sh -c "chmod 644 $keys/ssh_host_ecdsa_key-cert.pub
        grep -q '^HostCertificate' /config/sshd/sshd_config \
            || echo 'HostCertificate $keys/ssh_host_ecdsa_key-cert.pub' >> /config/sshd/sshd_config
        kill -HUP \$(cat /config/sshd.pid)"
}

# OpenLDAP server, port 389 (StartTLS) and 636 (LDAPS) with a self-signed
# certificate
start_ldap() {
    running myldaptest && return 0
    podman run --rm -d \
        --name myldaptest \
        --hostname myldaptest \
        --net myguacnet \
        -e LDAP_ORGANISATION="Example" \
        -e LDAP_DOMAIN="example.org" \
        -e LDAP_ADMIN_PASSWORD=LdapAdm1n \
        -e LDAP_TLS_VERIFY_CLIENT=never \
        docker.io/osixia/openldap:1.5.0 >/dev/null || return 1

    # The image runs slapd once to set itself up, then again for good
    until podman logs myldaptest 2>&1 | grep -q "Running /container/run/process/slapd/run"; do sleep 1; done
    until podman exec myldaptest ldapsearch -x -H ldap://localhost -b dc=example,dc=org \
        -D cn=admin,dc=example,dc=org -w LdapAdm1n -s base >/dev/null 2>&1; do sleep 1; done
    podman exec -i myldaptest ldapadd -x -H ldap://localhost -D cn=admin,dc=example,dc=org -w LdapAdm1n >/dev/null <<'LDIF'
dn: ou=people,dc=example,dc=org
objectClass: organizationalUnit
ou: people

dn: uid=ldaptest,ou=people,dc=example,dc=org
objectClass: inetOrgPerson
uid: ldaptest
cn: LDAP Test
sn: Test
userPassword: P@ssw0rd
LDIF
}

# Waits until Samba answers LDAPS. The image's own ldapsearch is a wrapper
# that already passes a password file, so the real one is used, and Samba's
# certificate is self-signed.
wait_for_samba() {
    until podman exec -e LDAPTLS_REQCERT=never myadtest /usr/bin/ldapsearch -x -H ldaps://localhost \
        -D 'Administrator@ad.example.org' -w AdAdm1n-Pass -b DC=ad,DC=example,DC=org -s base >/dev/null 2>&1; do
        sleep 2
    done
}

# Samba Active Directory domain controller: LDAPS port 636, Kerberos KDC
# port 88 and kpasswd port 464
start_ad() {
    running myadtest && return 0
    podman run --rm -d \
        --name myadtest \
        --hostname myadtest \
        --net myguacnet \
        -e REALM=AD.EXAMPLE.ORG \
        -e DOMAIN=ADEXAMPLE \
        -e ADMINPASS=AdAdm1n-Pass \
        docker.io/smblds/smblds:latest >/dev/null || return 1
    wait_for_samba

    # Samba accepts a user's previous password for an hour after a change;
    # turn that off so tests show the old password is really rejected after
    # rotation. The image only runs LDAP; also run the KDC, which serves
    # kpasswd too
    podman exec myadtest sed -i '/^\[global\]/a\    old password allowed period = 0' /etc/samba/smb.conf
    podman exec myadtest sed -i 's/^\(\s*server services = ldap cldap\)$/\1 kdc/' /etc/samba/smb.conf
    podman restart myadtest >/dev/null
    wait_for_samba

    # Test user, named "adtest" in its DN too
    podman exec myadtest samba-tool user create adtest 'P@ssw0rd-AD1' --given-name=AD --surname=Test \
        --use-username-as-cn >/dev/null

    # Allow changing a password again right away, so accounts changing their
    # own password can be rotated repeatedly
    podman exec myadtest samba-tool domain passwordsettings set --min-pwd-age=0 >/dev/null
}

# MIT Kerberos KDC: KDC port 88, kpasswd port 464. The packages are installed
# when the container starts, which takes a minute.
start_kdc() {
    running mykdctest && return 0
    podman run --rm -d \
        --name mykdctest \
        --hostname mykdctest \
        --net myguacnet \
        docker.io/library/debian:bookworm-slim \
        bash -c '
set -e
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq krb5-kdc krb5-admin-server >/dev/null
cat > /etc/krb5.conf <<CONF
[libdefaults]
    default_realm = EXAMPLE.ORG
[realms]
    EXAMPLE.ORG = {
        kdc = mykdctest
        admin_server = mykdctest
    }
CONF
echo "admin/admin@EXAMPLE.ORG *" > /etc/krb5kdc/kadm5.acl
kdb5_util create -s -r EXAMPLE.ORG -P KdcMaster-Pass >/dev/null
kadmin.local -q "addprinc -pw KdcAdm1n-Pass admin/admin" >/dev/null
kadmin.local -q "addprinc -pw P@ssw0rd-KDC1 kdctest" >/dev/null
krb5kdc
touch /tmp/ready
exec kadmind -nofork
' >/dev/null || return 1

    # Wait for the KDC and kadmind (which serves kpasswd)
    until podman exec mykdctest test -f /tmp/ready 2>/dev/null; do sleep 2; done
}

# TACACS+ server, port 49. tac_plus-ng is built from source into the image
# "localhost/pam-tacacs-test" the first time, which takes a few minutes.
start_tacacs() {
    running mytacacstest && return 0
    podman image exists localhost/pam-tacacs-test \
        || podman build -t localhost/pam-tacacs-test tacacs || return 1
    podman run --rm -d \
        --name mytacacstest \
        --hostname mytacacstest \
        --net myguacnet \
        localhost/pam-tacacs-test >/dev/null || return 1

    # Accounts live in its shadow file: user:hash:last change (days):...
    local hash
    hash=$(podman exec mytacacstest mkpasswd -m sha-512 'P@ssw0rd-Tac1')
    podman exec mytacacstest sh -c "echo 'tactest:$hash:$(( $(date +%s) / 86400 )):0:99999:7:::' > /etc/tacacs/shadow"
}

# The databases to manage accounts on, over TLS
# A certificate of the test CA for each given server, into lab/targets/certs
# as HOST.crt and HOST.key, the CA (ca.crt) made the first time
certify() {
    local certs=targets/certs host
    mkdir -p "$certs"
    if [ ! -s "$certs/ca.crt" ]; then
        openssl req -x509 -newkey rsa:2048 -nodes -days 3650 -subj "/CN=guacamole-pam test CA" \
            -keyout "$certs/ca.key" -out "$certs/ca.crt" 2>/dev/null || return 1
    fi
    for host in "$@"; do
        [ -s "$certs/$host.crt" ] && continue
        openssl req -newkey rsa:2048 -nodes -subj "/CN=$host" -keyout "$certs/$host.key" \
            -out "$certs/$host.csr" 2>/dev/null
        openssl x509 -req -in "$certs/$host.csr" -CA "$certs/ca.crt" -CAkey "$certs/ca.key" -CAcreateserial \
            -days 3650 -extfile <(printf 'subjectAltName=DNS:%s\nextendedKeyUsage=serverAuth\n' "$host") \
            -out "$certs/$host.crt" 2>/dev/null
        rm -f "$certs/$host.csr"
    done
}

start_databases() {
    local certs=targets/certs
    local targets="mypgtarget mymysqltarget mymariadbtarget mymssqltarget"

    # The test CA, and a certificate for each server
    certify $targets || return 1
    # Read by each server's own user, so world-readable: test keys only
    chmod 644 "$certs"/*.key

    # Copies the certificate where the server's own user can read it, then
    # starts the server as the image would
    local copy_certs='mkdir -p /etc/pam-certs && cp /certs/ca.crt /certs/$HOST.crt /certs/$HOST.key /etc/pam-certs/ && chown -R $OWNER /etc/pam-certs && chmod 600 /etc/pam-certs/$HOST.key'

    running mypgtarget || podman run --rm -d --name mypgtarget --hostname mypgtarget --net myguacnet \
        -e POSTGRES_PASSWORD='PgAdm1n-Pass' -e HOST=mypgtarget -e OWNER=postgres -v "./$certs:/certs:ro,Z" \
        --entrypoint bash docker.io/library/postgres:18.4 -c "$copy_certs && exec docker-entrypoint.sh postgres \
            -c ssl=on -c ssl_cert_file=/etc/pam-certs/mypgtarget.crt -c ssl_key_file=/etc/pam-certs/mypgtarget.key" >/dev/null

    running mymysqltarget || podman run --rm -d --name mymysqltarget --hostname mymysqltarget --net myguacnet \
        -e MYSQL_ROOT_PASSWORD='MyAdm1n-Pass' -e HOST=mymysqltarget -e OWNER=mysql -v "./$certs:/certs:ro,Z" \
        --entrypoint bash docker.io/library/mysql:8.4 -c "$copy_certs && exec docker-entrypoint.sh mysqld \
            --ssl-ca=/etc/pam-certs/ca.crt --ssl-cert=/etc/pam-certs/mymysqltarget.crt \
            --ssl-key=/etc/pam-certs/mymysqltarget.key" >/dev/null

    running mymariadbtarget || podman run --rm -d --name mymariadbtarget --hostname mymariadbtarget --net myguacnet \
        -e MARIADB_ROOT_PASSWORD='MariaAdm1n-Pass' -e HOST=mymariadbtarget -e OWNER=mysql -v "./$certs:/certs:ro,Z" \
        --entrypoint bash docker.io/library/mariadb:11.4 -c "$copy_certs && exec docker-entrypoint.sh mariadbd \
            --ssl-ca=/etc/pam-certs/ca.crt --ssl-cert=/etc/pam-certs/mymariadbtarget.crt \
            --ssl-key=/etc/pam-certs/mymariadbtarget.key" >/dev/null

    # SQL Server runs as its own user from the start: its certificate is read
    # where it is mounted
    printf '[network]\ntlscert = /certs/mymssqltarget.crt\ntlskey = /certs/mymssqltarget.key\ntlsprotocols = 1.2\nforceencryption = 0\n' \
        > targets/mssql.conf
    running mymssqltarget || podman run --rm -d --name mymssqltarget --hostname mymssqltarget --net myguacnet \
        -e ACCEPT_EULA=Y -e MSSQL_SA_PASSWORD='SqlAdm1n-Pass!' -v "./$certs:/certs:ro,Z" \
        -v ./targets/mssql.conf:/var/opt/mssql/mssql.conf:ro,Z mcr.microsoft.com/mssql/server:2022-latest >/dev/null

    # Wait for each, then add its test account (unless present)
    pg() { podman exec mypgtarget psql -U postgres -tAq -c "$1"; }
    my() { podman exec mymysqltarget mysql -uroot -pMyAdm1n-Pass -N -e "$1" 2>/dev/null; }
    ma() { podman exec mymariadbtarget mariadb -uroot -pMariaAdm1n-Pass -N -e "$1" 2>/dev/null; }
    sq() { podman exec mymssqltarget /opt/mssql-tools18/bin/sqlcmd -C -S localhost -U sa -P 'SqlAdm1n-Pass!' -h -1 -b \
        -Q "SET NOCOUNT ON; $1" 2>/dev/null; }

    until [ "$(pg 'SELECT 1' 2>/dev/null)" = 1 ] && podman logs mypgtarget 2>&1 \
        | grep -q "PostgreSQL init process complete\|ready to accept connections"; do sleep 2; done
    until podman logs mymysqltarget 2>&1 | grep -q "port: 3306" && [ "$(my 'SELECT 1')" = 1 ]; do sleep 2; done
    until [ "$(ma 'SELECT 1')" = 1 ]; do sleep 2; done
    until [ "$(sq 'SELECT 1' | tr -d ' ')" = 1 ]; do sleep 2; done

    pg "DO \$\$ BEGIN IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'dbtest') THEN
        CREATE ROLE dbtest LOGIN PASSWORD 'P@ssw0rd-Db1'; END IF; END \$\$"
    my "CREATE USER IF NOT EXISTS 'dbtest'@'%' IDENTIFIED BY 'P@ssw0rd-Db1'"
    ma "CREATE USER IF NOT EXISTS 'dbtest'@'%' IDENTIFIED BY 'P@ssw0rd-Db1'"
    sq "IF SUSER_ID('dbtest') IS NULL CREATE LOGIN dbtest WITH PASSWORD = 'P@ssw0rd-Db1'"
}

# A syslog receiver, writing each transport's messages to its file in /tmp
start_syslog() {
    running mysyslogtest && return 0
    certify mysyslogtest || return 1
    podman run --rm -d \
        --name mysyslogtest \
        --hostname mysyslogtest \
        --net myguacnet \
        -v "./targets/certs:/certs:ro,Z" \
        --entrypoint sh docker.io/alpine/socat:1.8.1.1 -c '
            socat -u OPENSSL-LISTEN:6514,reuseaddr,fork,cert=/certs/mysyslogtest.crt,key=/certs/mysyslogtest.key,verify=0 \
                OPEN:/tmp/tls.log,creat,append &
            socat -u TCP-LISTEN:514,reuseaddr,fork OPEN:/tmp/tcp.log,creat,append &
            socat -u UDP-RECV:514 OPEN:/tmp/udp.log,creat,append &
            wait' >/dev/null
}

# A mail server, keeping what it receives
start_mail() {
    running mymailtest && return 0
    certify mymailtest || return 1
    podman run --rm -d \
        --name mymailtest \
        --hostname mymailtest \
        --net myguacnet \
        -v "./targets/certs:/certs:ro,Z" \
        -e MP_SMTP_TLS_CERT=/certs/mymailtest.crt \
        -e MP_SMTP_TLS_KEY=/certs/mymailtest.key \
        -e MP_SMTP_REQUIRE_STARTTLS=true \
        -e MP_SMTP_AUTH='pammail:P@ssw0rd-Mail1' \
        docker.io/axllent/mailpit:v1.31.5 >/dev/null
}

start_services() {
    local service
    for service in ssh ldap ad kdc tacacs databases syslog mail; do
        "start_$service" || { echo "The $service test server did not start." >&2; return 1; }
    done
    echo "Test servers running."
}

usage() {
    sed -n '/^#   lab.sh/,/^# Commands/{/^# Commands/d;s/^# \{0,1\}//;p}' "$(basename "$0")" | grep '^  lab.sh'
    exit 2
}

[ $# -eq 0 ] && usage
ha=no ha_module=false
for arg in "$@"; do
    case "$arg" in
        --ha) ha=yes ha_module=true;;
        --ha=off) ha=yes ha_module=false;;
        app|services|seed|reset|stop) ;;
        *) usage;;
    esac
done

# Said of the servers started, with two of them
ha_note=
[ $ha = yes ] && ha_note=", HA module $([ $ha_module = true ] && echo on || echo off)"

app=no
for arg in "$@"; do
    case "$arg" in
        app) start_guacamole || exit 1; app=yes
            [ $ha = yes ] && { start_second || exit 1; };;
        services) start_services || exit 1;;
        seed) ./seed.sh || exit 1;;
        reset) reset || exit 1;;
        stop) stop $LAB_CONTAINERS; echo "Lab stopped.";;
    esac
done
# --ha or --ha=off without "app": both servers again
[ $ha = yes ] && [ $app = no ] && { restart_ha || exit 1; }
exit 0
