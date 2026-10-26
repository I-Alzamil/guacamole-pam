#!/bin/bash
# Helpers of tests/ha/run.sh: checks counted as PASS/FAIL, Guacamole's REST API,
# the database's own client, and sessions held open in the background.

DB_PASSWORD='Guac-Test-Pw1'

T2_PASSED=${T2_PASSED:-0}
T2_FAILED=${T2_FAILED:-0}
T2_FAILURES=()
T2_TMP=$(mktemp -d)

section() { printf '\n== %s\n' "$*"; }
pass() { T2_PASSED=$((T2_PASSED + 1)); printf '  PASS  %s\n' "$1"; }
fail() {
    T2_FAILED=$((T2_FAILED + 1)); T2_FAILURES+=("$DB: $1")
    printf '  FAIL  %s\n' "$1"
    [ -n "$2" ] && printf '        %s\n' "$2"
    return 0
}

# check DESCRIPTION EXPECTED ACTUAL
check() { if [ "$2" = "$3" ]; then pass "$1"; else fail "$1" "expected: $2 | got: $3"; fi; }

# check_contains DESCRIPTION NEEDLE HAYSTACK
check_contains() { case "$3" in *"$2"*) pass "$1";; *) fail "$1" "expected to contain: $2 | got: $3";; esac; }

# eventually DESCRIPTION EXPECTED SECONDS COMMAND...: the command's output
# becomes EXPECTED within SECONDS (counts shown are read again every few)
eventually() {
    local description=$1 expected=$2 seconds=$3 actual; shift 3
    for _ in $(seq "$seconds"); do
        actual=$("$@")
        [ "$actual" = "$expected" ] && { pass "$description"; return; }
        sleep 1
    done
    fail "$description" "expected within ${seconds}s: $expected | got: $actual"
}

# json_get JSON EXPRESSION -> the expression of the JSON as "d", or ""
json_get() {
    python3 -I -c "import sys,json;d=json.loads(sys.argv[1]);v=$2;print('' if v is None else v)" "$1" 2>/dev/null
}

# token URL USERNAME PASSWORD
token() {
    curl -s -d "username=$2" -d "password=$3" "$1/api/tokens" \
        | python3 -I -c "import sys,json;print(json.load(sys.stdin)['authToken'])"
}

# login URL USERNAME PASSWORD [TOTP-CODE] -> the token, or "refused MESSAGE";
# from the address $LOGIN_FROM if set, as a load balancer forwards it
login() {
    local answer options=(-d "username=$2" -d "password=$3")
    [ -n "$4" ] && options+=(-d "guac-totp=$4")
    [ -n "$LOGIN_FROM" ] && options+=(-H "X-Forwarded-For: $LOGIN_FROM")
    answer=$(curl -s "${options[@]}" "$1/api/tokens")
    json_get "$answer" "d.get('authToken') or 'refused ' + str(d.get('message'))"
}

# self_name URL TOKEN -> who the token is logged in as on that server, or ""
self_name() {
    json_get "$(api GET "$1/api/session/data/$DS/self" "$2")" "d.get('username')"
}

# totp SECRET -> the TOTP code of a base32 secret now, as the TOTP extension
# computes it by default (SHA-1, 6 digits, 30 seconds)
totp() {
    python3 -I -c "
import base64,hmac,struct,sys,time
key=base64.b32decode(sys.argv[1]); counter=struct.pack('>Q',int(time.time())//30)
h=hmac.new(key,counter,'sha1').digest(); o=h[-1]&15
print('%06d'%((struct.unpack('>I',h[o:o+4])[0]&0x7fffffff)%1000000))" "$1"
}

# active_session URL TOKEN CONNECTION USERNAME -> the identifier of the
# active connection of a connection opened by a user, as listed there
active_session() {
    json_get "$(api GET "$1/api/session/data/$DS/activeConnections" "$2")" \
        "next((c['identifier'] for c in d.values() if c.get('connectionIdentifier') == '$3'
            and c.get('username') == '$4'), '')"
}

# active_users URL TOKEN CONNECTION -> who opened the active connections of
# a connection, as listed there ("None" where not shown), sorted
active_users() {
    json_get "$(api GET "$1/api/session/data/$DS/activeConnections" "$2")" \
        "','.join(sorted(str(c.get('username')) for c in d.values() if c.get('connectionIdentifier') == '$3'))"
}

# active_count URL TOKEN CONNECTION -> how many active connections of a
# connection are listed there, joining ones included
active_count() {
    json_get "$(api GET "$1/api/session/data/$DS/activeConnections" "$2")" \
        "len([c for c in d.values() if c.get('connectionIdentifier') == '$3'])"
}

# share_key JSON -> the key of sharing credentials
share_key() { json_get "$1" "d['values']['key']"; }

# api METHOD URL TOKEN [JSON] -> the body of the answer
api() {
    if [ -n "$4" ]; then
        curl -s -X "$1" -H 'Content-Type: application/json' -d "$4" "$2?token=$3"
    else
        curl -s -X "$1" "$2?token=$3"
    fi
}

# sql QUERY -> the rows of a query on the database of $DB, one per line
sql() {
    case "$DB" in
        postgresql) podman exec mypamha-postgresql psql -U guacamole -d guacamole -tAc "$1";;
        mysql) podman exec mypamha-mysql mysql -uguacamole -p"$DB_PASSWORD" guacamole -N -e "$1" 2>/dev/null;;
        mariadb) podman exec mypamha-mariadb mariadb -uguacamole -p"$DB_PASSWORD" guacamole -N -e "$1" 2>/dev/null;;
        sqlserver) podman exec mypamha-sqlserver /opt/mssql-tools18/bin/sqlcmd -C -S localhost -U sa \
            -P "$DB_PASSWORD" -d guacamole -h -1 -W -Q "SET NOCOUNT ON; $1";;
    esac
}

# active URL TOKEN ID [c|g] -> "Currently in use by" of a connection or group
active() {
    local kind=connections
    [ "$4" = g ] && kind=connectionGroups
    json_get "$(api GET "$1/api/session/data/$DS/$kind/$3" "$2")" "d.get('activeConnections')"
}

# hold NAME URL TOKEN ID [c|g|a] -> "open", or "refused STATUS MESSAGE", as
# the session NAME opens or not, of a connection, a group, or joining an
# active connection, of data source $DS, or $HOLD_DS if set; an open session
# stays open until release NAME.
# What an earlier session of the same name wrote is removed first, so it is
# never read for this one's.
hold() {
    local name=$1 file=$T2_TMP/session-$1
    rm -f "$file" "$file.pid"
    PAM_DATA_SOURCE="${HOLD_DS:-$DS}" python3 -I "$(dirname "${BASH_SOURCE[0]}")/../session.py" "$2" "$3" "$4" "${5:-c}" \
        >"$file" 2>&1 &
    echo $! > "$file.pid"
    for _ in $(seq 150); do
        [ -s "$file" ] && break
        sleep 0.1
    done
    head -1 "$file" 2>/dev/null
}

# state NAME -> the last line the session NAME wrote: "open", "closed", ...
state() { tail -1 "$T2_TMP/session-$1" 2>/dev/null; }

release() {
    local file=$T2_TMP/session-$1
    [ -f "$file.pid" ] || return 0
    kill -TERM "$(cat "$file.pid")" 2>/dev/null
    for _ in $(seq 50); do kill -0 "$(cat "$file.pid")" 2>/dev/null || break; sleep 0.1; done
    rm -f "$file.pid"
}

release_all() {
    local pid
    for pid in "$T2_TMP"/session-*.pid; do
        [ -f "$pid" ] && release "$(basename "$pid" .pid | sed 's/^session-//')"
    done
}
