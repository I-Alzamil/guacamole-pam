#!/bin/bash
# Shared helpers of the Tier 2 suites: Guacamole's REST API, checks counted
# as PASS/FAIL, per-suite cleanup, and checks of passwords made directly on
# the test servers (independently of the extension).
#
# Everything a suite creates is named with the "t2" prefix and removed by its
# cleanup, which runs even when a check fails.

# The test database (podman/database.sh): its "sql" and Guacamole data source
source "$(dirname "${BASH_SOURCE[0]}")/../podman/database.sh"

GUAC_URL="${GUAC_URL:-http://localhost:8080}"
API="$GUAC_URL/api"
DATA="$API/session/data/$PAM_DATA_SOURCE"
PAM="$API/session/ext/pam"
GUAC_ADMIN="${GUAC_ADMIN:-guacadmin}"
GUAC_ADMIN_PASSWORD="${GUAC_ADMIN_PASSWORD:-guacadmin}"

# The key build.sh encrypts stored secrets with, and the jar that decrypts them
PAM_TEST_KEY="${PAM_ENCRYPTION_KEY-um/hqZa6cc89CtHmc9vYOuoDd8S1jY8IaASlz5S00iY=}"
T2_JAR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && ./podman/extension-jar.sh)"

T2_PASSED=${T2_PASSED:-0}
T2_FAILED=${T2_FAILED:-0}
T2_FAILURES=()

T2_TMP=$(mktemp -d)

# ---- Reporting ----

section() { printf '\n== %s\n' "$*"; }

pass() { T2_PASSED=$((T2_PASSED + 1)); printf '  PASS  %s\n' "$1"; }

fail() {
    T2_FAILED=$((T2_FAILED + 1)); T2_FAILURES+=("$1")
    printf '  FAIL  %s\n' "$1"
    [ -n "$2" ] && printf '        %s\n' "$2"
    return 0
}

# check DESCRIPTION EXPECTED ACTUAL
check() { if [ "$2" = "$3" ]; then pass "$1"; else fail "$1" "expected: $2 | got: $3"; fi; }

# check_contains DESCRIPTION NEEDLE HAYSTACK
check_contains() { case "$3" in *"$2"*) pass "$1";; *) fail "$1" "expected to contain: $2 | got: $3";; esac; }

# ---- Cleanup, run in reverse order when the suite ends ----

T2_CLEANUP=()
on_cleanup() { T2_CLEANUP+=("$*"); }
# Runs the cleanup, newest first, logged in again: Guacamole ends a session
# by itself when guacd reports a connection's login rejected. API calls not
# answered with success are reported, so a suite cannot silently leave test
# data behind. (Cleanup commands use "$ADMIN" as it is then.)
run_cleanup() {
    local i result
    ADMIN=$(admin_token)
    for ((i = ${#T2_CLEANUP[@]} - 1; i >= 0; i--)); do
        result=$(eval "${T2_CLEANUP[$i]}" 2>&1)
        case "${T2_CLEANUP[$i]}" in
            api\ *|delete_user_group\ *) case "$result" in 2[0-9][0-9]\ *|2[0-9][0-9]) ;; *)
                printf '  CLEANUP FAILED  %s\n        %s\n' "${T2_CLEANUP[$i]}" "${result:0:200}";;
            esac;;
        esac
    done
    T2_CLEANUP=()
}

# ---- JSON (python3, isolated) ----

# json_get JSON PYTHON-EXPRESSION-ON-d
json_get() { python3 -I -c "import sys,json;d=json.loads(sys.argv[1]);v=$2;print('' if v is None else v)" "$1" 2>/dev/null; }

# ---- Guacamole API ----

token() {
    curl -s -d "username=$1" -d "password=$2" "$API/tokens" | python3 -I -c "import sys,json;print(json.load(sys.stdin)['authToken'])"
}

admin_token() { token "$GUAC_ADMIN" "$GUAC_ADMIN_PASSWORD"; }

# api METHOD URL TOKEN [JSON] -> prints "STATUS BODY"
api() {
    local method=$1 url=$2 tok=$3 body=$4 sep='?'
    case "$url" in *\?*) sep='&';; esac
    if [ -n "$body" ]; then
        curl -s -o "$T2_TMP/body" -w '%{http_code}' -X "$method" -H 'Content-Type: application/json' -d "$body" "$url${sep}token=$tok"
    else
        curl -s -o "$T2_TMP/body" -w '%{http_code}' -X "$method" "$url${sep}token=$tok"
    fi
    printf ' %s' "$(cat "$T2_TMP/body")"
}

# The error message of an API answer, or "" for success
message_of() { json_get "${1#* }" "d.get('message')"; }
status_of() { printf '%s' "${1%% *}"; }

connection_id() {
    curl -s "$DATA/connections?token=$ADMIN" | python3 -I -c "
import sys,json
m=[c['identifier'] for c in json.load(sys.stdin).values() if c['name']==sys.argv[1]]
print(m[0] if m else '')" "$1"
}

platform_id() {
    curl -s "$PAM/platforms?token=$ADMIN" | python3 -I -c "
import sys,json
m=[p['id'] for p in json.load(sys.stdin) if p['name']==sys.argv[1]]
print(m[0] if m else '')" "$1"
}

# create_platform VARIABLE JSON: creates it, sets VARIABLE to its id, and
# removes it at cleanup. (Not called as $(...): cleanup is registered here.)
create_platform() {
    local id
    id=$(json_get "$(api POST "$PAM/platforms" "$ADMIN" "$2" | cut -d' ' -f2-)" "d.get('id')")
    [ -n "$id" ] && on_cleanup "api DELETE '$PAM/platforms/$id' \"\$ADMIN\""
    printf -v "$1" '%s' "$id"
    [ -n "$id" ] || fail "creating platform for \$$1" "$(cat "$T2_TMP/body")"
}

# create_connection VARIABLE JSON: likewise for a connection
create_connection() {
    local id
    id=$(json_get "$(api POST "$DATA/connections" "$ADMIN" "$2" | cut -d' ' -f2-)" "d.get('identifier')")
    [ -n "$id" ] && on_cleanup "api DELETE '$DATA/connections/$id' \"\$ADMIN\""
    printf -v "$1" '%s' "$id"
    [ -n "$id" ] || fail "creating connection for \$$1" "$(cat "$T2_TMP/body")"
}

# create_group VARIABLE JSON: likewise for a connection group
create_group() {
    local id
    id=$(json_get "$(api POST "$DATA/connectionGroups" "$ADMIN" "$2" | cut -d' ' -f2-)" "d.get('identifier')")
    [ -n "$id" ] && on_cleanup "api DELETE '$DATA/connectionGroups/$id' \"\$ADMIN\""
    printf -v "$1" '%s' "$id"
    [ -n "$id" ] || fail "creating group for \$$1" "$(cat "$T2_TMP/body")"
}

# create_user NAME PASSWORD [ATTRIBUTES-JSON] (removed at cleanup)
create_user() {
    local attributes=${3:-'{}'}
    api POST "$DATA/users" "$ADMIN" "{\"username\":\"$1\",\"password\":\"$2\",\"attributes\":$attributes}" >/dev/null
    on_cleanup "api DELETE '$DATA/users/$1' \"\$ADMIN\""
}

# delete_user_group NAME -> "HTTP-STATUS BODY". Guacamole 1.6 cannot delete
# user groups on MySQL (its statement lacks an AND), so there the group is
# removed from the database instead, as Guacamole would
delete_user_group() {
    local result
    result=$(api DELETE "$DATA/userGroups/$1" "$ADMIN")
    if [ "${result%% *}" = 500 ] && [ "$PAM_DATA_SOURCE" = mysql ] \
            && sql "DELETE FROM guacamole_entity WHERE type = 'USER_GROUP' AND name = '$1'"; then
        result="204 removed from the database"
    fi
    printf '%s\n' "$result"
}

# create_user_group NAME ATTRIBUTES-JSON MEMBER... (removed at cleanup)
create_user_group() {
    local name=$1 attributes=$2 member
    shift 2
    api POST "$DATA/userGroups" "$ADMIN" "{\"identifier\":\"$name\",\"attributes\":$attributes}" >/dev/null
    on_cleanup "delete_user_group '$name'"
    for member in "$@"; do
        api PATCH "$DATA/userGroups/$name/memberUsers" "$ADMIN" "[{\"op\":\"add\",\"path\":\"/\",\"value\":\"$member\"}]" >/dev/null
    done
}

# grant USER PERMISSION-PATCH-JSON
grant() { api PATCH "$DATA/users/$1/permissions" "$ADMIN" "$2" >/dev/null; }

grant_read() { grant "$1" "[{\"op\":\"add\",\"path\":\"/connectionPermissions/$2\",\"value\":\"READ\"}]"; }

# parameter ID NAME: a connection parameter; secrets as plaintext, also
# when kept apart by the extension (the parameter is then a token such as
# ${PAM_PASSWORD_17}, which the API shows as ********)
parameter() {
    local value
    value=$(json_get "$(curl -s "$DATA/connections/$1/parameters?token=$ADMIN")" "d.get('$2')")
    if [ "$value" = '********' ]; then
        value=$(sql "SELECT parameter_value
            FROM guacamole_connection_parameter WHERE connection_id = $1 AND parameter_name = '$2'")
    fi
    if [[ "$value" == '${PAM_'*"_$1}" ]]; then
        value=$(reveal "connection-secret:$1:$2" "$(sql \
            "SELECT value FROM pam_connection_secret WHERE connection_id = $1 AND parameter_name = '$2'")")
    fi
    printf '%s\n' "$value"
}

# reveal PURPOSE VALUE: the value, decrypted if the extension encrypted it
# (with the key build.sh gives the test setup), by the extension's own tool
reveal() {
    case "$2" in
        pam:v1:*) printf '%s\n' "$2" | PAM_ENCRYPTION_KEY="$PAM_TEST_KEY" java -cp "$T2_JAR" \
                      org.apache.guacamole.pam.crypto.SecretCipher "$1";;
        *) printf '%s\n' "$2";;
    esac
}

# edit_connection TOKEN ID PARAMS-PATCH-JSON ATTRS-PATCH-JSON [NEW-NAME] [NEW-PROTOCOL] -> "STATUS BODY"
# A parameter set to null is removed.
edit_connection() {
    local edited params=${3:-'{}'} attributes=${4:-'{}'}
    edited=$(python3 -I - "$(curl -s "$DATA/connections/$2?token=$ADMIN")" \
            "$(curl -s "$DATA/connections/$2/parameters?token=$ADMIN")" "$params" "$attributes" "$5" "$6" <<'PY'
import sys, json
c = json.loads(sys.argv[1]); p = json.loads(sys.argv[2])
for k, v in json.loads(sys.argv[3]).items():
    if v is None: p.pop(k, None)
    else: p[k] = v
c['parameters'] = p
c['attributes'].update(json.loads(sys.argv[4]))
if sys.argv[5]: c['name'] = sys.argv[5]
if sys.argv[6]: c['protocol'] = sys.argv[6]
print(json.dumps(c))
PY
)
    api PUT "$DATA/connections/$2" "$1" "$edited"
}

# rotate ID -> "STATUS: first line of the message"
rotate() {
    json_get "$(api POST "$PAM/connections/$1/rotate" "$ADMIN" | cut -d' ' -f2-)" \
        "d.get('status','?') + ((': ' + d['message'].splitlines()[0]) if d.get('message') else '')"
}

# tunnel TOKEN ID TYPE(c|g) -> "HTTP-STATUS [error message]"
tunnel() {
    curl -s -m 8 -D - -o /dev/null -X POST "$GUAC_URL/tunnel?connect" --data \
        "token=$1&GUAC_DATA_SOURCE=$PAM_DATA_SOURCE&GUAC_ID=$2&GUAC_TYPE=$3&GUAC_WIDTH=800&GUAC_HEIGHT=600&GUAC_DPI=96" \
        | tr -d '\r' | awk '/^HTTP\// {s=$2} tolower($0) ~ /^guacamole-error-message:/ {sub(/^[^:]*: */,""); m=$0} END {print s (m ? " " m : "")}'
}

# ---- Passwords checked directly on the test servers ----

# The SSH image's sshd only lets its own user in; a helper there prints the password
ssh_accepts() {
    podman exec mysshtest sh -c '[ -x /usr/local/bin/t2askpass ] || { printf "#!/bin/sh\nprintf \"%%s\\\\n\" \"\$T2PW\"\n" > /usr/local/bin/t2askpass; chmod 755 /usr/local/bin/t2askpass; }'
    podman exec -e T2PW="$2" -e SSH_ASKPASS=/usr/local/bin/t2askpass -e SSH_ASKPASS_REQUIRE=force mysshtest \
        ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o PubkeyAuthentication=no \
        -o NumberOfPasswordPrompts=1 -o LogLevel=ERROR "$1@localhost" true >/dev/null 2>&1 && echo yes || echo no
}

# known_ssh_password SEEDED-ID -> mysshtest's current password: that of the
# seeded connection (seed.sh), whose password suites keep in step with the
# account; otherwise the image's, set again on the server if a rotation
# without a seeded connection to keep it changed it
known_ssh_password() {
    local password
    password=$( [ -n "$1" ] && parameter "$1" password )
    if [ "$(ssh_accepts mysshtest "$password")" != yes ]; then
        password='P@ssw0rd'
        [ "$(ssh_accepts mysshtest "$password")" = yes ] \
            || podman exec mysshtest sh -c "echo 'mysshtest:$password' | chpasswd" >/dev/null 2>&1
    fi
    printf '%s\n' "$password"
}

openldap_accepts() {
    podman exec myldaptest ldapwhoami -x -H ldap://localhost -D "$1" -w "$2" >/dev/null 2>&1 && echo yes || echo no
}

samba_accepts() {
    podman exec -e LDAPTLS_REQCERT=never myadtest /usr/bin/ldapsearch -x -H ldaps://localhost \
        -D "$1@ad.example.org" -w "$2" -b "" -s base >/dev/null 2>&1 && echo yes || echo no
}

mit_accepts() {
    printf '%s\n' "$2" | podman exec -i mykdctest kinit "$1@EXAMPLE.ORG" >/dev/null 2>&1 && echo yes || echo no
}

# The Samba realm, through MIT's kinit (another implementation than the extension's)
samba_kinit_accepts() {
    podman exec mykdctest sh -c '[ -f /tmp/t2-ad-krb5.conf ] || printf "[libdefaults]\n    default_realm = AD.EXAMPLE.ORG\n    dns_lookup_kdc = false\n    udp_preference_limit = 1\n[realms]\n    AD.EXAMPLE.ORG = {\n        kdc = myadtest\n    }\n" > /tmp/t2-ad-krb5.conf'
    printf '%s\n' "$2" | podman exec -i -e KRB5_CONFIG=/tmp/t2-ad-krb5.conf mykdctest kinit "$1@AD.EXAMPLE.ORG" \
        >/dev/null 2>&1 && echo yes || echo no
}

# rotate_and_verify ID LABEL CHECK-FUNCTION ACCOUNT [ROUNDS]
# Rotates, then checks on the server that the new password works and the old one no longer does.
rotate_and_verify() {
    local id=$1 label=$2 accepts=$3 account=$4 rounds=${5:-2} i old new result
    for ((i = 1; i <= rounds; i++)); do
        old=$(parameter "$id" password)
        result=$(rotate "$id")
        new=$(parameter "$id" password)
        check "$label: rotation $i succeeds" "SUCCESS" "${result%%:*}"
        check "$label: rotation $i, server accepts the new password" yes "$($accepts "$account" "$new")"
        check "$label: rotation $i, server refuses the old password" no "$($accepts "$account" "$old")"
    done
}

cert_fingerprint() { openssl x509 -noout -fingerprint -sha256 2>/dev/null | cut -d= -f2; }

# Waits for Guacamole (it may just have been redeployed), then logs in
wait_for_guacamole() {
    local i
    for i in $(seq 90); do curl -sf "$API/languages" >/dev/null && break; sleep 2; done
    ADMIN=$(admin_token)
}
