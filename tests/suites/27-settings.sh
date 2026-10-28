#!/bin/bash
# The settings shared by every server, on the PAM Settings tab: who may read
# and change them, invalid changes refused whole, each change applying to
# requests at once, and on the second server within its cache time (when it
# runs), and defaults restored. Importing guacamole.properties values needs a
# server started with them: see tests/README.md.

SETTINGS="$PAM/settings"
GUAC2_URL="${GUAC2_URL:-http://localhost:8081}"

# Leaves every setting at its default, whatever a check left
reset_settings() {
    api PUT "$SETTINGS" "$ADMIN" \
        '{"pam-admin-bypass-requests":null,"pam-admin-require-approvals":null,"pam-extensions-enabled":null,
          "pam-max-extensions":null}' >/dev/null
}

section "Setup"
create_connection GATED "{\"name\":\"t27 gated ssh\",\"parentIdentifier\":\"ROOT\",\"protocol\":\"ssh\",
    \"parameters\":{\"hostname\":\"mysshtest\",\"port\":\"22\"},\"attributes\":{}}"
create_user t27-user t27-user-pw
grant_read t27-user "$GATED"
USER=$(token t27-user t27-user-pw)
reset_settings
on_cleanup reset_settings
check "setup: a connection and a user exist" yes "$([ -n "$GATED" ] && [ -n "$USER" ] && echo yes)"

setting() { # NAME EXPRESSION -> the expression, of the setting as listed
    curl -s "$SETTINGS?token=$ADMIN" | python3 -I -c "
import sys,json
e=[e for e in json.load(sys.stdin) if e['name']==sys.argv[1]][0]
print($2)" "$1"
}

# ---------------------------------------------------------------- access
section "Who may read and change them"
check "a user cannot read them" 403 "$(status_of "$(api GET "$SETTINGS" "$USER")")"
check "...nor change them" 403 "$(status_of "$(api PUT "$SETTINGS" "$USER" '{"pam-admin-bypass-requests":true}')")"
check "...which stay as they were" "False False" "$(setting pam-admin-bypass-requests "e['value'], e['set']")"
check "an administrator reads each general setting, at its default" \
    "pam-admin-bypass-requests=False pam-admin-require-approvals=False pam-extensions-enabled=True pam-max-extensions=2" \
    "$(curl -s "$SETTINGS?token=$ADMIN" | python3 -I -c "
import sys,json
print(' '.join('%s=%s' % (e['name'], e['value']) for e in json.load(sys.stdin) if e['section'] == 'GENERAL'))")"
check "...with their defaults and bounds" "2 0 20" "$(setting pam-max-extensions "e['defaultValue'], e['minimum'], e['maximum']")"

# ---------------------------------------------------------------- invalid
section "Invalid changes, refused whole"
R=$(api PUT "$SETTINGS" "$ADMIN" '{"pam-max-extensions":21}')
check "a number out of bounds" "400 \"pam-max-extensions\" must be from 0 to 20." "$(status_of "$R") $(message_of "$R")"
R=$(api PUT "$SETTINGS" "$ADMIN" '{"pam-extensions-enabled":"maybe"}')
check "a yes/no that is neither" "400 \"pam-extensions-enabled\" must be true or false." "$(status_of "$R") $(message_of "$R")"
R=$(api PUT "$SETTINGS" "$ADMIN" '{"pam-max-extensions":3,"pam-encryption-key":"x"}')
check "a setting that is not one, such as the encryption key" "400 Unknown setting \"pam-encryption-key\"." \
    "$(status_of "$R") $(message_of "$R")"
check "...with a valid change beside it, which is not made either" "2 False" \
    "$(setting pam-max-extensions "e['value'], e['set']")"

# ---------------------------------------------------------------- applied
section "Changes apply at once"
R=$(api POST "$PAM/requests/$GATED" "$ADMIN" '{}')
check_contains "by default, an administrator gives a reason too" "reason" "$(message_of "$R")"
R=$(api PUT "$SETTINGS" "$ADMIN" '{"pam-admin-bypass-requests":true}')
check "an administrator lets administrators bypass requests" "200 True" \
    "$(status_of "$R") $(json_get "${R#* }" "[e['value'] for e in d if e['name']=='pam-admin-bypass-requests'][0]")"
check "...recorded as theirs" "True $GUAC_ADMIN" "$(setting pam-admin-bypass-requests "e['set'], e['modifiedBy']")"
check "...in the database" "true $GUAC_ADMIN" \
    "$(sql "SELECT value, modified_by FROM pam_setting WHERE name = 'pam-admin-bypass-requests'" | tr '\t' ' ')"
check_contains "...and logged" "User \"$GUAC_ADMIN\" set \"pam-admin-bypass-requests\" to true (was the default (false))." \
    "$(podman logs --since 1m myguactest 2>&1)"
check "an administrator now connects without a request" "true" \
    "$(json_get "$(api GET "$PAM/requests/$GATED" "$ADMIN" | cut -d' ' -f2-)" "str(d['bypass']).lower()")"
check "...but a user still needs one" "false" \
    "$(json_get "$(api GET "$PAM/requests/$GATED" "$USER" | cut -d' ' -f2-)" "str(d['noRequest']).lower()")"

api PUT "$SETTINGS" "$ADMIN" '{"pam-max-extensions":0}' >/dev/null
check "no extensions by default: requests ask for one time limit at most" 1 \
    "$(json_get "$(api GET "$PAM/requests/$GATED" "$USER" | cut -d' ' -f2-)" "d['maxPeriods']")"
api PUT "$SETTINGS" "$ADMIN" '{"pam-max-extensions":4}' >/dev/null
check "...or one more than the extensions allowed" 5 \
    "$(json_get "$(api GET "$PAM/requests/$GATED" "$USER" | cut -d' ' -f2-)" "d['maxPeriods']")"
api PUT "$SETTINGS" "$ADMIN" '{"pam-extensions-enabled":false}' >/dev/null
check "extensions turned off: one time limit again" 1 \
    "$(json_get "$(api GET "$PAM/requests/$GATED" "$USER" | cut -d' ' -f2-)" "d['maxPeriods']")"

# ---------------------------------------------------------------- second server
if [ "$(podman inspect -f '{{.State.Running}}' myguactest2 2>/dev/null)" = true ]; then
    section "...and on the other server, within seconds"
    for i in $(seq 90); do curl -sf "$GUAC2_URL/api/languages" >/dev/null && break; sleep 2; done
    ADMIN2=$(curl -s -d "username=$GUAC_ADMIN&password=$GUAC_ADMIN_PASSWORD" "$GUAC2_URL/api/tokens" \
        | python3 -I -c 'import sys,json;print(json.load(sys.stdin)["authToken"])')
    PAM2="$GUAC2_URL/api/session/ext/pam"
    seen2() { json_get "$(api GET "$PAM2/requests/$GATED" "$ADMIN2" | cut -d' ' -f2-)" "$1"; }
    check "the other server applies them" "true 1" "$(seen2 "str(d['bypass']).lower()") $(seen2 "d['maxPeriods']")"
    api PUT "$SETTINGS" "$ADMIN" '{"pam-admin-bypass-requests":false,"pam-extensions-enabled":true}' >/dev/null
    sleep 6
    check "...and changes made here, after its cache time (5 s)" "false 5" \
        "$(seen2 "str(d['bypass']).lower()") $(seen2 "d['maxPeriods']")"
else
    section "Skipped: no second server (start it with lab/lab.sh --ha)"
fi

# ---------------------------------------------------------------- defaults
section "Defaults restored"
R=$(api PUT "$SETTINGS" "$ADMIN" '{"pam-admin-bypass-requests":null,"pam-admin-require-approvals":null,
    "pam-extensions-enabled":null,"pam-max-extensions":null}')
check "each set back to its default" "200 False/False False/False True/False 2/False" "$(status_of "$R") $(json_get "${R#* }" \
    "' '.join('%s/%s' % (e['value'], e['set']) for e in d if e['section'] == 'GENERAL')")"
check "...still recorded as decided here, so a server's guacamole.properties cannot bring them back" 3 \
    "$(sql "SELECT COUNT(*) FROM pam_setting WHERE value IS NULL AND name IN ('pam-admin-bypass-requests',
        'pam-extensions-enabled', 'pam-max-extensions')")"
