#!/bin/bash
# Showing a connection's password to the holder of its checkout: off by
# default, only to the holder, each display recorded, and a managed password
# rotated once the connection is no longer in use, whatever its rotation mode.

shown() { # TOKEN ID -> "STATUS password username"
    local r
    r=$(api POST "$PAM/requests/$2/password" "$1")
    printf '%s %s\n' "$(status_of "$r")" "$(json_get "${r#* }" "(d.get('password') or '') + ' ' + (d.get('accountName') or '')")"
}
reveal_count() { # ID -> how many times the latest checkout showed the password
    sql "SELECT reveal_count FROM pam_checkout WHERE checkout_id = (SELECT max(checkout_id) FROM pam_checkout
         WHERE connection_id = $1)"
}
last_success() { sql "SELECT last_success FROM pam_rotation_state WHERE connection_id = $1"; }
wait_for_rotation() { # ID SINCE: waits up to 30 seconds for a rotation after SINCE; yes or no
    local i
    for i in $(seq 30); do
        [ -n "$(sql "SELECT 1 FROM pam_rotation_state WHERE connection_id = $1 AND last_success > '$2'")" ] \
            && { echo yes; return; }
        sleep 1
    done
    echo no
}

section "Setup"
# mysshtest's account is shared with the seeded "PAM test (Linux)" connection
SEEDED=$(connection_id "PAM test (Linux)")
SSH_PASSWORD=$(known_ssh_password "$SEEDED")
check "precondition: the SSH server's password is known" yes "$(ssh_accepts mysshtest "$SSH_PASSWORD")"
LINUX=$(platform_id "Unix")
create_connection SHOWN "{\"name\":\"t2 reveal managed\",\"parentIdentifier\":\"ROOT\",\"protocol\":\"ssh\",
    \"parameters\":{\"hostname\":\"mysshtest\",\"port\":\"22\",\"username\":\"mysshtest\",\"password\":\"$SSH_PASSWORD\"},
    \"attributes\":{\"pam-platform\":\"$LINUX\",\"pam-rotation-mode\":\"never\"}}"
sync_seeded_ssh() {
    local password
    password=$(parameter "$SHOWN" password)
    [ -n "$SEEDED" ] && [ -n "$password" ] \
        && edit_connection "$ADMIN" "$SEEDED" "{\"password\":\"$password\"}" >/dev/null
}
on_cleanup sync_seeded_ssh
create_connection GUAC_TOKEN "{\"name\":\"t2 reveal own credentials\",\"parentIdentifier\":\"ROOT\",\"protocol\":\"ssh\",
    \"parameters\":{\"hostname\":\"mysshtest\",\"username\":\"\${GUAC_USERNAME}\",\"password\":\"\${GUAC_PASSWORD}\"},
    \"attributes\":{\"pam-reveal-password\":\"true\"}}"

create_user t2-holder t2-holder-pw
create_user t2-other t2-other-pw
for c in $SHOWN $GUAC_TOKEN; do grant_read t2-holder "$c"; grant_read t2-other "$c"; done
HOLDER=$(token t2-holder t2-holder-pw)
OTHER=$(token t2-other t2-other-pw)
check "setup: connections and users exist" yes "$([ -n "$SHOWN$GUAC_TOKEN" ] && [ -n "$HOLDER$OTHER" ] && echo yes)"

# ---------------------------------------------------------------- off by default
section "Off by default"
check "the request says the password is not shown" False \
    "$(json_get "$(api GET "$PAM/requests/$SHOWN" "$HOLDER" | cut -d' ' -f2-)" "d.get('passwordShown')")"
R=$(api POST "$PAM/requests/$SHOWN" "$HOLDER" '{"reason":"T2 reveal off"}')
check "a checkout grants access" 200 "$(status_of "$R")"
check "...without the password" "" "$(json_get "${R#* }" "d.get('password')")"
check "...nor can the holder ask for it" "403 " "$(shown "$HOLDER" "$SHOWN" | cut -d' ' -f1-2)"
api POST "$PAM/requests/$SHOWN/release" "$HOLDER" >/dev/null

# ---------------------------------------------------------------- allowed
section "Allowed on the connection"
edit_connection "$ADMIN" "$SHOWN" '' '{"pam-reveal-password":"true"}' >/dev/null
check "the setting is stored" true "$(sql "SELECT attribute_value FROM guacamole_connection_attribute
    WHERE connection_id = $SHOWN AND attribute_name = 'pam-reveal-password'")"
check "the request says the password may be shown" True \
    "$(json_get "$(api GET "$PAM/requests/$SHOWN" "$HOLDER" | cut -d' ' -f2-)" "d.get('passwordShown')")"
check "without a checkout, it is not shown" 400 "$(shown "$HOLDER" "$SHOWN" | cut -d' ' -f1)"

BEFORE=$(parameter "$SHOWN" password)
R=$(api POST "$PAM/requests/$SHOWN" "$HOLDER" '{"reason":"T2 reveal on"}')
check "a checkout still grants access without the password" "200 " "$(status_of "$R") $(json_get "${R#* }" "d.get('password')")"
check "...which counts no display yet" 0 "$(reveal_count "$SHOWN")"
check "the holder is shown the password and username" "200 $BEFORE mysshtest" "$(shown "$HOLDER" "$SHOWN")"
check "...uncached" "no-store" "$(curl -s -D - -o /dev/null -X POST "$PAM/requests/$SHOWN/password?token=$HOLDER" \
    | tr -d '\r' | grep -i '^cache-control:' | grep -o no-store)"
check "...each display is recorded" 2 "$(reveal_count "$SHOWN")"
check "...and logged" yes "$(podman logs --since 1m myguactest 2>&1 | grep -q "User \"t2-holder\" viewed the password of \"t2 reveal managed\"" && echo yes || echo no)"
check "another user who may read it is not shown it" 400 "$(shown "$OTHER" "$SHOWN" | cut -d' ' -f1)"
check_contains "the history shows the displays" "'revealCount': 2" \
    "$(curl -s "$PAM/checkouts/history?token=$ADMIN&contains=T2%20reveal%20on" | python3 -I -c "import sys,json; print([{'revealCount': c['revealCount']} for c in json.load(sys.stdin)])")"

# ---------------------------------------------------------------- rotation
section "Rotated once released, although its mode is never"
SINCE=$(sql "SELECT $(sql_now)")
api POST "$PAM/requests/$SHOWN/release" "$HOLDER" >/dev/null
check "a rotation follows the release" yes "$(wait_for_rotation "$SHOWN" "$SINCE")"
AFTER=$(parameter "$SHOWN" password)
check "...the password changed" yes "$([ -n "$AFTER" ] && [ "$AFTER" != "$BEFORE" ] && echo yes)"
check "...the SSH server accepts the new one" yes "$(ssh_accepts mysshtest "$AFTER")"
check "...and refuses the one shown" no "$(ssh_accepts mysshtest "$BEFORE")"
check_contains "...logged as caused by the display" "Rotation (password shown) of connection \"t2 reveal managed\"" \
    "$(podman logs --since 1m myguactest 2>&1 | grep 'password shown')"

# A checkout that showed nothing leaves a "never" password alone
SINCE=$(sql "SELECT $(sql_now)")
api POST "$PAM/requests/$SHOWN" "$HOLDER" '{"reason":"T2 reveal unused"}' >/dev/null
api POST "$PAM/requests/$SHOWN/release" "$HOLDER" >/dev/null
sleep 8
check "a checkout that did not show the password is not followed by a rotation" "$AFTER" "$(parameter "$SHOWN" password)"

# ---------------------------------------------------------------- edge cases
section "Nothing of its own to show"
api POST "$PAM/requests/$GUAC_TOKEN" "$HOLDER" '{"reason":"T2 reveal token"}' >/dev/null
R=$(api POST "$PAM/requests/$GUAC_TOKEN/password" "$HOLDER")
check "a password that is Guacamole's token for the user's own is not shown" 400 "$(status_of "$R")"
check_contains "...saying there is none stored" "no stored password" "$(message_of "$R")"
api POST "$PAM/requests/$GUAC_TOKEN/release" "$HOLDER" >/dev/null
