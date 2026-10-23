#!/bin/bash
# Two Guacamole servers sharing the database (lab.sh guacamole --second): sessions seen
# by every server, checkouts ended on one server closing sessions on the
# other, one rotation of a connection at a time, and sessions of a server
# that stopped. Skipped unless the second server runs. About 3 minutes.

GUAC2_URL="${GUAC2_URL:-http://localhost:8081}"
PAM2="$GUAC2_URL/api/session/ext/pam"

if [ "$(podman inspect -f '{{.State.Running}}' myguactest2 2>/dev/null)" != true ]; then
    section "Skipped: no second server (start it with lab/lab.sh --second)"
    return 0
fi
for i in $(seq 90); do curl -sf "$GUAC2_URL/api/languages" >/dev/null && break; sleep 2; done

token2() {
    curl -s -d "username=$1" -d "password=$2" "$GUAC2_URL/api/tokens" | python3 -I -c "import sys,json;print(json.load(sys.stdin)['authToken'])"
}

# open_session VARIABLE URL TOKEN ID: holds a session open in the background,
# setting VARIABLE to the file its state is written to ("open", "closed")
open_session() {
    local file="$T2_TMP/session-$1" i
    python3 -I ./session.py "$2" "$3" "$4" >"$file" 2>&1 &
    echo $! >"$file.pid"
    on_cleanup "kill $! 2>/dev/null"
    printf -v "$1" '%s' "$file"
    for i in $(seq 15); do grep -q . "$file" && break; sleep 1; done
}
end_session() { kill "$(cat "$1.pid")" 2>/dev/null; }
session_state() { tail -1 "$1"; }

# wait_for SECONDS COMMAND...: prints yes once COMMAND prints yes, or no
wait_for() {
    local end=$((SECONDS + $1)); shift
    while [ $SECONDS -lt $end ]; do
        [ "$("$@")" = yes ] && { echo yes; return; }
        sleep 1
    done
    echo no
}

session_rows() { sql "SELECT count(*) FROM pam_session WHERE connection_id = $1"; }
# The helper reports "closed" at once; Guacamole ends the tunnel itself up to
# 15 seconds later, when the client's reads stop
session_rows_are() { [ "$(session_rows "$1")" = "$2" ] && echo yes || echo no; }
no_session_rows() { session_rows_are "$1" 0; }
is_closed() { [ "$(session_state "$1")" = closed ] && echo yes || echo no; }
password_changed() { [ "$(parameter "$1" password)" != "$2" ] && echo yes || echo no; }

# Open sessions of a managed connection, as one server lists them
active_sessions() { # PAM-URL TOKEN ID
    curl -s "$1/connections?token=$2" | python3 -I -c "
import sys,json
m=[c['activeSessions'] for c in json.load(sys.stdin) if c['identifier']==sys.argv[1]]
print(m[0] if m else '')" "$3"
}

section "Setup"
SEEDED=$(connection_id "PAM test (Linux)")
SSH_PASSWORD=$(known_ssh_password "$SEEDED")
check "precondition: mysshtest's current password is known" yes "$(ssh_accepts mysshtest "$SSH_PASSWORD")"

LINUX=$(platform_id "Unix")
# Slow enough to overlap: the account sleeps before changing its password
create_platform SLOW '{"name":"t2 slow passwd","type":"ssh","settings":{"script":"@timeout 20\nsleep 6; passwd\n@expect assword:\n<OLDPASS>\n@expect assword:\n<NEWPASS>\n@expect assword:\n<NEWPASS>\n@regex (?i)(success|updated|changed)\n"},"policy":{}}'
create_connection SSH_C "{\"name\":\"t2 servers ssh\",\"parentIdentifier\":\"ROOT\",\"protocol\":\"ssh\",
    \"parameters\":{\"hostname\":\"mysshtest\",\"port\":\"22\",\"username\":\"mysshtest\",\"password\":\"$SSH_PASSWORD\"},
    \"attributes\":{\"pam-platform\":\"$LINUX\",\"pam-request-exempt\":\"true\",\"pam-rotation-mode\":\"never\"}}"
create_connection GATED "{\"name\":\"t2 servers gated\",\"parentIdentifier\":\"ROOT\",\"protocol\":\"ssh\",
    \"parameters\":{\"hostname\":\"mysshtest\",\"port\":\"22\",\"username\":\"mysshtest\",\"password\":\"$SSH_PASSWORD\"},
    \"attributes\":{}}"
sync_seeded_ssh() {
    [ -n "$SEEDED" ] && edit_connection "$ADMIN" "$SEEDED" "{\"password\":\"$(parameter "$SSH_C" password)\"}" >/dev/null
}
on_cleanup sync_seeded_ssh

create_user t2-servers t2-servers-pw
grant_read t2-servers "$GATED"
grant_read t2-servers "$SSH_C"
USER1=$(token t2-servers t2-servers-pw)
USER2=$(token2 t2-servers t2-servers-pw)
ADMIN2=$(token2 "$GUAC_ADMIN" "$GUAC_ADMIN_PASSWORD")
check "setup: logged in on both servers" yes "$([ -n "$USER1" ] && [ -n "$USER2" ] && [ -n "$ADMIN2" ] && echo yes)"

# ---------------------------------------------------------------- sessions
section "Sessions are seen by every server"
open_session S2 "$GUAC2_URL" "$ADMIN2" "$SSH_C"
check "a session opens through server 2" open "$(session_state "$S2")"
check_contains "...recorded by server 2" "myguactest2/" "$(sql "SELECT server FROM pam_session WHERE connection_id = $SSH_C")"
check "server 1 counts it" 1 "$(active_sessions "$PAM" "$ADMIN" "$SSH_C")"
end_session "$S2"
check "once it ends, its record goes" yes "$(wait_for 40 no_session_rows "$SSH_C")"
check "...and server 1 no longer counts it" 0 "$(active_sessions "$PAM" "$ADMIN" "$SSH_C")"

# ---------------------------------------------------------------- checkouts
section "A checkout ended on one server closes sessions on the other"
check "the user checks out the gated connection on server 1" 200 \
    "$(status_of "$(api POST "$PAM/requests/$GATED" "$USER1" '{"reason":"T2 two servers"}')")"
open_session G2 "$GUAC2_URL" "$USER2" "$GATED"
check "...and opens it through server 2" open "$(session_state "$G2")"
ACTIVE=$(curl -s "$PAM/checkouts/active?token=$ADMIN" | python3 -I -c "
import sys,json
m=[c['id'] for c in json.load(sys.stdin) if c['username']=='t2-servers' and c['connectionIdentifier']==sys.argv[1]]
print(m[0] if m else '')" "$GATED")
check "the administrator revokes the checkout on server 1" 204 "$(status_of "$(api POST "$PAM/checkouts/$ACTIVE/revoke" "$ADMIN")")"
START=$SECONDS
check "server 2 closes the session within 30 seconds" yes "$(wait_for 30 is_closed "$G2")"
printf '        (closed after %d s)\n' $((SECONDS - START))
check_contains "...because the checkout ended" "its checkout ended on another server" \
    "$(podman logs --since 2m myguactest2 2>&1 | grep 't2 servers gated')"

# ---------------------------------------------------------------- after use
section "After-use rotation waits for sessions on every server"
edit_connection "$ADMIN" "$SSH_C" '' '{"pam-rotation-mode":"after-use"}' >/dev/null
PASSWORD=$(parameter "$SSH_C" password)
open_session A2 "$GUAC2_URL" "$ADMIN2" "$SSH_C"
check "a session is open through server 2" open "$(session_state "$A2")"
open_session B1 "$GUAC_URL" "$ADMIN" "$SSH_C"
check "another session opens through server 1" 2 "$(active_sessions "$PAM" "$ADMIN" "$SSH_C")"
end_session "$B1"
check "...and ends there" yes "$(wait_for 40 session_rows_are "$SSH_C" 1)"
sleep 12
check "server 1 does not rotate: the session on server 2 is still open" no "$(password_changed "$SSH_C" "$PASSWORD")"
end_session "$A2"
check "the session on server 2 ends" yes "$(wait_for 40 no_session_rows "$SSH_C")"
check "...then the password is rotated" yes "$(wait_for 30 password_changed "$SSH_C" "$PASSWORD")"
check "...and the server accepts the new one" yes "$(ssh_accepts mysshtest "$(parameter "$SSH_C" password)")"
edit_connection "$ADMIN" "$SSH_C" '' '{"pam-rotation-mode":"never"}' >/dev/null

# ---------------------------------------------------------------- one rotation at a time
section "One rotation of a connection at a time, across servers"
edit_connection "$ADMIN" "$SSH_C" '' "{\"pam-platform\":\"$SLOW\",\"pam-request-exempt\":null}" >/dev/null
api POST "$PAM/connections/$SSH_C/rotate" "$ADMIN" >"$T2_TMP/rotation1" &
ROTATION=$!
sleep 2
R=$(api POST "$PAM2/connections/$SSH_C/rotate" "$ADMIN2")
check "server 2 refuses a second rotation while server 1 rotates" "already running" \
    "$(message_of "$R" | grep -o 'already running')"
check "...and lists the connection as being rotated" yes \
    "$(curl -s "$PAM2/connections?token=$ADMIN2" | python3 -I -c "
import sys,json
print('yes' if any(c['identifier']==sys.argv[1] and c['rotating'] for c in json.load(sys.stdin)) else 'no')" "$SSH_C")"
check_contains "server 2 refuses a checkout meanwhile" "being rotated" \
    "$(message_of "$(api POST "$PAM2/requests/$SSH_C" "$USER2" '{"reason":"T2 during rotation"}')")"
wait $ROTATION
check "server 1's rotation succeeds" SUCCESS "$(json_get "$(cut -d' ' -f2- "$T2_TMP/rotation1")" "d.get('status')")"
check "...and the server accepts the new password" yes "$(ssh_accepts mysshtest "$(parameter "$SSH_C" password)")"
check "the refused checkout left nothing active" "[]" "$(curl -s "$PAM/checkouts/active?token=$ADMIN" | python3 -I -c "
import sys,json
print([c['id'] for c in json.load(sys.stdin) if c['connectionIdentifier']==sys.argv[1]])" "$SSH_C")"
edit_connection "$ADMIN" "$SSH_C" '' "{\"pam-platform\":\"$LINUX\",\"pam-request-exempt\":\"true\"}" >/dev/null

# ---------------------------------------------------------------- stopped servers
section "Sessions of a server that stopped"
check "precondition: no session open" yes "$(wait_for 40 no_session_rows "$SSH_C")"
sleep 10 # lets after-use rotations of earlier sessions finish
edit_connection "$ADMIN" "$SSH_C" '' '{"pam-rotation-mode":"after-use"}' >/dev/null
PASSWORD=$(parameter "$SSH_C" password)
sql "INSERT INTO pam_session (session_id, connection_id, username, server, started, heartbeat)
     VALUES ('t2-fresh', $SSH_C, 't2-servers', 't2-running', $(sql_now), $(sql_now))" >/dev/null
check "a session recorded by another running server counts" 1 "$(active_sessions "$PAM" "$ADMIN" "$SSH_C")"
sql "UPDATE pam_session SET server = 't2-stopped', started = $(sql_ago 3600),
     heartbeat = $(sql_ago 600) WHERE session_id = 't2-fresh'" >/dev/null
check "once its heartbeat is stale, it no longer counts" 0 "$(active_sessions "$PAM" "$ADMIN" "$SSH_C")"
check "a server removes it, and rotates the connection after use" yes "$(wait_for 90 password_changed "$SSH_C" "$PASSWORD")"
check "...and the server accepts the new password" yes "$(ssh_accepts mysshtest "$(parameter "$SSH_C" password)")"
check "...and the stale record is gone" 0 "$(session_rows "$SSH_C")"
edit_connection "$ADMIN" "$SSH_C" '' '{"pam-rotation-mode":"never"}' >/dev/null
