#!/bin/bash
# Revoked access: open sessions close once their user may no longer read the
# connection, or it is deleted, and an administrator who loses the
# permission loses its powers within the same login. Sessions are checked
# every 15 seconds.

section "Setup"
create_connection REVOKED "{\"name\":\"t2 revoked ssh\",\"parentIdentifier\":\"ROOT\",\"protocol\":\"ssh\",
    \"parameters\":{\"hostname\":\"mysshtest\",\"port\":\"22\"},\"attributes\":{\"pam-request-exempt\":\"true\"}}"
# Created without a cleanup: it is deleted below
KEPT=$(json_get "$(api POST "$DATA/connections" "$ADMIN" "{\"name\":\"t2 kept ssh\",\"parentIdentifier\":\"ROOT\",
    \"protocol\":\"ssh\",\"parameters\":{\"hostname\":\"mysshtest\",\"port\":\"22\"},
    \"attributes\":{\"pam-request-exempt\":\"true\"}}" | cut -d' ' -f2-)" "d.get('identifier')")
create_user t2-revoked t2-revoked-pw
create_user t2-demoted t2-demoted-pw
grant_read t2-revoked "$REVOKED"
grant_read t2-revoked "$KEPT"
# Allowed to edit the connection without being an administrator, so only
# the extension refuses once the permission is gone
grant t2-demoted "[{\"op\":\"add\",\"path\":\"/systemPermissions\",\"value\":\"ADMINISTER\"},
    {\"op\":\"add\",\"path\":\"/connectionPermissions/$REVOKED\",\"value\":\"READ\"},
    {\"op\":\"add\",\"path\":\"/connectionPermissions/$REVOKED\",\"value\":\"UPDATE\"}]"
REVOKED_USER=$(token t2-revoked t2-revoked-pw)
DEMOTED=$(token t2-demoted t2-demoted-pw)
check "setup: connections and users exist" yes "$([ -n "$REVOKED$KEPT" ] && [ -n "$REVOKED_USER$DEMOTED" ] && echo yes)"

# open_session VARIABLE TOKEN ID: holds a session open in the background,
# setting VARIABLE to the file its state is written to ("open", "closed")
open_session() {
    local file="$T2_TMP/session-$1" i
    python3 -I ./session.py "$GUAC_URL" "$2" "$3" >"$file" 2>&1 &
    on_cleanup "kill $! 2>/dev/null"
    printf -v "$1" '%s' "$file"
    for i in $(seq 15); do grep -q . "$file" && break; sleep 1; done
}
session_state() { tail -1 "$1"; }

# wait_closed FILE: the state once closed, or after 30 seconds (two checks)
wait_closed() {
    local i
    for i in $(seq 30); do [ "$(session_state "$1")" = closed ] && break; sleep 1; done
    session_state "$1"
}

# ---------------------------------------------------------------- permission
section "Revoking the permission to read a connection"
open_session ON_REVOKED "$REVOKED_USER" "$REVOKED"
open_session ON_KEPT "$REVOKED_USER" "$KEPT"
check "a session of each connection is open" "open open" "$(session_state "$ON_REVOKED") $(session_state "$ON_KEPT")"
grant t2-revoked "[{\"op\":\"remove\",\"path\":\"/connectionPermissions/$REVOKED\",\"value\":\"READ\"}]"
check "the session of the revoked connection closes" closed "$(wait_closed "$ON_REVOKED")"
check "...while the other stays open" open "$(session_state "$ON_KEPT")"

# ---------------------------------------------------------------- deletion
section "Deleting a connection"
check "the connection still in use is deleted" 204 "$(status_of "$(api DELETE "$DATA/connections/$KEPT" "$ADMIN")")"
check "...and its session closes" closed "$(wait_closed "$ON_KEPT")"

# ---------------------------------------------------------------- administrator
section "An administrator losing the permission"
check "an administrator may change access requests" 204 \
    "$(status_of "$(edit_connection "$DEMOTED" "$REVOKED" '' '{"pam-checkout-duration":"45"}')")"
grant t2-demoted '[{"op":"remove","path":"/systemPermissions","value":"ADMINISTER"}]'
check "once no longer one, within the same login, they may not" \
    "403 Only administrators can change password management or access requests." \
    "$(R=$(edit_connection "$DEMOTED" "$REVOKED" '' '{"pam-checkout-duration":"50"}'); printf '%s %s' "$(status_of "$R")" "$(message_of "$R")")"
