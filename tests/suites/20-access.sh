#!/bin/bash
# Access requests: reasons, approvals by distinct approvers (directly or
# through a group), denials, cancellations, checkouts of Accounts and of
# connections, and what administrators skip.

ACCOUNT_PASSWORD='T2-Account-Pw1!'

section "Setup"
create_connection ACCOUNT "{\"name\":\"t2 account\",\"parentIdentifier\":\"ROOT\",\"protocol\":\"pam-account\",
    \"parameters\":{\"username\":\"svc-t2\",\"password\":\"$ACCOUNT_PASSWORD\",\"account-url\":\"https://t2.example\"},
    \"attributes\":{\"pam-approvals-required\":\"2\",\"pam-checkout-duration\":\"30\"}}"
create_connection GATED "{\"name\":\"t2 gated ssh\",\"parentIdentifier\":\"ROOT\",\"protocol\":\"ssh\",
    \"parameters\":{\"hostname\":\"mysshtest\",\"port\":\"22\"},\"attributes\":{}}"
create_connection OPEN "{\"name\":\"t2 open ssh\",\"parentIdentifier\":\"ROOT\",\"protocol\":\"ssh\",
    \"parameters\":{\"hostname\":\"mysshtest\",\"port\":\"22\"},\"attributes\":{\"pam-request-exempt\":\"true\"}}"

create_user t2-requester t2-requester-pw
create_user t2-approver1 t2-approver1-pw "{\"pam-approver\":\"true\",\"pam-approver-connections\":\"[\\\"$ACCOUNT\\\"]\"}"
create_user t2-approver2 t2-approver2-pw
create_user t2-outsider t2-outsider-pw
create_user_group t2-approvers "{\"pam-approver\":\"true\",\"pam-approver-connections\":\"[\\\"$ACCOUNT\\\"]\"}" t2-approver2
for c in $ACCOUNT $GATED $OPEN; do grant_read t2-requester "$c"; done
grant_read t2-approver1 "$ACCOUNT"

REQUESTER=$(token t2-requester t2-requester-pw)
APPROVER1=$(token t2-approver1 t2-approver1-pw)
APPROVER2=$(token t2-approver2 t2-approver2-pw)
OUTSIDER=$(token t2-outsider t2-outsider-pw)
check "setup: connections and users exist" yes "$([ -n "$ACCOUNT$GATED$OPEN" ] && [ -n "$REQUESTER" ] && [ -n "$APPROVER2" ] && echo yes)"

pending_id() { # USERNAME -> id of their pending request
    curl -s "$PAM/approvals/pending?token=$ADMIN" | python3 -I -c "
import sys,json
m=[r['id'] for r in json.load(sys.stdin) if r['username']==sys.argv[1]]
print(m[0] if m else '')" "$1"
}

# ---------------------------------------------------------------- listing
section "What a user may request"
LISTED=$(curl -s "$PAM/requests?token=$REQUESTER" | python3 -I -c "import sys,json;print(sorted(r['name'] for r in json.load(sys.stdin)))")
check "listed: the Account and the gated connection, not the open one" "['t2 account', 't2 gated ssh']" "$LISTED"
check "an outsider cannot see the Account's request" 403 "$(status_of "$(api GET "$PAM/requests/$ACCOUNT" "$OUTSIDER")")"

section "An LDAP account's DN, shown only if its platform says so"
LDAP_PLATFORM_JSON='{"name":"t2 access ldap","type":"ldap","settings":{"hostname":"myldaptest","ldap-encryption":"none"%s},"policy":{"rotation-mode":"never"}}'
create_platform DN_PLATFORM "$(printf "$LDAP_PLATFORM_JSON" '')"
create_connection DN_ACCOUNT "{\"name\":\"t2 dn account\",\"parentIdentifier\":\"ROOT\",\"protocol\":\"pam-account\",
    \"parameters\":{\"username\":\"t2-dn\",\"password\":\"x\"},
    \"attributes\":{\"pam-platform\":\"$DN_PLATFORM\",\"pam-ldap-dn\":\"uid=t2-dn,ou=people,dc=example,dc=org\"}}"
grant_read t2-requester "$DN_ACCOUNT"
account_dn() { json_get "$(api GET "$PAM/requests/$DN_ACCOUNT" "$REQUESTER" | cut -d' ' -f2-)" "d.get('accountName') + ' ' + str(d.get('accountDn'))"; }
check "by default, the requester sees the username only" "t2-dn None" "$(account_dn)"
api PUT "$PAM/platforms/$DN_PLATFORM" "$ADMIN" "$(printf "$LDAP_PLATFORM_JSON" ',"ldap-show-dn":"true"')" >/dev/null
check "...and its DN too once the platform shows it" "t2-dn uid=t2-dn,ou=people,dc=example,dc=org" "$(account_dn)"

# ---------------------------------------------------------------- approvals
section "Two approvals by distinct approvers"
R=$(api POST "$PAM/requests/$ACCOUNT" "$REQUESTER" '{}')
check_contains "a reason is required" "reason" "$(message_of "$R")"
R=$(api POST "$PAM/requests/$ACCOUNT" "$REQUESTER" '{"reason":"T2 ticket 1"}')
check "with a reason, the request awaits approval (202)" 202 "$(status_of "$R")"
ID=$(pending_id t2-requester)

R=$(api POST "$PAM/approvals/$ID/approve" "$OUTSIDER")
check "a non-approver gets 'no such request' for an existing request" "404 No such request." "$(status_of "$R") $(message_of "$R")"
R=$(api POST "$PAM/approvals/999999/approve" "$OUTSIDER")
check "...exactly as for a missing one" "404 No such request." "$(status_of "$R") $(message_of "$R")"
check "a non-approver sees no pending requests" "[]" "$(api GET "$PAM/approvals/pending" "$OUTSIDER" | cut -d' ' -f2-)"

R=$(api POST "$PAM/approvals/$ID/approve" "$APPROVER1")
check "approver 1 (own permission) approves: 1 of 2" "200 ['t2-approver1']" "$(status_of "$R") $(json_get "${R#* }" "d['approvers']")"
check_contains "approver 1 cannot approve twice" "already approved" "$(message_of "$(api POST "$PAM/approvals/$ID/approve" "$APPROVER1")")"
R=$(api POST "$PAM/requests/$ACCOUNT" "$REQUESTER" '{"reason":"T2 ticket 1"}')
check "no password before the second approval" 202 "$(status_of "$R")"

R=$(api POST "$PAM/approvals/$ID/approve" "$APPROVER2")
check "approver 2 (through a group) approves: request approved" "200 APPROVED" "$(status_of "$R") $(json_get "${R#* }" "d['status']")"

GRANT=$(curl -s -D "$T2_TMP/headers" -X POST -H 'Content-Type: application/json' -d '{}' "$PAM/requests/$ACCOUNT?token=$REQUESTER")
check "the requester now gets the password" "$ACCOUNT_PASSWORD" "$(json_get "$GRANT" "d.get('password')")"
REQUESTED_FROM=$(sql "SELECT remote_host FROM pam_request WHERE request_id = $ID")
check "...in a checkout keeping the remote host the request came from" "yes $REQUESTED_FROM" \
    "$([ -n "$REQUESTED_FROM" ] && echo yes) $(sql "SELECT k.remote_host
        FROM pam_checkout k JOIN pam_request r ON r.checkout_id = k.checkout_id WHERE r.request_id = $ID")"
check_contains "...in a response that is never cached" "no-store" "$(grep -i '^cache-control' "$T2_TMP/headers")"
APPROVALS=$(curl -s -G --data-urlencode "contains=T2 ticket 1" "$PAM/approvals/history?token=$ADMIN" | python3 -I -c "
import sys,json
r=[r for r in json.load(sys.stdin) if r['id']==int(sys.argv[1])][0]
print(' '.join('%s@%s' % (a['approver'], a.get('remoteHost') or '') for a in r['approvals']))" "$ID")
check "each approval keeps where its approver approved from" \
    "t2-approver1@$REQUESTED_FROM t2-approver2@$REQUESTED_FROM" "$APPROVALS"
check "the checkout lists those approvals too" "t2-approver1@$REQUESTED_FROM t2-approver2@$REQUESTED_FROM" \
    "$(curl -s -G --data-urlencode "contains=T2 ticket 1" "$PAM/checkouts/history?token=$ADMIN" | python3 -I -c "
import sys,json
c=[c for c in json.load(sys.stdin) if c.get('approvals')][0]
print(' '.join('%s@%s' % (a['approver'], a.get('remoteHost') or '') for a in c['approvals']))")"
check "...and the history can be searched by it" yes "$(curl -s -G --data-urlencode "contains=$REQUESTED_FROM" \
    --data-urlencode "contains=T2 ticket 1" "$PAM/approvals/history?token=$ADMIN" | python3 -I -c "
import sys,json; print('yes' if any(r['id']==int(sys.argv[1]) for r in json.load(sys.stdin)) else 'no')" "$ID")"
check "the requester releases it" 204 "$(status_of "$(api POST "$PAM/requests/$ACCOUNT/release" "$REQUESTER")")"
check "...after which there is no password without a new request" 202 "$(status_of "$(api POST "$PAM/requests/$ACCOUNT" "$REQUESTER" '{"reason":"again"}')")"

# ---------------------------------------------------------------- deny, cancel, self-approval
section "Denials, cancellations and self-approval"
ID=$(pending_id t2-requester)
check_contains "a denial needs a reason" "reason for the denial" "$(message_of "$(api POST "$PAM/approvals/$ID/deny" "$APPROVER1" '{}')")"
check "approver 1 denies with a reason" 204 "$(status_of "$(api POST "$PAM/approvals/$ID/deny" "$APPROVER1" '{"reason":"Not this week"}')")"
check "...kept with where they denied it from" "t2-approver1 $REQUESTED_FROM" \
    "$(sql "SELECT decided_by, decided_host FROM pam_request WHERE request_id = $ID" | tr '\t' ' ')"
LATEST=$(api GET "$PAM/requests/$ACCOUNT" "$REQUESTER" | cut -d' ' -f2-)
check "the requester sees the denial and its reason" "DENIED Not this week" \
    "$(json_get "$LATEST" "str(d.get('lastStatus')) + ' ' + str(d.get('lastDecisionReason'))")"

api POST "$PAM/requests/$ACCOUNT" "$REQUESTER" '{"reason":"T2 ticket 2"}' >/dev/null
ID=$(pending_id t2-requester)
check "the requester cancels their request" 204 "$(status_of "$(api DELETE "$PAM/requests/$ACCOUNT/pending" "$REQUESTER")")"
check_contains "a cancelled request can no longer be approved" "no longer awaiting approval" \
    "$(message_of "$(api POST "$PAM/approvals/$ID/approve" "$APPROVER1")")"

api POST "$PAM/requests/$ACCOUNT" "$APPROVER1" '{"reason":"my own"}' >/dev/null
ID=$(pending_id t2-approver1)
check_contains "an approver cannot approve their own request" "cannot approve your own" \
    "$(message_of "$(api POST "$PAM/approvals/$ID/approve" "$APPROVER1")")"
check_contains "...nor deny it" "cannot decide on your own" \
    "$(message_of "$(api POST "$PAM/approvals/$ID/deny" "$APPROVER1" '{"reason":"x"}')")"
api DELETE "$PAM/requests/$ACCOUNT/pending" "$APPROVER1" >/dev/null

# ---------------------------------------------------------------- simultaneous approvals
section "The last two approvals given at once"

# Both approvers may see the request complete: only the one claiming it
# starts the checkout. Another approver's claim, as while it starts it:
api POST "$PAM/requests/$ACCOUNT" "$REQUESTER" '{"reason":"T2 claimed"}' >/dev/null
ID=$(pending_id t2-requester)
api POST "$PAM/approvals/$ID/approve" "$APPROVER1" >/dev/null
sql "UPDATE pam_request SET decided_by = 't2-approver1' WHERE request_id = $ID" >/dev/null
R=$(api POST "$PAM/approvals/$ID/approve" "$APPROVER2")
check "the other approver completing it too: answered, leaving the rest to the claim's holder" "200 PENDING" \
    "$(status_of "$R") $(json_get "${R#* }" "d['status']")"
check "...keeping their approval, starting no checkout" "2 0" \
    "$(sql "SELECT COUNT(*) FROM pam_request_approval WHERE request_id = $ID") $(sql "SELECT COUNT(*)
        FROM pam_checkout WHERE connection_id = $ACCOUNT AND username = 't2-requester' AND released IS NULL")"
sql "UPDATE pam_request SET decided_by = NULL WHERE request_id = $ID" >/dev/null
api DELETE "$PAM/requests/$ACCOUNT/pending" "$REQUESTER" >/dev/null

# The two at once, repeated, as they rarely meet
race_failures=()
for round in 1 2 3 4; do
    api POST "$PAM/requests/$ACCOUNT" "$REQUESTER" "{\"reason\":\"T2 race $round\"}" >/dev/null
    ID=$(pending_id t2-requester)
    curl -s -o /dev/null -w '%{http_code}' -X POST "$PAM/approvals/$ID/approve?token=$APPROVER1" > "$T2_TMP/race1" &
    curl -s -o /dev/null -w '%{http_code}' -X POST "$PAM/approvals/$ID/approve?token=$APPROVER2" > "$T2_TMP/race2" &
    wait
    OUTCOME="$(cat "$T2_TMP/race1") $(cat "$T2_TMP/race2") $(sql "SELECT status FROM pam_request WHERE request_id = $ID")"
    OUTCOME+=" $(sql "SELECT COUNT(*) FROM pam_request_approval WHERE request_id = $ID")"
    OUTCOME+=" $(sql "SELECT COUNT(*) FROM pam_checkout WHERE connection_id = $ACCOUNT AND username = 't2-requester'
        AND released IS NULL")"
    [ "$OUTCOME" = "200 200 APPROVED 2 1" ] || race_failures+=("round $round: $OUTCOME")
    api POST "$PAM/requests/$ACCOUNT/release" "$REQUESTER" >/dev/null
done
check "...both answered, approved with both approvals, one checkout (4 rounds)" "" "${race_failures[*]}"

# ---------------------------------------------------------------- who may approve
section "Approvers through connection groups and nested user groups"

# An Account two connection groups deep
create_group OUTER '{"name":"t2 approvals outer","parentIdentifier":"ROOT","type":"ORGANIZATIONAL","attributes":{}}'
create_group INNER "{\"name\":\"t2 approvals inner\",\"parentIdentifier\":\"$OUTER\",\"type\":\"ORGANIZATIONAL\",\"attributes\":{}}"
create_connection DEEP "{\"name\":\"t2 deep account\",\"parentIdentifier\":\"$INNER\",\"protocol\":\"pam-account\",
    \"parameters\":{\"username\":\"svc-t2-deep\",\"password\":\"T2-Deep-Pw1!\"},\"attributes\":{\"pam-approvals-required\":\"1\"}}"
grant_read t2-requester "$DEEP"

create_user t2-by-group t2-by-group-pw "{\"pam-approver\":\"true\",\"pam-approver-connection-groups\":\"[\\\"$OUTER\\\"]\"}"
create_user t2-by-root t2-by-root-pw '{"pam-approver":"true","pam-approver-connection-groups":"[\"ROOT\"]"}'
create_user t2-nested t2-nested-pw
create_user t2-disabled t2-disabled-pw
create_user_group t2-deep-approvers "{\"pam-approver\":\"true\",\"pam-approver-connections\":\"[\\\"$DEEP\\\"]\"}"
create_user_group t2-deep-members '{}' t2-nested
add_member_group t2-deep-approvers t2-deep-members >/dev/null
DISABLED_ATTRIBUTES="{\"pam-approver\":\"true\",\"pam-approver-connections\":\"[\\\"$DEEP\\\"]\"}"
create_user_group t2-deep-disabled "$DISABLED_ATTRIBUTES" t2-disabled
api PUT "$DATA/userGroups/t2-deep-disabled" "$ADMIN" \
    "{\"identifier\":\"t2-deep-disabled\",\"disabled\":true,\"attributes\":$DISABLED_ATTRIBUTES}" >/dev/null

api POST "$PAM/requests/$DEEP" "$REQUESTER" '{"reason":"T2 deep"}' >/dev/null
ID=$(pending_id t2-requester)
sees() { # USERNAME PASSWORD -> whether they see the request awaiting approval
    curl -s "$PAM/approvals/pending?token=$(token "$1" "$2")" | python3 -I -c "
import sys,json; print('yes' if any(r['id']==int(sys.argv[1]) for r in json.load(sys.stdin)) else 'no')" "$ID"
}
check "an approver for a connection group, of a connection in a group within it" yes "$(sees t2-by-group t2-by-group-pw)"
check "an approver for ROOT, of any connection" yes "$(sees t2-by-root t2-by-root-pw)"
check "an approver through a group within the approvers' group" yes "$(sees t2-nested t2-nested-pw)"
check "not through a disabled group" no "$(sees t2-disabled t2-disabled-pw)"
check "not the approvers of other connections" no "$(sees t2-approver1 t2-approver1-pw)"
R=$(api POST "$PAM/approvals/$ID/approve" "$(token t2-nested t2-nested-pw)")
check "...and the nested one approves it" "200 APPROVED" "$(status_of "$R") $(json_get "${R#* }" "d['status']")"
api POST "$PAM/requests/$DEEP/release" "$REQUESTER" >/dev/null

# ---------------------------------------------------------------- connections needing a checkout
section "Connections that need a checkout"
check_contains "the gated connection refuses a session without a checkout" "403 You must request access" "$(tunnel "$REQUESTER" "$GATED" c)"
check "the open connection needs no request" 200 "$(tunnel "$REQUESTER" "$OPEN" c)"
check_contains "an Account refuses any session, as forbidden (which the web UI explains)" "403 This is an Account" "$(tunnel "$REQUESTER" "$ACCOUNT" c)"
check "the requester checks out the gated connection" 200 "$(status_of "$(api POST "$PAM/requests/$GATED" "$REQUESTER" '{"reason":"T2 maintenance"}')")"
check "...and can now open it" 200 "$(tunnel "$REQUESTER" "$GATED" c)"
# The browser counts down by the server's time, not by its own clock
check "the server's time is that its checkout ends by, the duration before its end" yes \
    "$(json_get "$(api GET "$PAM/requests/$GATED" "$REQUESTER" | cut -d' ' -f2-)" \
        "d['expires'], d['durationMinutes']" | tr -d '(),' | {
        read -r expires minutes
        now=$(json_get "$(api GET "$PAM/time" "$REQUESTER" | cut -d' ' -f2-)" "d['now']")
        left=$(( (expires - now) / 1000 ))
        [ "$left" -gt $(( minutes * 60 - 30 )) ] && [ "$left" -le $(( minutes * 60 )) ] && echo yes || echo "$left s left"; })"
ACTIVE=$(curl -s "$PAM/checkouts/active?token=$ADMIN" | python3 -I -c "
import sys,json
m=[c['id'] for c in json.load(sys.stdin) if c['username']=='t2-requester' and c['connectionIdentifier']==sys.argv[1]]
print(m[0] if m else '')" "$GATED")
check "the administrator sees the active checkout" yes "$([ -n "$ACTIVE" ] && echo yes)"
HOST=$(curl -s "$PAM/checkouts/active?token=$ADMIN" | python3 -I -c "
import sys,json; print([c.get('remoteHost') or '' for c in json.load(sys.stdin) if c['id']==int(sys.argv[1])][0])" "$ACTIVE")
check "...with the remote host the user requested from" yes "$([ -n "$HOST" ] && echo yes)"
check "...as Guacamole's connection history records it for the session" "$HOST" \
    "$(sql "SELECT remote_host FROM guacamole_connection_history WHERE history_id = (SELECT max(history_id)
        FROM guacamole_connection_history WHERE username = 't2-requester' AND connection_id = $GATED)")"
check "...and the history can be searched by it" yes "$(curl -s -G --data-urlencode "contains=$HOST" \
    --data-urlencode "contains=T2 maintenance" "$PAM/checkouts/history?token=$ADMIN" | python3 -I -c "
import sys,json; print('yes' if any(c['id']==int(sys.argv[1]) for c in json.load(sys.stdin)) else 'no')" "$ACTIVE")"
check "the administrator revokes it" 204 "$(status_of "$(api POST "$PAM/checkouts/$ACTIVE/revoke" "$ADMIN")")"
check "...kept with where they revoked it from" "$GUAC_ADMIN yes" \
    "$(sql "SELECT released_by FROM pam_checkout WHERE checkout_id = $ACTIVE") $([ -n "$(sql "SELECT released_host
        FROM pam_checkout WHERE checkout_id = $ACTIVE")" ] && echo yes)"
check_contains "...and the connection refuses a new session" "403 You must request access" "$(tunnel "$REQUESTER" "$GATED" c)"

# The periodic check ends expired checkouts every 2 seconds; until then,
# they must not count
section "A checkout past its time limit, not ended yet"
check "the requester checks out the gated connection again" 200 \
    "$(status_of "$(api POST "$PAM/requests/$GATED" "$REQUESTER" '{"reason":"T2 expiry"}')")"
sql "UPDATE pam_checkout SET expires = $(sql_ago 1)
    WHERE connection_id = $GATED AND released IS NULL" >/dev/null
check_contains "once past its time limit, it opens no session" "403 You must request access" "$(tunnel "$REQUESTER" "$GATED" c)"
check "...and a new request is granted at once" 200 \
    "$(status_of "$(api POST "$PAM/requests/$GATED" "$REQUESTER" '{"reason":"T2 expiry again"}')")"
# Of this run's connection only: earlier runs' stay in the history
EXPIRED_REASON=$(curl -s -G --data-urlencode "contains=T2 expiry" "$PAM/checkouts/history?token=$ADMIN" | python3 -I -c "
import sys,json
print(' '.join(c.get('releaseReason') or 'ACTIVE' for c in json.load(sys.stdin)
    if c.get('connectionIdentifier') == sys.argv[1] and c['reason'] in ('T2 expiry', 'T2 expiry again')))" "$GATED")
check "...the expired one ended as expired" "ACTIVE EXPIRED" "$EXPIRED_REASON"
api POST "$PAM/requests/$GATED/release" "$REQUESTER" >/dev/null

# ---------------------------------------------------------------- administrators
section "Administrators (default: give a reason, skip approvals)"
check_contains "an administrator must give a reason too" "reason" "$(message_of "$(api POST "$PAM/requests/$ACCOUNT" "$ADMIN" '{}')")"
GRANT=$(api POST "$PAM/requests/$ACCOUNT" "$ADMIN" '{"reason":"T2 admin access"}')
check "...but gets the password without approvals" "200 $ACCOUNT_PASSWORD" "$(status_of "$GRANT") $(json_get "${GRANT#* }" "d.get('password')")"
api POST "$PAM/requests/$ACCOUNT/release" "$ADMIN" >/dev/null
check_contains "an administrator also needs a checkout to connect" "403 You must request access" "$(tunnel "$ADMIN" "$GATED" c)"

section "Administrators needing approvals (pam-admin-require-approvals)"
admin_approvals() { api PUT "$PAM/settings" "$ADMIN" "{\"pam-admin-require-approvals\":$1}" >/dev/null; }
admin_approvals true
on_cleanup admin_approvals null
R=$(api POST "$PAM/requests/$ACCOUNT" "$ADMIN" '{"reason":"T2 admin approval"}')
check "an administrator's request now awaits approval (202)" 202 "$(status_of "$R")"
ADMIN_ID=$(curl -s "$PAM/approvals/pending?token=$APPROVER1" | python3 -I -c "
import sys,json
m=[r['id'] for r in json.load(sys.stdin) if r['username']==sys.argv[1]]
print(m[0] if m else '')" "$GUAC_ADMIN")
R=$(api POST "$PAM/approvals/${ADMIN_ID:-0}/approve" "$ADMIN")
check "...which the administrator cannot approve themselves" "400 You cannot approve your own request." \
    "$(status_of "$R") $(message_of "$R")"
api POST "$PAM/approvals/$ADMIN_ID/approve" "$APPROVER1" >/dev/null
check "...and one approval of the two is not enough" 202 \
    "$(status_of "$(api POST "$PAM/requests/$ACCOUNT" "$ADMIN" '{"reason":"T2 admin approval"}')")"
api POST "$PAM/approvals/$ADMIN_ID/approve" "$APPROVER2" >/dev/null
GRANT=$(api POST "$PAM/requests/$ACCOUNT" "$ADMIN" '{}')
check "...the second one grants it" "200 $ACCOUNT_PASSWORD" "$(status_of "$GRANT") $(json_get "${GRANT#* }" "d.get('password')")"
api POST "$PAM/requests/$ACCOUNT/release" "$ADMIN" >/dev/null
api PUT "$PAM/settings" "$ADMIN" '{"pam-admin-bypass-requests":true}' >/dev/null
check "letting administrators bypass requests overrides it" yes \
    "$(json_get "$(api GET "$PAM/requests/$ACCOUNT" "$ADMIN" | cut -d' ' -f2-)" "'yes' if d['bypass'] and d['approvalsRequired'] == 0 else d")"
api PUT "$PAM/settings" "$ADMIN" '{"pam-admin-bypass-requests":null}' >/dev/null
admin_approvals null

# ---------------------------------------------------------------- deletion
section "Deleting a connection keeps its history"
# Created without a cleanup: deleting it is the test. Its history stays, so
# its name is new on every run
DOOMED_NAME="t2 doomed $(date +%s%N)"
DOOMED=$(json_get "$(api POST "$DATA/connections" "$ADMIN" "{\"name\":\"$DOOMED_NAME\",\"parentIdentifier\":\"ROOT\",
    \"protocol\":\"ssh\",\"parameters\":{\"hostname\":\"mysshtest\",\"port\":\"22\"},
    \"attributes\":{\"pam-approvals-required\":\"1\"}}" | cut -d' ' -f2-)" "d.get('identifier')")
grant_read t2-requester "$DOOMED"
check "a request awaits approval" 202 "$(status_of "$(api POST "$PAM/requests/$DOOMED" "$REQUESTER" '{"reason":"T2 doomed"}')")"
check "the administrator holds it" 200 "$(status_of "$(api POST "$PAM/requests/$DOOMED" "$ADMIN" '{"reason":"T2 doomed admin"}')")"
check "the connection is deleted" 204 "$(status_of "$(api DELETE "$DATA/connections/$DOOMED" "$ADMIN")")"
ENDED=$(curl -s -G --data-urlencode "contains=$DOOMED_NAME" "$PAM/checkouts/history?token=$ADMIN" | python3 -I -c "
import sys,json
print(' '.join('%s/%s/%s' % (c['connectionName'], c.get('releaseReason'), c.get('connectionIdentifier')) for c in json.load(sys.stdin)))")
check "its checkout stays in the history, ended by the deletion" "$DOOMED_NAME/DELETED/None" "$ENDED"
CANCELLED=$(curl -s -G --data-urlencode "contains=$DOOMED_NAME" "$PAM/approvals/history?token=$ADMIN" | python3 -I -c "
import sys,json
print(' '.join('%s/%s' % (r['connectionName'], r['status']) for r in json.load(sys.stdin)))")
check "its pending request stays too, cancelled" "$DOOMED_NAME/CANCELLED" "$CANCELLED"
check "nothing is left awaiting approval for it" "" "$(pending_id t2-requester)"
