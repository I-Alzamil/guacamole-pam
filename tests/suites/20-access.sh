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
check_contains "...in a response that is never cached" "no-store" "$(grep -i '^cache-control' "$T2_TMP/headers")"
check "the requester releases it" 204 "$(status_of "$(api POST "$PAM/requests/$ACCOUNT/release" "$REQUESTER")")"
check "...after which there is no password without a new request" 202 "$(status_of "$(api POST "$PAM/requests/$ACCOUNT" "$REQUESTER" '{"reason":"again"}')")"

# ---------------------------------------------------------------- deny, cancel, self-approval
section "Denials, cancellations and self-approval"
ID=$(pending_id t2-requester)
check_contains "a denial needs a reason" "reason for the denial" "$(message_of "$(api POST "$PAM/approvals/$ID/deny" "$APPROVER1" '{}')")"
check "approver 1 denies with a reason" 204 "$(status_of "$(api POST "$PAM/approvals/$ID/deny" "$APPROVER1" '{"reason":"Not this week"}')")"
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

# ---------------------------------------------------------------- connections needing a checkout
section "Connections that need a checkout"
check_contains "the gated connection refuses a session without a checkout" "403 You must request access" "$(tunnel "$REQUESTER" "$GATED" c)"
check "the open connection needs no request" 200 "$(tunnel "$REQUESTER" "$OPEN" c)"
check_contains "an Account refuses any session, as forbidden (which the web UI explains)" "403 This is an Account" "$(tunnel "$REQUESTER" "$ACCOUNT" c)"
check "the requester checks out the gated connection" 200 "$(status_of "$(api POST "$PAM/requests/$GATED" "$REQUESTER" '{"reason":"T2 maintenance"}')")"
check "...and can now open it" 200 "$(tunnel "$REQUESTER" "$GATED" c)"
ACTIVE=$(curl -s "$PAM/checkouts/active?token=$ADMIN" | python3 -I -c "
import sys,json
m=[c['id'] for c in json.load(sys.stdin) if c['username']=='t2-requester' and c['connectionIdentifier']==sys.argv[1]]
print(m[0] if m else '')" "$GATED")
check "the administrator sees the active checkout" yes "$([ -n "$ACTIVE" ] && echo yes)"
check "the administrator revokes it" 204 "$(status_of "$(api POST "$PAM/checkouts/$ACTIVE/revoke" "$ADMIN")")"
check_contains "...and the connection refuses a new session" "403 You must request access" "$(tunnel "$REQUESTER" "$GATED" c)"

# ---------------------------------------------------------------- administrators
section "Administrators (default: give a reason, skip approvals)"
check_contains "an administrator must give a reason too" "reason" "$(message_of "$(api POST "$PAM/requests/$ACCOUNT" "$ADMIN" '{}')")"
GRANT=$(api POST "$PAM/requests/$ACCOUNT" "$ADMIN" '{"reason":"T2 admin access"}')
check "...but gets the password without approvals" "200 $ACCOUNT_PASSWORD" "$(status_of "$GRANT") $(json_get "${GRANT#* }" "d.get('password')")"
api POST "$PAM/requests/$ACCOUNT/release" "$ADMIN" >/dev/null
check_contains "an administrator also needs a checkout to connect" "403 You must request access" "$(tunnel "$ADMIN" "$GATED" c)"

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
