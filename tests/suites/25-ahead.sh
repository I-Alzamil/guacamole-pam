#!/bin/bash
# Requests ahead of time: approved before they start, they reserve the
# connection for their time, which its requester checks out with; others'
# checkouts of a connection checked out alone leave room for them. Times
# are moved in the database rather than waited for.

ACCOUNT_PASSWORD='T25-Account-Pw1!'

section "Setup"
create_connection ACCOUNT "{\"name\":\"t25 account\",\"parentIdentifier\":\"ROOT\",\"protocol\":\"pam-account\",
    \"parameters\":{\"username\":\"svc-t25\",\"password\":\"$ACCOUNT_PASSWORD\"},
    \"attributes\":{\"pam-approvals-required\":\"1\",\"pam-checkout-duration\":\"30\",\"pam-checkout-exclusive\":\"yes\"}}"
create_connection GATED "{\"name\":\"t25 gated ssh\",\"parentIdentifier\":\"ROOT\",\"protocol\":\"ssh\",
    \"parameters\":{\"hostname\":\"mysshtest\",\"port\":\"22\"},\"attributes\":{}}"

create_user t25-alice t25-alice-pw
create_user t25-bob t25-bob-pw
create_user t25-approver t25-approver-pw "{\"pam-approver\":\"true\",\"pam-approver-connections\":\"[\\\"$ACCOUNT\\\"]\"}"
for u in t25-alice t25-bob; do grant_read $u "$ACCOUNT"; grant_read $u "$GATED"; done

ALICE=$(token t25-alice t25-alice-pw)
BOB=$(token t25-bob t25-bob-pw)
APPROVER=$(token t25-approver t25-approver-pw)
check "setup: connections and users exist" yes "$([ -n "$ACCOUNT$GATED" ] && [ -n "$ALICE" ] && [ -n "$APPROVER" ] && echo yes)"

now_ms() { echo $(( $(date +%s%3N) )); }
in_ms() { echo $(( $(now_ms) + $1 * 1000 )); } # SECONDS -> epoch milliseconds

pending_of() { # USERNAME -> id of their pending request for the Account
    curl -s "$PAM/approvals/pending?token=$ADMIN" | python3 -I -c "
import sys,json
m=[r['id'] for r in json.load(sys.stdin) if r['username']==sys.argv[1] and r['connectionIdentifier']==sys.argv[2]]
print(m[0] if m else '')" "$1" "$ACCOUNT"
}

ask_ahead() { # TOKEN REASON STARTS-MS -> "HTTP-STATUS BODY"
    api POST "$PAM/requests/$ACCOUNT" "$1" "{\"reason\":\"$2\",\"starts\":\"$3\"}"
}

# ---------------------------------------------------------------- refusals
section "What can be requested ahead of time"
check_contains "only access needing approval" "needing approval" \
    "$(message_of "$(api POST "$PAM/requests/$GATED" "$ALICE" "{\"reason\":\"x\",\"starts\":\"$(in_ms 3600)\"}")")"
check_contains "a start in the past is refused" "in the future" "$(message_of "$(ask_ahead "$ALICE" past "$(in_ms -600)")")"
check_contains "...and one over 30 days ahead" "30 days" "$(message_of "$(ask_ahead "$ALICE" far "$(in_ms $((31 * 86400)))")")"
check_contains "...and one that is no time" "Invalid start" "$(message_of "$(ask_ahead "$ALICE" bad soon)")"
check "nothing was left awaiting approval" "" "$(pending_of t25-alice)"

# ---------------------------------------------------------------- reserving
section "Approved ahead of time: a reservation"
STARTS=$(in_ms 7200)
R=$(ask_ahead "$ALICE" "T25 tonight" "$STARTS")
check "Alice asks for two hours from now: awaiting approval (202)" 202 "$(status_of "$R")"
ID=$(pending_of t25-alice)
PENDING=$(api GET "$PAM/approvals/pending" "$APPROVER" | cut -d' ' -f2-)
check "the approver sees its time, for the Account's 30 minutes" "$STARTS $((STARTS + 1800000))" \
    "$(json_get "$PENDING" "' '.join(str(r.get(k)) for r in d if r['id']==$ID for k in ('starts','ends'))")"

R=$(api POST "$PAM/approvals/$ID/approve" "$APPROVER")
check "the approval reserves it, with no checkout yet" "200 APPROVED None" \
    "$(status_of "$R") $(json_get "${R#* }" "d['status'] + ' ' + str(d.get('checkoutId'))")"
MINE=$(api GET "$PAM/requests/$ACCOUNT" "$ALICE" | cut -d' ' -f2-)
check "Alice sees her reservation, and nothing awaiting approval" "$ID None False" \
    "$(json_get "$MINE" "str(d['reservation']['id']) + ' ' + str(d.get('pending')) + ' ' + str(d.get('mine'))")"
check_contains "before it starts, opening it gives no password (a request needs a reason)" "reason" \
    "$(message_of "$(api POST "$PAM/requests/$ACCOUNT" "$ALICE" '{}')")"

check_contains "Bob cannot ask for a time overlapping it" "reserved by \"t25-alice\"" \
    "$(message_of "$(ask_ahead "$BOB" "T25 overlap" "$((STARTS + 900000))")")"
check_contains "Alice cannot either" "already have approved access" \
    "$(message_of "$(ask_ahead "$ALICE" "T25 overlap" "$((STARTS + 900000))")")"
check "Bob asks for right after it" 202 "$(status_of "$(ask_ahead "$BOB" "T25 after" "$((STARTS + 1800000))")")"
check "Alice asks for after that too, overlapping Bob's (only awaiting approval, so allowed)" 202 \
    "$(status_of "$(ask_ahead "$ALICE" "T25 later" "$((STARTS + 2400000))")")"
BOB_ID=$(pending_of t25-bob)
LATER_ID=$(pending_of t25-alice)
check "Bob's is approved" 200 "$(status_of "$(api POST "$PAM/approvals/$BOB_ID/approve" "$APPROVER")")"
check "...which rejects Alice's overlapping one, by no one" "DENIED " \
    "$(sql "SELECT status, coalesce(decided_by, '') FROM pam_request WHERE request_id = $LATER_ID" | tr '\t' ' ')"
LATEST=$(api GET "$PAM/requests/$ACCOUNT" "$ALICE" | cut -d' ' -f2-)
check_contains "...and Alice is told why" "overlaps that of \"t25-bob\" (request $BOB_ID), approved first" \
    "$(json_get "$LATEST" "str(d.get('lastStatus')) + ' ' + str(d.get('lastDecisionReason'))")"
check_contains "...as a denial" "DENIED" "$(json_get "$LATEST" "d.get('lastStatus')")"
check_contains "it can no longer be approved" "no longer awaiting approval" \
    "$(message_of "$(api POST "$PAM/approvals/$LATER_ID/approve" "$APPROVER")")"
check "Alice's that does not overlap stays approved" APPROVED "$(sql "SELECT status FROM pam_request WHERE request_id = $ID")"

# ---------------------------------------------------------------- others' checkouts
section "Checkouts leave room for others' reservations"
sql "UPDATE pam_request SET starts = $(sql_in 600), ends = $(sql_in 2400) WHERE request_id = $ID" >/dev/null
GRANT=$(api POST "$PAM/requests/$ACCOUNT" "$ADMIN" '{"reason":"T25 admin before"}')
check "ten minutes before Alice's, the administrator checks it out" 200 "$(status_of "$GRANT")"
RESERVED_FROM=$(json_get "$(api GET "$PAM/requests/$ACCOUNT" "$ALICE" | cut -d' ' -f2-)" "d['reservation']['starts']")
check "...until her reservation starts, not for 30 minutes" "$RESERVED_FROM" "$(json_get "${GRANT#* }" "d.get('expires')")"
SEEN=$(api GET "$PAM/requests/$ACCOUNT" "$BOB" | cut -d' ' -f2-)
check "Bob sees whose reservation is next" "t25-alice $RESERVED_FROM" \
    "$(json_get "$SEEN" "str(d.get('reservedBy')) + ' ' + str(d.get('reservedFrom'))")"
api POST "$PAM/requests/$ACCOUNT/release" "$ADMIN" >/dev/null

sql "UPDATE pam_request SET starts = $(sql_ago 60), ends = $(sql_in 1740) WHERE request_id = $ID" >/dev/null
check_contains "once it started, the administrator cannot check it out" "reserved by \"t25-alice\" now" \
    "$(message_of "$(api POST "$PAM/requests/$ACCOUNT" "$ADMIN" '{"reason":"T25 admin during"}')")"
check_contains "...nor can Bob request it now" "reserved by \"t25-alice\" now" \
    "$(message_of "$(api POST "$PAM/requests/$ACCOUNT" "$BOB" '{"reason":"T25 bob now"}')")"

# ---------------------------------------------------------------- using it
section "Checking out with a reservation"
ENDS=$(json_get "$(api GET "$PAM/requests/$ACCOUNT" "$ALICE" | cut -d' ' -f2-)" "d['reservation']['ends']")
GRANT=$(api POST "$PAM/requests/$ACCOUNT" "$ALICE" '{}')
check "once it started, Alice gets the password without a new request" "200 $ACCOUNT_PASSWORD" \
    "$(status_of "$GRANT") $(json_get "${GRANT#* }" "d.get('password')")"
check "...until her reservation ends" "$ENDS" "$(json_get "${GRANT#* }" "d.get('expires')")"
check "...in a checkout with the request's reason, linked to it" "T25 tonight yes" \
    "$(sql "SELECT k.reason FROM pam_checkout k JOIN pam_request r ON r.checkout_id = k.checkout_id
        WHERE r.request_id = $ID") $([ -n "$(sql "SELECT checkout_id FROM pam_request WHERE request_id = $ID")" ] && echo yes)"
check "...which used up the reservation" "" \
    "$(json_get "$(api GET "$PAM/requests/$ACCOUNT" "$ALICE" | cut -d' ' -f2-)" "d.get('reservation')")"
check "Alice releases it" 204 "$(status_of "$(api POST "$PAM/requests/$ACCOUNT/release" "$ALICE")")"
check_contains "...and the reservation does not give it back" "reason" \
    "$(message_of "$(api POST "$PAM/requests/$ACCOUNT" "$ALICE" '{}')")"

check "Bob cancels his reservation" 204 "$(status_of "$(api DELETE "$PAM/requests/$ACCOUNT/reservation" "$BOB")")"
check "...recorded as cancelled by him" "CANCELLED t25-bob" \
    "$(sql "SELECT status, decided_by FROM pam_request WHERE request_id = $BOB_ID" | tr '\t' ' ')"
check_contains "...and there is none left to cancel" "no approved access" \
    "$(message_of "$(api DELETE "$PAM/requests/$ACCOUNT/reservation" "$BOB")")"

# ---------------------------------------------------------------- expiry
section "Requests ahead of time expire at their end, not after 24 hours"
check "Bob asks for an hour from now" 202 "$(status_of "$(ask_ahead "$BOB" "T25 expiry" "$(in_ms 3600)")")"
BOB_ID=$(pending_of t25-bob)
sql "UPDATE pam_request SET requested = $(sql_ago 90000) WHERE request_id = $BOB_ID" >/dev/null
check "made 25 hours ago, it can still be approved" 200 "$(status_of "$(api POST "$PAM/approvals/$BOB_ID/approve" "$APPROVER")")"
api DELETE "$PAM/requests/$ACCOUNT/reservation" "$BOB" >/dev/null
check "Bob asks again" 202 "$(status_of "$(ask_ahead "$BOB" "T25 expiry 2" "$(in_ms 3600)")")"
BOB_ID=$(pending_of t25-bob)
sql "UPDATE pam_request SET starts = $(sql_ago 1800), ends = $(sql_ago 60) WHERE request_id = $BOB_ID" >/dev/null
check_contains "once its time is over, it can no longer be approved" "no longer awaiting approval" \
    "$(message_of "$(api POST "$PAM/approvals/$BOB_ID/approve" "$APPROVER")")"
check "...as it expired" EXPIRED "$(sql "SELECT status FROM pam_request WHERE request_id = $BOB_ID")"

# ---------------------------------------------------------------- deletion
section "Deleting a connection cancels its reservations"
# Created without a cleanup: deleting it is the test
DOOMED=$(json_get "$(api POST "$DATA/connections" "$ADMIN" "{\"name\":\"t25 doomed $(date +%s%N)\",
    \"parentIdentifier\":\"ROOT\",\"protocol\":\"pam-account\",\"parameters\":{\"username\":\"svc-t25\",
    \"password\":\"$ACCOUNT_PASSWORD\"},\"attributes\":{\"pam-approvals-required\":\"1\"}}" | cut -d' ' -f2-)" "d.get('identifier')")
grant_read t25-bob "$DOOMED"
check "Bob asks for an hour from now" 202 "$(status_of "$(api POST "$PAM/requests/$DOOMED" "$BOB" \
    "{\"reason\":\"T25 deleted\",\"starts\":\"$(in_ms 3600)\"}")")"
BOB_ID=$(sql "SELECT request_id FROM pam_request WHERE connection_id = $DOOMED AND status = 'PENDING'")
check "...approved" 200 "$(status_of "$(api POST "$PAM/approvals/$BOB_ID/approve" "$ADMIN")")"
check "the connection is deleted" 204 "$(status_of "$(api DELETE "$DATA/connections/$DOOMED" "$ADMIN")")"
check "...and the reservation with it" "CANCELLED $GUAC_ADMIN" \
    "$(sql "SELECT status, decided_by FROM pam_request WHERE request_id = $BOB_ID" | tr '\t' ' ')"
