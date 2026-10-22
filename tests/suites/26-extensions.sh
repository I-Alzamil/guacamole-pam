#!/bin/bash
# Extensions of checkouts, and access asked for several time limits at once:
# limits per connection (the default of 2 extensions, or none), approvals as
# for requests, cancellation, expiry with the checkout, and reservations of
# others bounding them.

ACCOUNT_PASSWORD='T26-Account-Pw1!'

section "Setup"
create_connection OPEN "{\"name\":\"t26 gated ssh\",\"parentIdentifier\":\"ROOT\",\"protocol\":\"ssh\",
    \"parameters\":{\"hostname\":\"mysshtest\",\"port\":\"22\"},\"attributes\":{\"pam-checkout-duration\":\"30\"}}"
create_connection FIXED "{\"name\":\"t26 fixed ssh\",\"parentIdentifier\":\"ROOT\",\"protocol\":\"ssh\",
    \"parameters\":{\"hostname\":\"mysshtest\",\"port\":\"22\"},\"attributes\":{\"pam-extensions\":\"no\"}}"
create_connection ACCOUNT "{\"name\":\"t26 account\",\"parentIdentifier\":\"ROOT\",\"protocol\":\"pam-account\",
    \"parameters\":{\"username\":\"svc-t26\",\"password\":\"$ACCOUNT_PASSWORD\"},
    \"attributes\":{\"pam-approvals-required\":\"1\",\"pam-checkout-duration\":\"30\",\"pam-checkout-exclusive\":\"yes\",
    \"pam-max-extensions\":\"3\",\"pam-extension-duration\":\"15\"}}"

create_user t26-ann t26-ann-pw
create_user t26-ben t26-ben-pw
create_user t26-approver t26-approver-pw "{\"pam-approver\":\"true\",\"pam-approver-connections\":\"[\\\"$ACCOUNT\\\"]\"}"
for u in t26-ann t26-ben; do for c in $OPEN $FIXED $ACCOUNT; do grant_read $u "$c"; done; done

ANN=$(token t26-ann t26-ann-pw)
BEN=$(token t26-ben t26-ben-pw)
APPROVER=$(token t26-approver t26-approver-pw)
check "setup: connections and users exist" yes "$([ -n "$OPEN$FIXED$ACCOUNT" ] && [ -n "$ANN" ] && [ -n "$APPROVER" ] && echo yes)"

seen_by() { # TOKEN CONNECTION EXPRESSION -> the expression, of the request as the user sees it
    json_get "$(api GET "$PAM/requests/$2" "$1" | cut -d' ' -f2-)" "$3"
}
held_minutes() { # CONNECTION USERNAME -> how long their active checkout lasts in all, in minutes
    curl -s "$PAM/checkouts/active?token=$ADMIN" | python3 -I -c "
import sys,json
c=[c for c in json.load(sys.stdin) if c['connectionIdentifier']==sys.argv[1] and c['username']==sys.argv[2]]
print(round((c[0]['expires'] - c[0]['checkedOut']) / 60000) if c else '')" "$1" "$2"
}
pending_extension() { # USERNAME -> id of their extension awaiting approval
    curl -s "$PAM/approvals/pending?token=$ADMIN" | python3 -I -c "
import sys,json
m=[r['id'] for r in json.load(sys.stdin) if r['username']==sys.argv[1] and r.get('extendsCheckout')]
print(m[0] if m else '')" "$1"
}

# ---------------------------------------------------------------- several time limits at once
section "Several time limits at once"
check "by default, up to 3 times the time limit (1 + 2 extensions)" 3 "$(seen_by "$ANN" "$OPEN" "d['maxPeriods']")"
check_contains "4 times is refused" "up to 3 times" \
    "$(message_of "$(api POST "$PAM/requests/$OPEN" "$ANN" '{"reason":"T26 long","periods":"4"}')")"
check "twice the time limit is granted" 200 "$(status_of "$(api POST "$PAM/requests/$OPEN" "$ANN" '{"reason":"T26 long","periods":"2"}')")"
check "...for 60 minutes" 60 "$(held_minutes "$OPEN" t26-ann)"
check "...leaving one extension" 1 "$(seen_by "$ANN" "$OPEN" "d['extensionsLeft']")"

# ---------------------------------------------------------------- extensions without approval
section "Extensions where no approval is needed"
check_contains "an extension needs a reason" "reason" "$(message_of "$(api POST "$PAM/requests/$OPEN/extension" "$ANN" '{}')")"
check "with one, it is granted at once" 200 \
    "$(status_of "$(api POST "$PAM/requests/$OPEN/extension" "$ANN" '{"reason":"T26 more time"}')")"
check "...by the time limit, as no extension length is set" 90 "$(held_minutes "$OPEN" t26-ann)"
check "...and recorded as approved, by the holder" "APPROVED t26-ann" \
    "$(seen_by "$ANN" "$OPEN" "d['extension']['status'] + ' ' + d['extension']['decidedBy']")"
check_contains "no extension is left" "cannot be extended any more" \
    "$(message_of "$(api POST "$PAM/requests/$OPEN/extension" "$ANN" '{"reason":"T26 again"}')")"
HISTORY=$(curl -s -G --data-urlencode "contains=T26 long" "$PAM/checkouts/history?token=$ADMIN" | python3 -I -c "
import sys,json
c=[c for c in json.load(sys.stdin) if c.get('connectionIdentifier')==sys.argv[1]][0]
print(c['extensions'], c['maxExtensions'], ' '.join('%d/%s' % (e['minutes'], e['reason']) for e in c['extensionHistory']))" "$OPEN")
check "the history lists the extension" "1 1 30/T26 more time" "$HISTORY"
check "...which the approvals history leaves out, as it needed no approval" "" \
    "$(curl -s -G --data-urlencode "contains=T26 more time" "$PAM/approvals/history?token=$ADMIN" | python3 -I -c "
import sys,json; print(' '.join(str(r['id']) for r in json.load(sys.stdin)))")"
check_contains "Ben, holding nothing, cannot extend" "do not hold" \
    "$(message_of "$(api POST "$PAM/requests/$OPEN/extension" "$BEN" '{"reason":"x"}')")"
api POST "$PAM/requests/$OPEN/release" "$ANN" >/dev/null

section "A connection allowing no extensions"
check "only its time limit can be asked for" 1 "$(seen_by "$ANN" "$FIXED" "d['maxPeriods']")"
check_contains "...not twice" "longer than its time limit" \
    "$(message_of "$(api POST "$PAM/requests/$FIXED" "$ANN" '{"reason":"T26 fixed","periods":"2"}')")"
api POST "$PAM/requests/$FIXED" "$ANN" '{"reason":"T26 fixed"}' >/dev/null
check_contains "...and its checkouts cannot be extended" "cannot be extended" \
    "$(message_of "$(api POST "$PAM/requests/$FIXED/extension" "$ANN" '{"reason":"x"}')")"
api POST "$PAM/requests/$FIXED/release" "$ANN" >/dev/null

# ---------------------------------------------------------------- extensions needing approval
section "Extensions needing approval, as requests do"
api POST "$PAM/requests/$ACCOUNT" "$ANN" '{"reason":"T26 account"}' >/dev/null
ID=$(curl -s "$PAM/approvals/pending?token=$ADMIN" | python3 -I -c "
import sys,json; print([r['id'] for r in json.load(sys.stdin) if r['username']=='t26-ann'][0])")
api POST "$PAM/approvals/$ID/approve" "$APPROVER" >/dev/null
check "Ann holds the Account for its 30 minutes" 30 "$(held_minutes "$ACCOUNT" t26-ann)"
R=$(api POST "$PAM/requests/$ACCOUNT/extension" "$ANN" '{"reason":"T26 extend account"}')
check "her extension awaits approval" "200 PENDING" "$(status_of "$R") $(json_get "${R#* }" "d['extension']['status']")"
check "...not extended yet" 30 "$(held_minutes "$ACCOUNT" t26-ann)"
check_contains "...and a second one cannot be asked meanwhile" "already awaits approval" \
    "$(message_of "$(api POST "$PAM/requests/$ACCOUNT/extension" "$ANN" '{"reason":"T26 twice"}')")"
EXT=$(pending_extension t26-ann)
check "the approver sees what it extends, and by how much" "15 yes" \
    "$(json_get "$(api GET "$PAM/approvals/pending" "$APPROVER" | cut -d' ' -f2-)" \
        "' '.join('%s %s' % (r['extensionMinutes'], 'yes' if r['extendsCheckout'] else 'no') for r in d if r['id']==$EXT)")"
check_contains "Ann cannot approve it herself" "No such request" \
    "$(message_of "$(api POST "$PAM/approvals/$EXT/approve" "$ANN")")"
check "the approver approves it" "200 APPROVED" \
    "$(R=$(api POST "$PAM/approvals/$EXT/approve" "$APPROVER"); echo "$(status_of "$R") $(json_get "${R#* }" "d['status']")")"
check "...extending the checkout by the connection's extension length" 45 "$(held_minutes "$ACCOUNT" t26-ann)"
check "...with its approver in the history, apart from those of the checkout" "t26-approver | t26-approver" \
    "$(curl -s -G --data-urlencode "contains=T26 account" "$PAM/checkouts/history?token=$ADMIN" | python3 -I -c "
import sys,json
c=[c for c in json.load(sys.stdin) if c.get('connectionIdentifier')==sys.argv[1]][0]
print(','.join(c['approvedBy']), '|', ','.join(a['approver'] for e in c['extensionHistory'] for a in e['approvals']))" "$ACCOUNT")"

api POST "$PAM/requests/$ACCOUNT/extension" "$ANN" '{"reason":"T26 cancel"}' >/dev/null
EXT=$(pending_extension t26-ann)
check "Ann cancels an extension awaiting approval" 204 "$(status_of "$(api DELETE "$PAM/requests/$ACCOUNT/extension" "$ANN")")"
check "...which is then cancelled" CANCELLED "$(sql "SELECT status FROM pam_request WHERE request_id = $EXT")"

api POST "$PAM/requests/$ACCOUNT/extension" "$ANN" '{"reason":"T26 released"}' >/dev/null
EXT=$(pending_extension t26-ann)
api POST "$PAM/requests/$ACCOUNT/release" "$ANN" >/dev/null
check_contains "once the checkout ends, its extension can no longer be approved" "no longer awaiting approval" \
    "$(message_of "$(api POST "$PAM/approvals/$EXT/approve" "$APPROVER")")"
check "...as it expired" EXPIRED "$(sql "SELECT status FROM pam_request WHERE request_id = $EXT")"

# ---------------------------------------------------------------- reservations
section "Others' reservations bound extensions"
api POST "$PAM/requests/$ACCOUNT" "$ANN" '{"reason":"T26 before ben"}' >/dev/null
ID=$(curl -s "$PAM/approvals/pending?token=$ADMIN" | python3 -I -c "
import sys,json; print([r['id'] for r in json.load(sys.stdin) if r['username']=='t26-ann'][0])")
api POST "$PAM/approvals/$ID/approve" "$APPROVER" >/dev/null
CHECKOUT=$(sql "SELECT checkout_id FROM pam_request WHERE request_id = $ID")
api POST "$PAM/requests/$ACCOUNT" "$BEN" "{\"reason\":\"T26 ben later\",\"starts\":\"$(( $(date +%s%3N) + 7200000 ))\"}" >/dev/null
BEN_ID=$(curl -s "$PAM/approvals/pending?token=$ADMIN" | python3 -I -c "
import sys,json; print([r['id'] for r in json.load(sys.stdin) if r['username']=='t26-ben'][0])")
api POST "$PAM/approvals/$BEN_ID/approve" "$APPROVER" >/dev/null
# Ben's reservation starts 5 minutes after Ann's checkout ends
sql "UPDATE pam_request SET starts = (SELECT $( [ "$PAM_DB" = sqlserver ] && echo "DATEADD(second, 300, expires)" || \
    { [ "$PAM_DB" = postgresql ] && echo "expires + make_interval(secs => 300)" || echo "TIMESTAMPADD(SECOND, 300, expires)"; } )
    FROM pam_checkout WHERE checkout_id = $CHECKOUT) WHERE request_id = $BEN_ID" >/dev/null
api POST "$PAM/requests/$ACCOUNT/extension" "$ANN" '{"reason":"T26 bounded"}' >/dev/null
api POST "$PAM/approvals/$(pending_extension t26-ann)/approve" "$APPROVER" >/dev/null
check "a 15-minute extension only lasts until Ben's reservation starts" 35 "$(held_minutes "$ACCOUNT" t26-ann)"
api POST "$PAM/requests/$ACCOUNT/extension" "$ANN" '{"reason":"T26 refused"}' >/dev/null
EXT=$(pending_extension t26-ann)
check_contains "...and none is granted once it would start right away" "reserved by \"t26-ben\" as soon as your checkout ends" \
    "$(message_of "$(api POST "$PAM/approvals/$EXT/approve" "$APPROVER")")"
api DELETE "$PAM/requests/$ACCOUNT/extension" "$ANN" >/dev/null
api POST "$PAM/requests/$ACCOUNT/release" "$ANN" >/dev/null
api DELETE "$PAM/requests/$ACCOUNT/reservation" "$BEN" >/dev/null
