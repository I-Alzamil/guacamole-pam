#!/bin/bash
# Events emailed through the lab's mail server (mymailtest, Mailpit):
# settings checked, the password kept secret, the test button saying why it
# failed, then who receives what: approvers a request and other approvers'
# decisions, the requester the decision and their access ending,
# administrators everything, the extra address too; nobody what they did
# themselves; each kind turned off under Preferences.

SETTINGS="$PAM/settings"
MAIL_PASSWORD='P@ssw0rd-Mail1'

# Every setting of the Email sections back to its default
reset_email() {
    api PUT "$SETTINGS" "$ADMIN" "$(curl -s "$SETTINGS?token=$ADMIN" | python3 -I -c "
import sys,json
print(json.dumps({e['name']: None for e in json.load(sys.stdin) if e['section'] == 'EMAIL'}))")" >/dev/null
    api DELETE "$PAM/email-languages/en" "$ADMIN" >/dev/null
}

email_set() { api PUT "$SETTINGS" "$ADMIN" "$1"; }

# The messages received since the suite started, as "TO|SUBJECT" lines, or
# with TEXT their text too (as "TO|SUBJECT|TEXT", newlines as "\n")
MAIL_SINCE=$(date -u +%Y-%m-%dT%H:%M:%S)
mails() { # [text]
    podman exec mymailtest wget -qO- "http://localhost:8025/api/v1/messages?limit=500" | python3 -I -c "
import sys, json, subprocess
since, text = sys.argv[1], len(sys.argv) > 2
for m in reversed(json.load(sys.stdin)['messages']):
    if m['Created'][:19] < since:
        continue
    to = ','.join(a['Address'] for a in m['To'])
    line = to + '|' + m['Subject']
    if text:
        body = json.loads(subprocess.run(['podman', 'exec', 'mymailtest', 'wget', '-qO-',
            'http://localhost:8025/api/v1/message/' + m['ID']], capture_output=True, text=True).stdout)
        line += '|' + body['Text'].replace('\r', '').replace('\n', '\\\\n')
    print(line)" "$MAIL_SINCE" $1
}

# Waits up to 10 s for an email to ADDRESS whose subject contains TEXT,
# printing yes or no
mailed() { # ADDRESS TEXT
    local i
    for i in $(seq 20); do
        mails | grep -F -- "$1|" | grep -qF -- "$2" && { echo yes; return; }
        sleep 0.5
    done
    echo no
}

# Who was emailed a subject containing TEXT, sorted (after waiting for
# the emails of an event to be sent)
mailed_to() { sleep 3; mails | grep -F -- "$1" | cut -d'|' -f1 | sort -u | tr '\n' ' ' | sed 's/ $//'; }

# How many emails to ADDRESS have a subject containing TEXT
count_mailed() { mails | grep -F -- "$1|" | grep -cF -- "$2"; }

test_email() { api POST "$SETTINGS/test/email" "$1"; }

CA=$(python3 -I -c "import json,sys;print(json.dumps(open(sys.argv[1]).read()))" ../lab/targets/certs/ca.crt)

section "Setup"
create_connection GATED "{\"name\":\"t46 gated ssh\",\"parentIdentifier\":\"ROOT\",\"protocol\":\"ssh\",
    \"parameters\":{\"hostname\":\"mysshtest\",\"port\":\"22\"},\"attributes\":{\"pam-approvals-required\":\"1\"}}"
create_user t46-admin t46-admin-pw '{"guac-email-address":"t46-admin@example.org"}'
grant t46-admin '[{"op":"add","path":"/systemPermissions","value":"ADMINISTER"}]'
create_user t46-approver t46-approver-pw "{\"guac-email-address\":\"t46-approver@example.org\",\"pam-approver\":\"true\",\"pam-approver-connections\":\"[\\\"$GATED\\\"]\"}"
create_user t46-approver2 t46-approver2-pw "{\"guac-email-address\":\"t46-approver2@example.org\"}"
create_user_group t46-approvers "{\"pam-approver\":\"true\",\"pam-approver-connections\":\"[\\\"$GATED\\\"]\"}" t46-approver2
create_user t46-user t46-user-pw '{"guac-email-address":"t46-user@example.org"}'
create_user t46-nobody t46-nobody-pw
for u in t46-user t46-nobody t46-approver t46-approver2; do grant_read "$u" "$GATED"; done
T46_ADMIN=$(token t46-admin t46-admin-pw)
APPROVER=$(token t46-approver t46-approver-pw)
APPROVER2=$(token t46-approver2 t46-approver2-pw)
USER=$(token t46-user t46-user-pw)
NOBODY=$(token t46-nobody t46-nobody-pw)
reset_email
on_cleanup reset_email
check "setup: a connection, users, and the mail server exist" yes \
    "$([ -n "$GATED" ] && [ -n "$T46_ADMIN" ] && [ -n "$USER" ] && [ "$(podman inspect -f '{{.State.Running}}' mymailtest 2>/dev/null)" = true ] && echo yes)"

pending_id() {
    curl -s "$PAM/approvals/pending?token=$ADMIN" | python3 -I -c "
import sys,json
m=[r['id'] for r in json.load(sys.stdin) if r['username']==sys.argv[1]]
print(m[0] if m else '')" "$1"
}

# ---------------------------------------------------------------- settings
section "Settings"
check "off by default, with STARTTLS on 587" "False starttls 587" \
    "$(curl -s "$SETTINGS?token=$ADMIN" | python3 -I -c "
import sys,json
e={e['name']: e for e in json.load(sys.stdin)}
print(e['pam-email-enabled']['value'], e['pam-email-security']['value'], e['pam-email-port']['value'])")"
check "...unencrypted last" "starttls tls none" \
    "$(curl -s "$SETTINGS?token=$ADMIN" | python3 -I -c "
import sys,json
print(' '.join([e for e in json.load(sys.stdin) if e['name']=='pam-email-security'][0]['options']))")"
R=$(email_set '{"pam-email-enabled":true,"pam-email-host":"mymailtest"}')
check "turning it on needs a sender" "400 \"pam-email-from\" is needed while \"pam-email-enabled\" is on." \
    "$(status_of "$R") $(message_of "$R")"
R=$(email_set '{"pam-email-from":"pam"}')
check "a sender must be an address" "400 \"pam-email-from\": not an email address." "$(status_of "$R") $(message_of "$R")"
R=$(email_set '{"pam-email-admin-address":"a@example.org, b@example.org"}')
check "...one address" "400 \"pam-email-admin-address\": not an email address." "$(status_of "$R") $(message_of "$R")"
R=$(email_set '{"pam-email-link":"guac.example.org"}')
check "a link must be http:// or https://" "400 \"pam-email-link\": not an http:// or https:// address." \
    "$(status_of "$R") $(message_of "$R")"

email_set "{\"pam-email-password\":\"$MAIL_PASSWORD\"}" >/dev/null
check "the password is never shown again, only that it is set" "None True" \
    "$(curl -s "$SETTINGS?token=$ADMIN" | python3 -I -c "
import sys,json
e=[e for e in json.load(sys.stdin) if e['name']=='pam-email-password'][0]
print(e['value'], e['set'])")"
STORED=$(sql "SELECT value FROM pam_setting WHERE name = 'pam-email-password'")
if [ -n "$(podman exec myguactest printenv PAM_ENCRYPTION_KEY 2>/dev/null)" ]; then
    check "...and stored encrypted" yes "$([ "$STORED" != "$MAIL_PASSWORD" ] && [ -n "$STORED" ] && echo yes)"
fi
check_contains "...nor logged" "set \"pam-email-password\" to a new secret (was none)" "$(podman logs --since 1m myguactest 2>&1)"
check "...nor its plaintext anywhere in the log" no \
    "$(podman logs --since 1m myguactest 2>&1 | grep -qF "$MAIL_PASSWORD" && echo yes || echo no)"

# ---------------------------------------------------------------- test
section "The test button"
check "a user cannot test" 403 "$(status_of "$(test_email "$USER")")"
R=$(test_email "$T46_ADMIN")
check "without a server, it says so" "False No mail server is set." "$(json_get "${R#* }" "d['sent']") $(message_of "$R")"
email_set '{"pam-email-host":"mymailtest","pam-email-port":1025,"pam-email-from":"Guacamole PAM <pam@example.org>"}' >/dev/null
R=$(test_email "$ADMIN")
check_contains "an administrator without an address is told to set one" "False Your Guacamole user has no email address" \
    "$(json_get "${R#* }" "d['sent']") $(message_of "$R")"
R=$(test_email "$T46_ADMIN")
check_contains "a certificate of a CA Java does not trust is refused" \
    "The certificate of mail server mymailtest:1025 with STARTTLS is not trusted" "$(message_of "$R")"
check_contains "...which is logged" "User \"t46-admin\" tested email: The certificate of mail server" \
    "$(podman logs --since 1m myguactest 2>&1)"
email_set "{\"pam-email-ca-certificates\":$CA,\"pam-email-security\":\"none\"}" >/dev/null
R=$(test_email "$T46_ADMIN")
check_contains "unencrypted, a server requiring STARTTLS refuses" "False Mail server mymailtest:1025 unencrypted" \
    "$(json_get "${R#* }" "d['sent']") $(message_of "$R")"
email_set '{"pam-email-security":"tls"}' >/dev/null
R=$(test_email "$T46_ADMIN")
check_contains "TLS from the start, to a STARTTLS port, fails" "False" "$(json_get "${R#* }" "d['sent']")"
email_set '{"pam-email-security":null}' >/dev/null
R=$(test_email "$T46_ADMIN")
check_contains "with STARTTLS and the CA trusted, a login is still needed" "False Mail server mymailtest:1025 with STARTTLS" \
    "$(json_get "${R#* }" "d['sent']") $(message_of "$R")"
email_set '{"pam-email-username":"pammail","pam-email-password":"wrong"}' >/dev/null
R=$(test_email "$T46_ADMIN")
check_contains "a wrong password is refused" "refused the username or password" "$(message_of "$R")"
email_set "{\"pam-email-password\":\"$MAIL_PASSWORD\"}" >/dev/null
R=$(test_email "$T46_ADMIN")
check "the right one: the test is sent to the administrator" \
    "True A test email was sent to t46-admin@example.org through mail server mymailtest:1025 with STARTTLS." \
    "$(json_get "${R#* }" "d['sent']") $(message_of "$R")"
check "...and received, from the sender set" yes "$(mailed t46-admin@example.org "[Guacamole PAM] A test from the PAM settings page, sent by \"t46-admin\".")"

# ---------------------------------------------------------------- preferences
section "Preferences"
EMAILS=$(json_get "$(api GET "$PAM/access" "$USER" | cut -d' ' -f2-)" "' '.join([str(d['emails']['enabled']), str(d['emails']['address']), str(d['emails']['wanted']['own'])])")
check "a user is told emails are off, their address, and what they want" "False t46-user@example.org True" "$EMAILS"
check "a user without an address is told so" None \
    "$(json_get "$(api GET "$PAM/access" "$NOBODY" | cut -d' ' -f2-)" "str(d['emails']['address'])")"
check "an unknown kind" 400 "$(status_of "$(api PUT "$PAM/preferences/emails/pager" "$USER" '{"wanted":false}')")"

# ---------------------------------------------------------------- events
section "Who receives what"
email_set '{"pam-email-enabled":true,"pam-email-link":"https://guac.example.org/guacamole/"}' >/dev/null
check "an administrator is emailed another's setting change" yes \
    "$(mailed t46-admin@example.org "[Guacamole PAM] User \"$GUAC_ADMIN\" changed the PAM settings.")"

api POST "$PAM/requests/$GATED" "$USER" '{"reason":"T46 ticket 1"}' >/dev/null
check "a request goes to its approvers (directly and through a group) and administrators, not the requester" \
    "t46-admin@example.org t46-approver2@example.org t46-approver@example.org" \
    "$(mailed_to "User \"t46-user\" requested \"t46 gated ssh\"")"
BODY=$(mails text | grep -F "t46-approver@example.org|" | grep -F "requested \"t46 gated ssh\"" | tail -1 | cut -d'|' -f3-)
check_contains "...the approver's with its reason and a link to the Approvals tab" \
    'Reason: T46 ticket 1\n' "$BODY"
check_contains "...the link" 'Approve or deny it on the Approvals tab: https://guac.example.org/guacamole/#/settings/pam-approvals\n' "$BODY"
check_contains "...and why they receive it" "You receive this as an approver of the connection." "$BODY"

ID=$(pending_id t46-user)
api POST "$PAM/approvals/$ID/approve" "$APPROVER" >/dev/null
check "the approval goes to the requester, the other approver and administrators, not the approver" \
    "t46-admin@example.org t46-approver2@example.org t46-user@example.org" \
    "$(mailed_to "User \"t46-approver\" approved the request of \"t46-user\"")"
BODY=$(mails text | grep -F "t46-user@example.org|" | grep -F "approved the request" | tail -1 | cut -d'|' -f3-)
check_contains "...the requester's telling them to connect" 'Open the connection in Guacamole: https://guac.example.org/guacamole/\n' "$BODY"
check "...and no email says a password" no "$(mails text | grep -qiF "password:" && echo yes || echo no)"

sql "UPDATE pam_checkout SET expires = $(sql_ago 1) WHERE connection_id = $GATED AND released IS NULL" >/dev/null
check "the checkout expiring goes to its holder" yes "$(mailed t46-user@example.org "The checkout of \"t46 gated ssh\" by \"t46-user\" expired.")"

api POST "$PAM/requests/$GATED" "$USER" '{"reason":"T46 ticket 2"}' >/dev/null
sleep 1
api POST "$PAM/approvals/$(pending_id t46-user)/deny" "$APPROVER2" '{"reason":"Not today"}' >/dev/null
check "a denial goes to the requester" yes "$(mailed t46-user@example.org "User \"t46-approver2\" denied the request of \"t46-user\"")"
check_contains "...with its reason" 'Reason: Not today\n' \
    "$(mails text | grep -F "t46-user@example.org|" | grep -F "denied the request" | cut -d'|' -f3-)"

api PUT "$PAM/preferences/emails/own" "$USER" '{"wanted":false}' >/dev/null
check "a user turns their own emails off" False \
    "$(json_get "$(api GET "$PAM/access" "$USER" | cut -d' ' -f2-)" "str(d['emails']['wanted']['own'])")"
APPROVED="User \"t46-approver\" approved the request of \"t46-user\""
BEFORE="$(count_mailed t46-user@example.org "$APPROVED") $(count_mailed t46-approver2@example.org "$APPROVED")"
api POST "$PAM/requests/$GATED" "$USER" '{"reason":"T46 ticket 3"}' >/dev/null
sleep 1
api POST "$PAM/approvals/$(pending_id t46-user)/approve" "$APPROVER" >/dev/null
sleep 3
check "...and is no longer emailed the decision, which the other approver still is" \
    "${BEFORE% *} $(( ${BEFORE#* } + 1 ))" \
    "$(count_mailed t46-user@example.org "$APPROVED") $(count_mailed t46-approver2@example.org "$APPROVED")"
api PUT "$PAM/preferences/emails/own" "$USER" '{"wanted":true}' >/dev/null

ACTIVE=$(sql "SELECT checkout_id FROM pam_checkout WHERE connection_id = $GATED AND released IS NULL")
api POST "$PAM/checkouts/$ACTIVE/revoke" "$T46_ADMIN" >/dev/null
check "an administrator revoking a checkout: emailed to its holder" yes \
    "$(mailed t46-user@example.org "was ended by \"t46-admin\"")"
check "...not to that administrator" 0 "$(count_mailed t46-admin@example.org "was ended by \"t46-admin\"")"

email_set '{"pam-email-admin-address":"soc@example.org"}' >/dev/null
api POST "$PAM/requests/$GATED" "$NOBODY" '{"reason":"T46 nobody"}' >/dev/null
check "the extra address receives what administrators do" yes "$(mailed soc@example.org "User \"t46-nobody\" requested \"t46 gated ssh\"")"
check_contains "...saying why" "This address receives what Guacamole administrators receive" \
    "$(mails text | grep -F "soc@example.org|" | tail -1 | cut -d'|' -f3-)"
api DELETE "$PAM/requests/$GATED/pending" "$NOBODY" >/dev/null

api POST "$PAM/requests/$GATED" "$USER" '{"reason":"T46 left pending"}' >/dev/null
sql "UPDATE pam_request SET requested = $(sql_ago 90000) WHERE username = 't46-user' AND status = 'PENDING'" >/dev/null
# Expired before any decision, such as asking again
api POST "$PAM/requests/$GATED" "$NOBODY" '{"reason":"T46 after expiry"}' >/dev/null
EXPIRED="of \"t46-user\" for \"t46 gated ssh\" expired before it was decided."
check "a request expiring undecided goes to its requester and approvers" \
    "soc@example.org t46-admin@example.org t46-approver2@example.org t46-approver@example.org t46-user@example.org" \
    "$(mailed_to "$EXPIRED")"
check_contains "...telling the requester to ask again" "To use it again, request it again in Guacamole" \
    "$(mails text | grep -F "t46-user@example.org|" | grep -F "$EXPIRED" | tail -1 | cut -d'|' -f3-)"
api DELETE "$PAM/requests/$GATED/pending" "$NOBODY" >/dev/null

on_cleanup "sql \"DELETE FROM pam_login_group WHERE username LIKE 't46-%'\" >/dev/null"
check "a member of a group logs in: their groups are kept, for emails" t46-approvers \
    "$(sql "SELECT group_name FROM pam_login_group WHERE username = 't46-approver2'" | tr -d '[:space:]')"
create_user t46-ldap t46-ldap-pw '{"guac-email-address":"t46-ldap@example.org"}'
# A group another extension, such as LDAP, gave at login, which the
# database does not list
sql "INSERT INTO pam_login_group (username, group_name) VALUES ('t46-ldap', 't46-approvers')" >/dev/null
api POST "$PAM/requests/$GATED" "$NOBODY" '{"reason":"T46 login groups"}' >/dev/null
check "a request goes to who belonged to an approving group at their last login, through another extension" yes \
    "$(mailed t46-ldap@example.org "User \"t46-nobody\" requested \"t46 gated ssh\"")"
api DELETE "$PAM/requests/$GATED/pending" "$NOBODY" >/dev/null

# ---------------------------------------------------------------- templates
LANGS="$PAM/email-languages"
section "Email templates: English"
check "a user cannot read the languages" 403 "$(status_of "$(api GET "$LANGS" "$USER")")"
check "English is built in, unchanged" "en True False" \
    "$(json_get "$(api GET "$LANGS" "$ADMIN" | cut -d' ' -f2-)" "' '.join([d[0]['code'], str(d[0]['builtIn']), str(d[0]['changed'])])")"
check "...exported in the file format, with every kind" "guacamole-pam-email-language 1 approval decision ended other" \
    "$(json_get "$(api GET "$LANGS/en" "$ADMIN" | cut -d' ' -f2-)" "' '.join([d['format'], str(d['version'])] + list(d['templates']))")"
R=$(api PUT "$LANGS/en" "$ADMIN" '{"code":"en","name":"English","templates":{"decision":{"body":"Hello {usr}"}}}')
check_contains "a mistyped placeholder is refused" "400 The text of \"decision\" has an unknown placeholder {usr}." \
    "$(status_of "$R") $(message_of "$R")"
R=$(email_set '{"pam-email-time-zone":"Mars/Olympus"}')
check_contains "...and an unknown time zone" "400 \"pam-email-time-zone\": not a time zone" "$(status_of "$R") $(message_of "$R")"
R=$(api POST "$LANGS/preview" "$ADMIN" '{"kind":"decision","language":{"code":"en","name":"English","templates":{"decision":{"subject":"Preview {request}"}}}}')
check "a preview renders a sample, unsaved" "200 Preview 42" "$(status_of "$R") $(json_get "${R#* }" "d['subject']")"
api PUT "$LANGS/en" "$ADMIN" "$(python3 -I -c "import json;print(json.dumps({'code': 'en', 'name': 'English', 'templates': {'decision': {
    'subject': 'Your request {request}: {event}',
    'body': 'Dear {user},\n\n{actor} decided on {connection} at {time}.\nReason: {reason}\n\n{action}\n\nSecurity team {{PAM}}'}}}))")" >/dev/null
email_set '{"pam-email-time-zone":"Asia/Riyadh"}' >/dev/null
check "English, changed, is listed so, as whose" "True $GUAC_ADMIN" \
    "$(json_get "$(api GET "$LANGS" "$ADMIN" | cut -d' ' -f2-)" "' '.join([str(d[0]['changed']), d[0]['modifiedBy']])")"
api POST "$PAM/requests/$GATED" "$USER" '{"reason":"T46 templated"}' >/dev/null
sleep 1
REQUEST=$(pending_id t46-user)
api POST "$PAM/approvals/$REQUEST/deny" "$APPROVER" '{"reason":"Use the other one"}' >/dev/null
check "a decision is sent with its kind's subject" yes "$(mailed t46-user@example.org "Your request $REQUEST: request-denied")"
BODY=$(mails text | grep -F "t46-user@example.org|Your request $REQUEST:" | tail -1 | cut -d'|' -f3-)
check_contains "...and text, its placeholders replaced, times in the zone set" \
    "Dear t46-user,\n\nt46-approver decided on t46 gated ssh at $(TZ=Asia/Riyadh date +%Y-%m-%d)" "$BODY"
check_contains "...the zone named" "+03:00 (Asia/Riyadh).\nReason: Use the other one\n\nhttps://guac.example.org/guacamole/\n" "$BODY"
check_contains "...doubled braces written once" 'Security team {PAM}' "$BODY"
check "other kinds keep the built-in template" yes \
    "$(mailed t46-approver@example.org "[Guacamole PAM] User \"t46-user\" requested \"t46 gated ssh\"")"
check "restoring English" 204 "$(status_of "$(api DELETE "$LANGS/en" "$ADMIN")")"
check "...brings the built-in template back" "False [Guacamole PAM] {summary}" \
    "$(json_get "$(api GET "$LANGS" "$ADMIN" | cut -d' ' -f2-)" "str(d[0]['changed'])") $(json_get "$(api GET "$LANGS/en" "$ADMIN" | cut -d' ' -f2-)" "d['templates']['decision']['subject']")"
email_set '{"pam-email-time-zone":null}' >/dev/null

# ---------------------------------------------------------------- languages
section "Email templates: other languages"
# Gone already unless a check failed
delete_french() { api DELETE "$LANGS/fr" "$ADMIN" >/dev/null; }
on_cleanup delete_french
FRENCH='{"format":"guacamole-pam-email-language","version":1,"code":"fr","name":"Français","messages":{"SUMMARY_REQUEST_DENIED":"\"{actor}\" a refusé la demande de \"{user}\" pour \"{connection}\".","LABEL_REASON":"Motif"},"templates":{"decision":{"subject":"[PAM] {summary}"}}}'
REFUSED=yes
for bad in '{"code":"french","name":"x"}' '{"code":"fr","name":""}' '{"code":"fr","name":"x","messages":{"NOPE":"x"}}' '{"code":"fr","name":"x","templates":{"weekly":{"subject":"x"}}}' '{"format":"platforms","code":"fr","name":"x"}'; do
    R=$(api PUT "$LANGS/fr" "$ADMIN" "$bad")
    [ "$(status_of "$R")" = 400 ] || REFUSED="no: $bad -> $R"
done
check "invalid languages are refused: a bad code, no name, an unknown message or kind, another format" yes "$REFUSED"
check "a file of a language is imported" 200 "$(status_of "$(api PUT "$LANGS/fr" "$ADMIN" "$FRENCH")")"
check "...listed after English" "en fr Français False" \
    "$(json_get "$(api GET "$LANGS" "$ADMIN" | cut -d' ' -f2-)" "' '.join([d[0]['code'], d[1]['code'], d[1]['name'], str(d[1]['builtIn'])])")"
check "...offered to users" "Français" "$(json_get "$(api GET "$PAM/access" "$USER" | cut -d' ' -f2-)" "d['emails']['languages'].get('fr')")"
check "...exported complete: what it leaves out is English" "Motif Connection" \
    "$(json_get "$(api GET "$LANGS/fr" "$ADMIN" | cut -d' ' -f2-)" "d['messages']['LABEL_REASON'] + ' ' + d['messages']['LABEL_CONNECTION']")"
check "a language not offered is refused as a user's choice" 400 "$(status_of "$(api PUT "$PAM/preferences/email-language" "$USER" '{"language":"xx"}')")"
check "a user chooses French" "204 fr" "$(status_of "$(api PUT "$PAM/preferences/email-language" "$USER" '{"language":"fr"}')") $(json_get "$(api GET "$PAM/access" "$USER" | cut -d' ' -f2-)" "d['emails']['language']")"
api POST "$PAM/requests/$GATED" "$USER" '{"reason":"T46 french"}' >/dev/null
sleep 1
api POST "$PAM/approvals/$(pending_id t46-user)/deny" "$APPROVER" '{"reason":"Non"}' >/dev/null
check "...and receives the denial in French, with French's template" yes \
    "$(mailed t46-user@example.org "[PAM] \"t46-approver\" a refusé la demande de \"t46-user\"")"
BODY=$(mails text | grep -F "t46-user@example.org|[PAM]" | tail -1 | cut -d'|' -f3-)
check_contains "...its messages French, what it leaves out English" 'Connection: t46 gated ssh\n' "$BODY"
check_contains "...the French one" 'Motif: Non\n' "$BODY"
check "...while the approver who chose none receives it in English" yes \
    "$(mailed t46-approver2@example.org "User \"t46-approver\" denied the request of \"t46-user\"")"
email_set '{"pam-email-language":"fr"}' >/dev/null
api PUT "$PAM/preferences/email-language" "$USER" '{"language":null}' >/dev/null
api POST "$PAM/requests/$GATED" "$USER" '{"reason":"T46 default french"}' >/dev/null
sleep 1
api POST "$PAM/approvals/$(pending_id t46-user)/deny" "$APPROVER" '{"reason":"Non"}' >/dev/null
check "French as the default language: for those who chose none" yes \
    "$(mailed t46-approver2@example.org "[PAM] \"t46-approver\" a refusé")"
api PUT "$PAM/preferences/email-language" "$USER" '{"language":"fr"}' >/dev/null
check "French counts its user" 1 "$(json_get "$(api GET "$LANGS" "$ADMIN" | cut -d' ' -f2-)" "[l['users'] for l in d if l['code']=='fr'][0]")"
check "English cannot be deleted, only restored" 204 "$(status_of "$(api DELETE "$LANGS/en" "$ADMIN")")"
check "...and is still there" en "$(json_get "$(api GET "$LANGS" "$ADMIN" | cut -d' ' -f2-)" "d[0]['code']")"
check "French is deleted" 204 "$(status_of "$(api DELETE "$LANGS/fr" "$ADMIN")")"
email_set '{"pam-email-language":null}' >/dev/null
api POST "$PAM/requests/$GATED" "$USER" '{"reason":"T46 after french"}' >/dev/null
sleep 1
api POST "$PAM/approvals/$(pending_id t46-user)/deny" "$APPROVER" '{"reason":"No"}' >/dev/null
check "...and its user receives the default language" yes \
    "$(mailed t46-user@example.org "[Guacamole PAM] User \"t46-approver\" denied the request of \"t46-user\"")"
check "...an unknown language is not found" 404 "$(status_of "$(api GET "$LANGS/fr" "$ADMIN")")"

# ---------------------------------------------------------------- off
section "Turned off"
email_set '{"pam-email-enabled":false}' >/dev/null
REQUESTED="User \"t46-user\" requested \"t46 gated ssh\""
BEFORE=$(count_mailed t46-approver@example.org "$REQUESTED")
api POST "$PAM/requests/$GATED" "$USER" '{"reason":"T46 while off"}' >/dev/null
sleep 3
check "nothing is sent" "$BEFORE" "$(count_mailed t46-approver@example.org "$REQUESTED")"
api DELETE "$PAM/requests/$GATED/pending" "$USER" >/dev/null
