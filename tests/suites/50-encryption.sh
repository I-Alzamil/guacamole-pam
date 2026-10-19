#!/bin/bash
# Encryption at rest: what the database holds (platform secrets, Account
# passwords and pending passwords encrypted; other connections' passwords
# plaintext, as guacd needs them), what the API returns, and saving
# connections from the editor. Skipped when the test setup has no key.

if [ -z "$PAM_TEST_KEY" ]; then
    section "Skipped: build.sh was run without an encryption key"
    return 0
fi

sql() { podman exec myguacdbtest psql -U postgres -tAc "$1"; }
stored_password() { sql "SELECT parameter_value FROM guacamole_connection_parameter WHERE connection_id = $1 AND parameter_name = 'password'"; }
raw_parameter() { json_get "$(curl -s "$DATA/connections/$1/parameters?token=$ADMIN")" "d.get('password')"; }
is_encrypted() { case "$1" in pam:v1:*) echo yes;; *) echo no;; esac; }
checkout_password() { # ID -> the password a checkout hands over, then releases it
    json_get "$(api POST "$PAM/requests/$1" "$ADMIN" '{"reason":"T2 encryption"}' | cut -d' ' -f2-)" "d.get('password')"
    api POST "$PAM/requests/$1/release" "$ADMIN" >/dev/null
}

MIT_ADMIN_PASSWORD="KdcAdm1n-Pass"
ACCOUNT_PASSWORD='T2-Enc-Start1!'

section "Setup"
podman exec mykdctest kadmin.local -q "addprinc -pw $ACCOUNT_PASSWORD t2enc" >/dev/null 2>&1
on_cleanup "podman exec mykdctest kadmin.local -q 'delprinc -force t2enc'"
check "precondition: test principal created" yes "$(mit_accepts t2enc "$ACCOUNT_PASSWORD")"
create_platform KRB "{\"name\":\"t2 enc kerberos\",\"type\":\"kerberos\",\"settings\":{\"kerberos-realm\":\"EXAMPLE.ORG\",
    \"kerberos-kdc\":\"mykdctest\",\"kerberos-admin-principal\":\"admin/admin\",\"kerberos-admin-password\":\"$MIT_ADMIN_PASSWORD\"},\"policy\":{}}"
create_connection ACCOUNT "{\"name\":\"t2 enc account\",\"parentIdentifier\":\"ROOT\",\"protocol\":\"pam-account\",
    \"parameters\":{\"username\":\"t2enc\",\"password\":\"$ACCOUNT_PASSWORD\"},\"attributes\":{\"pam-platform\":\"$KRB\"}}"
create_connection SSH "{\"name\":\"t2 enc ssh\",\"parentIdentifier\":\"ROOT\",\"protocol\":\"ssh\",
    \"parameters\":{\"hostname\":\"mysshtest\",\"username\":\"nobody\",\"password\":\"T2-Ssh-Plain1!\"},\"attributes\":{\"pam-request-exempt\":\"true\"}}"

# ---------------------------------------------------------------- at rest
section "What the database holds"
SECRETS=$(sql "SELECT secrets FROM pam_platform WHERE platform_id = $KRB")
check "platform secrets are encrypted" yes "$(is_encrypted "$SECRETS")"
check_contains "...and decrypt to the administrator password" "$MIT_ADMIN_PASSWORD" "$(reveal platform-secrets "$SECRETS")"
check "...which appears nowhere in the table" 0 "$(sql "SELECT count(*) FROM pam_platform WHERE secrets LIKE '%$MIT_ADMIN_PASSWORD%'")"
STORED=$(stored_password "$ACCOUNT")
check "an Account's password is encrypted" yes "$(is_encrypted "$STORED")"
check "...and decrypts to the password" "$ACCOUNT_PASSWORD" "$(reveal connection-password "$STORED")"
check "another connection's password stays plaintext, for guacd" "T2-Ssh-Plain1!" "$(stored_password "$SSH")"
check "no Account password is stored as plaintext" 0 \
    "$(sql "SELECT count(*) FROM guacamole_connection_parameter p JOIN guacamole_connection c USING (connection_id)
            WHERE c.protocol = 'pam-account' AND p.parameter_name = 'password' AND p.parameter_value NOT LIKE 'pam:v1:%'")"
check "no platform secrets are stored as plaintext" 0 "$(sql "SELECT count(*) FROM pam_platform WHERE secrets NOT LIKE 'pam:v1:%'")"

# ---------------------------------------------------------------- API
section "What the API returns"
check "the connection API returns the Account's password encrypted only" yes "$(is_encrypted "$(raw_parameter "$ACCOUNT")")"
check "a checkout hands over the plaintext" "$ACCOUNT_PASSWORD" "$(checkout_password "$ACCOUNT")"
check_contains "the platform editor only says which secrets are stored" "['kerberos-admin-password'] {}" \
    "$(json_get "$(curl -s "$PAM/platforms/$KRB?token=$ADMIN")" "str(d.get('storedSecrets')) + ' ' + str({k: v for k, v in d['settings'].items() if 'password' in k})")"

# ---------------------------------------------------------------- editing
section "Saving connections from the editor"
edit_connection "$ADMIN" "$ACCOUNT" '' '' "t2 enc account renamed" >/dev/null
check "saved unchanged (the editor sends the encrypted value back), the value is kept" "$STORED" "$(stored_password "$ACCOUNT")"
check "...and still hands over the password" "$ACCOUNT_PASSWORD" "$(checkout_password "$ACCOUNT")"

R=$(edit_connection "$ADMIN" "$ACCOUNT" '{"password":"T2-Enc-Typed1!"}')
check "a new password typed in the editor is saved" 204 "$(status_of "$R")"
check "...encrypted" yes "$(is_encrypted "$(stored_password "$ACCOUNT")")"
check "...as typed" "T2-Enc-Typed1!" "$(checkout_password "$ACCOUNT")"
podman exec mykdctest kadmin.local -q "cpw -pw T2-Enc-Typed1! t2enc" >/dev/null 2>&1

R=$(edit_connection "$ADMIN" "$ACCOUNT" "{\"password\":\"$SECRETS\"}")
check_contains "the platform's encrypted secrets pasted as an Account password are refused" "400" "$(status_of "$R")"
check_contains "...as belonging to another field" "belongs to another field" "$(message_of "$R")"
R=$(edit_connection "$ADMIN" "$ACCOUNT" '{"password":"pam:v1:0badc0de:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}')
check_contains "a value encrypted with an unknown key is refused" "not configured" "$(message_of "$R")"
check "...and the stored password is unchanged" "T2-Enc-Typed1!" "$(checkout_password "$ACCOUNT")"

R=$(edit_connection "$ADMIN" "$SSH" "{\"password\":\"$(raw_parameter "$ACCOUNT")\"}")
check "an Account's encrypted password pasted into another connection is saved" 204 "$(status_of "$R")"
check "...as plaintext, for guacd" "T2-Enc-Typed1!" "$(stored_password "$SSH")"

# ---------------------------------------------------------------- rotation
section "Rotation"
BEFORE=$(stored_password "$ACCOUNT")
check "rotation of the Account succeeds" SUCCESS "$(rotate "$ACCOUNT" | cut -d: -f1)"
AFTER=$(stored_password "$ACCOUNT")
check "...the new password is stored encrypted" yes "$(is_encrypted "$AFTER")"
check "...the KDC accepts it" yes "$(mit_accepts t2enc "$(reveal connection-password "$AFTER")")"
check "...and refuses the old one" no "$(mit_accepts t2enc "$(reveal connection-password "$BEFORE")")"
check "...which a checkout hands over" "$(reveal connection-password "$AFTER")" "$(checkout_password "$ACCOUNT")"

# The password about to be set is kept from before the target is touched
# until the rotation is confirmed: seen during a rotation slowed down on the
# SSH server, whose account the seeded "PAM test (Linux)" connection shares
SEEDED=$(connection_id "PAM test (Linux)")
SSH_PASSWORD=$( [ -n "$SEEDED" ] && parameter "$SEEDED" password )
[ "$(ssh_accepts mysshtest "$SSH_PASSWORD")" = yes ] || SSH_PASSWORD='P@ssw0rd'
create_platform SLOW '{"name":"t2 enc slow passwd","type":"ssh","settings":{"script":"@timeout 20\nsleep 5; passwd\n@expect assword:\n<OLDPASS>\n@expect assword:\n<NEWPASS>\n@expect assword:\n<NEWPASS>\n@regex (?i)(success|updated|changed)\n"},"policy":{}}'
create_connection SLOW_C "{\"name\":\"t2 enc slow\",\"parentIdentifier\":\"ROOT\",\"protocol\":\"ssh\",
    \"parameters\":{\"hostname\":\"mysshtest\",\"port\":\"22\",\"username\":\"mysshtest\",\"password\":\"$SSH_PASSWORD\"},
    \"attributes\":{\"pam-platform\":\"$SLOW\",\"pam-request-exempt\":\"true\"}}"
sync_seeded_ssh() {
    [ -n "$SEEDED" ] && edit_connection "$ADMIN" "$SEEDED" "{\"password\":\"$(parameter "$SLOW_C" password)\"}" >/dev/null
}
on_cleanup sync_seeded_ssh

rotate "$SLOW_C" >"$T2_TMP/slow" &
ROTATION=$!
sleep 2
PENDING=$(sql "SELECT pending_password FROM pam_rotation_state WHERE connection_id = $SLOW_C")
wait $ROTATION
check "during a rotation, the password about to be set is stored encrypted" yes "$(is_encrypted "$PENDING")"
check "...the rotation succeeds" SUCCESS "$(cut -d: -f1 "$T2_TMP/slow")"
check "...the pending password was the new password" "$(parameter "$SLOW_C" password)" "$(reveal pending-password "$PENDING")"
check "...which is plaintext once stored for guacd" "$(parameter "$SLOW_C" password)" "$(stored_password "$SLOW_C")"
check "...and the SSH server accepts" yes "$(ssh_accepts mysshtest "$(stored_password "$SLOW_C")")"
check "...and the pending password is gone" "" "$(sql "SELECT pending_password FROM pam_rotation_state WHERE connection_id = $SLOW_C")"
