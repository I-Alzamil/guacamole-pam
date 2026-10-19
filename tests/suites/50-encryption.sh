#!/bin/bash
# Encryption at rest: what the database holds (platform secrets, Account
# passwords and pending passwords encrypted; connections' passwords, keys and
# passphrases kept apart, encrypted, behind tokens such as ${PAM_PASSWORD_17};
# Guacamole's own tokens left alone), what the API returns, saving
# connections from the editor, and sessions, also through balancing groups.
# Skipped when the test setup has no key.

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
check "a connection's password is kept apart, behind its token" "\${PAM_PASSWORD_$SSH}" "$(stored_password "$SSH")"
check "...and is the password" "T2-Ssh-Plain1!" "$(parameter "$SSH" password)"
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

# Stored decrypted, an editor could read it back: a decryption oracle
R=$(edit_connection "$ADMIN" "$SSH" "{\"password\":\"$(raw_parameter "$ACCOUNT")\"}")
check "an Account's encrypted password pasted into another connection is refused" 400 "$(status_of "$R")"
check_contains "...as encrypted passwords are not copied" "cannot be copied" "$(message_of "$R")"
check "...and that connection's password is unchanged" "T2-Ssh-Plain1!" "$(parameter "$SSH" password)"

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
# The connection that last changed mysshtest's password
LAST_SSH=$SLOW_C
sync_seeded_ssh() {
    local password
    password=$(parameter "$LAST_SSH" password)
    [ -n "$SEEDED" ] && [ -n "$password" ] \
        && edit_connection "$ADMIN" "$SEEDED" "{\"password\":\"$password\"}" >/dev/null
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
check "...and the SSH server accepts" yes "$(ssh_accepts mysshtest "$(parameter "$SLOW_C" password)")"
check "...and the pending password is gone" "" "$(sql "SELECT pending_password FROM pam_rotation_state WHERE connection_id = $SLOW_C")"

# ---------------------------------------------------------------- connections
section "Connections: secrets kept apart"
guacd_logged_in_since() { # TIME: how many SSH logins guacd logged since then
    podman logs --since "$1" myguacdtest 2>&1 | grep -c 'SSH connection successful'
}
# With its own login: Guacamole may end the session whose connection guacd
# reports a login rejected
session_of() { # ID [TYPE]: opens a session for a few seconds; whether guacd logged a login
    local since file
    since=$(date -u +%Y-%m-%dT%H:%M:%SZ)
    file="$T2_TMP/session-$1"
    python3 -I ./session.py "$GUAC_URL" "$(admin_token)" "$1" "${2:-c}" >"$file" 2>&1 &
    sleep 6
    kill $! 2>/dev/null
    [ "$(guacd_logged_in_since "$since")" -gt 0 ] && echo yes || echo no
}
kept() { sql "SELECT value FROM pam_connection_secret WHERE connection_id = $1 AND parameter_name = '${2:-password}'"; }
ssh_connection() { # VARIABLE NAME EXTRA-PARAMETERS-JSON [ATTRIBUTES-JSON] [PARENT]
    create_connection "$1" "$(python3 -I -c '
import json, sys
parameters = {"hostname": "mysshtest", "port": "22", "username": "mysshtest"}
parameters.update(json.loads(sys.argv[2]))
attributes = {"pam-request-exempt": "true"}
attributes.update(json.loads(sys.argv[3]))
print(json.dumps({"name": sys.argv[1], "parentIdentifier": sys.argv[4], "protocol": "ssh",
                  "parameters": parameters, "attributes": attributes}))' "$2" "$3" "${4:-{\}}" "${5:-ROOT}")"
}

ssh_connection WRONG "t2 enc wrong" '{"password": "T2-Wrong-1!"}'
check "control: with a wrong password, guacd logs no SSH login" no "$(session_of "$WRONG")"

LINUX=$(platform_id "Linux (passwd)")
CURRENT=$(parameter "$SLOW_C" password)
ssh_connection MANAGED "t2 enc managed" "{\"password\": \"$CURRENT\"}" "{\"pam-platform\": \"$LINUX\"}"
LAST_SSH=$MANAGED
on_cleanup sync_seeded_ssh
TOKEN="\${PAM_PASSWORD_$MANAGED}"

check "the password parameter is the token naming its connection" "$TOKEN" "$(stored_password "$MANAGED")"
KEPT=$(kept "$MANAGED")
check "...the password is kept encrypted" yes "$(is_encrypted "$KEPT")"
check "...for this connection and field alone" "$CURRENT" "$(reveal "connection-secret:$MANAGED:password" "$KEPT")"
check "...and the API shows editors only the token" "$TOKEN" "$(raw_parameter "$MANAGED")"
check "a session logs in with the kept password" yes "$(session_of "$MANAGED")"

check "rotation succeeds" SUCCESS "$(rotate "$MANAGED" | cut -d: -f1)"
check "...the parameter is still the token" "$TOKEN" "$(stored_password "$MANAGED")"
check "...the SSH server accepts the new kept password" yes "$(ssh_accepts mysshtest "$(parameter "$MANAGED" password)")"
check "...and refuses the previous one" no "$(ssh_accepts mysshtest "$CURRENT")"
check "...and a session logs in with it" yes "$(session_of "$MANAGED")"

KEPT=$(kept "$MANAGED")
edit_connection "$ADMIN" "$MANAGED" '' '' "t2 enc managed renamed" >/dev/null
check "saved unchanged (the editor sends the token back), the kept password is unchanged" "$KEPT" "$(kept "$MANAGED")"

R=$(edit_connection "$ADMIN" "$MANAGED" "{\"command\":\"echo $TOKEN\"}")
check "the token in another field, where Guacamole would replace it too, is refused" 400 "$(status_of "$R")"
check_contains "...as it only belongs in its field and connection" "can only be used in the field and connection" "$(message_of "$R")"
R=$(edit_connection "$ADMIN" "$SSH" "{\"password\":\"$TOKEN\"}")
check_contains "another connection's token is refused" "can only be used in the field and connection" "$(message_of "$R")"
R=$(edit_connection "$ADMIN" "$SSH" "{\"password\":\"$KEPT\"}")
check_contains "a kept value pasted into another connection is refused" "cannot be copied" "$(message_of "$R")"

R=$(edit_connection "$ADMIN" "$SSH" '{"password":"${GUAC_PASSWORD}"}')
check "Guacamole's own tokens are accepted" 204 "$(status_of "$R")"
check "...and stay in the parameter, for Guacamole to replace" '${GUAC_PASSWORD}' "$(stored_password "$SSH")"
check "...with nothing kept for them" "" "$(kept "$SSH")"

# Moved in the database, a kept value does not decrypt for another connection
sql "UPDATE pam_connection_secret SET value = (SELECT value FROM pam_connection_secret
     WHERE connection_id = $SLOW_C AND parameter_name = 'password') WHERE connection_id = $MANAGED" >/dev/null
check "another connection's kept password, moved in the database, is refused" 500 "$(tunnel "$ADMIN" "$MANAGED" c | cut -d' ' -f1)"
check_contains "...and the log says why" 'Connection "t2 enc managed renamed" cannot be opened: A secret could not be decrypted' \
    "$(podman logs --since 1m myguactest 2>&1 | grep 'cannot be opened')"
R=$(rotate "$MANAGED")
check "...and a rotation fails before trying the SSH server with it" FAILED "${R%%:*}"
check_contains "...saying why" "stored secrets cannot be read" "$R"
sql "UPDATE pam_connection_secret SET value = '$KEPT' WHERE connection_id = $MANAGED AND parameter_name = 'password'" >/dev/null
check "...and work again once restored" yes "$(session_of "$MANAGED")"

# ---------------------------------------------------------------- keys
section "Private keys and passphrases"
PASSPHRASE='T2 key passphrase'
ssh-keygen -q -t rsa -b 2048 -m PEM -N "$PASSPHRASE" -C t2-test-key -f "$T2_TMP/key"
podman exec -i mysshtest sh -c 'cat >> /config/.ssh/authorized_keys' < "$T2_TMP/key.pub"
on_cleanup "podman exec mysshtest sed -i '/t2-test-key/d' /config/.ssh/authorized_keys"
PRIVATE_KEY=$(cat "$T2_TMP/key")
ssh_connection KEYED "t2 enc keyed" "$(python3 -I -c 'import json,sys; print(json.dumps({"private-key": sys.argv[1], "passphrase": sys.argv[2]}))' "$PRIVATE_KEY" "$PASSPHRASE")"
check "the private key is kept apart" "\${PAM_PRIVATE_KEY_$KEYED}" "$(json_get "$(curl -s "$DATA/connections/$KEYED/parameters?token=$ADMIN")" "d.get('private-key')")"
check "...and the passphrase" "\${PAM_PASSPHRASE_$KEYED}" "$(json_get "$(curl -s "$DATA/connections/$KEYED/parameters?token=$ADMIN")" "d.get('passphrase')")"
check "...both encrypted" "yes yes" "$(is_encrypted "$(kept "$KEYED" private-key)") $(is_encrypted "$(kept "$KEYED" passphrase)")"
check "...the key as given" "$PRIVATE_KEY" "$(reveal "connection-secret:$KEYED:private-key" "$(kept "$KEYED" private-key)")"
check "a session logs in with the kept key and passphrase" yes "$(session_of "$KEYED")"

# ---------------------------------------------------------------- balancing groups
section "Balancing groups"
# Guacamole allows one session per user and group by default
create_group BALANCE '{"name":"t2 enc balance","parentIdentifier":"ROOT","type":"BALANCING","attributes":{"max-connections-per-user":"2"}}'
CURRENT=$(parameter "$MANAGED" password)
ssh_connection MEMBER_PW "t2 enc member password" "{\"password\": \"$CURRENT\"}" '{}' "$BALANCE"
ssh_connection MEMBER_KEY "t2 enc member key" "$(python3 -I -c 'import json,sys; print(json.dumps({"private-key": sys.argv[1], "passphrase": sys.argv[2]}))' "$PRIVATE_KEY" "$PASSPHRASE")" '{}' "$BALANCE"
check "members keep their secrets apart" "\${PAM_PASSWORD_$MEMBER_PW} \${PAM_PRIVATE_KEY_$MEMBER_KEY}" \
    "$(stored_password "$MEMBER_PW") $(json_get "$(curl -s "$DATA/connections/$MEMBER_KEY/parameters?token=$ADMIN")" "d.get('private-key')")"

# Two sessions at once: the group opens each member once
SINCE=$(date -u +%Y-%m-%dT%H:%M:%SZ)
HISTORY=$(sql "SELECT coalesce(max(history_id), 0) FROM guacamole_connection_history")
for i in 1 2; do
    python3 -I ./session.py "$GUAC_URL" "$(admin_token)" "$BALANCE" g >"$T2_TMP/balance-$i" 2>&1 &
    echo $! >"$T2_TMP/balance-$i.pid"
    sleep 2
done
sleep 4
for i in 1 2; do kill "$(cat "$T2_TMP/balance-$i.pid")" 2>/dev/null; done
check "two sessions through the group open both members" "$(printf '%s\n' "$MEMBER_PW" "$MEMBER_KEY" | sort | xargs)" \
    "$(sql "SELECT string_agg(DISTINCT connection_id::text, ' ' ORDER BY connection_id::text) FROM guacamole_connection_history
            WHERE history_id > $HISTORY AND connection_id IN ($MEMBER_PW, $MEMBER_KEY)")"
check "...and both log in, with their own secrets" 2 "$(guacd_logged_in_since "$SINCE")"
