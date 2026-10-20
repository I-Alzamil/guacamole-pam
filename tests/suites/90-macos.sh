#!/bin/bash
# The macOS default platform against a real Mac: the account's password and
# its login keychain's, a keychain left behind reported, and an account
# without a keychain. Skipped unless T2_MACOS_HOST, T2_MACOS_USER and
# T2_MACOS_PASSWORD name a throwaway standard (not administrator) account
# with Remote Login allowed, whose login keychain uses the same password.
# The account's password is left changed, and its login keychain deleted;
# the suite prints the last password.

if [ -z "$T2_MACOS_HOST" ] || [ -z "$T2_MACOS_USER" ] || [ -z "$T2_MACOS_PASSWORD" ]; then
    section "Skipped: no Mac (set T2_MACOS_HOST, T2_MACOS_USER and T2_MACOS_PASSWORD)"
    return 0
fi

printf '#!/bin/sh\nprintf "%%s\\n" "$T2PW"\n' > "$T2_TMP/askpass"
chmod 700 "$T2_TMP/askpass"

# mac_run PASSWORD COMMAND -> output of COMMAND, run as the account
mac_run() {
    T2PW="$1" SSH_ASKPASS="$T2_TMP/askpass" SSH_ASKPASS_REQUIRE=force ssh -o StrictHostKeyChecking=no \
        -o UserKnownHostsFile=/dev/null -o PubkeyAuthentication=no -o NumberOfPasswordPrompts=1 -o LogLevel=ERROR \
        "$T2_MACOS_USER@$T2_MACOS_HOST" "$2" 2>&1
}
mac_accepts() { [ "$(mac_run "$2" 'echo t2-in')" = t2-in ] && echo yes || echo no; }
keychain_opens() {
    mac_run "$1" "security lock-keychain login.keychain; security unlock-keychain -p '$2' login.keychain && echo t2-open" \
        | grep -q t2-open && echo yes || echo no
}

section "macOS: the account's password and its login keychain's"
check "precondition: the account's password is known" yes "$(mac_accepts "$T2_MACOS_USER" "$T2_MACOS_PASSWORD")"
check "precondition: its login keychain uses the same password" yes "$(keychain_opens "$T2_MACOS_PASSWORD" "$T2_MACOS_PASSWORD")"
check "precondition: it is not an administrator" no \
    "$(mac_run "$T2_MACOS_PASSWORD" 'id -Gn' | tr ' ' '\n' | grep -qx admin && echo yes || echo no)"

MACOS=$(platform_id "macOS")
create_connection MAC_C "{\"name\":\"t2 macos\",\"parentIdentifier\":\"ROOT\",\"protocol\":\"ssh\",
    \"parameters\":{\"hostname\":\"$T2_MACOS_HOST\",\"port\":\"22\",\"username\":\"$T2_MACOS_USER\",\"password\":\"$T2_MACOS_PASSWORD\"},
    \"attributes\":{\"pam-platform\":\"$MACOS\",\"pam-request-exempt\":\"true\"}}"

for round in 1 2; do
    OLD=$(parameter "$MAC_C" password)
    RESULT=$(rotate "$MAC_C")
    NEW=$(parameter "$MAC_C" password)
    check "macOS: rotation $round completes without a problem" "SUCCESS" "$RESULT"
    check "macOS: rotation $round, the Mac accepts the new password" yes "$(mac_accepts "$T2_MACOS_USER" "$NEW")"
    check "macOS: rotation $round, ...and refuses the old one" no "$(mac_accepts "$T2_MACOS_USER" "$OLD")"
    check "macOS: rotation $round, the login keychain opens with the new password" yes "$(keychain_opens "$NEW" "$NEW")"
done

section "macOS: a login keychain on another password"
CURRENT=$(parameter "$MAC_C" password)
mac_run "$CURRENT" "security set-keychain-password -o '$CURRENT' -p 'T2-Other-Keychain1!' login.keychain" >/dev/null
check "precondition: the keychain no longer uses the account's password" yes "$(keychain_opens "$CURRENT" 'T2-Other-Keychain1!')"
RESULT=$(rotate "$MAC_C")
NEW=$(parameter "$MAC_C" password)
check "macOS: the new password is kept" "SUCCESS" "${RESULT%%:*}"
check_contains "macOS: ...with the keychain reported" "login keychain password was not changed" "$RESULT"
check "macOS: ...and the Mac accepts it" yes "$(mac_accepts "$T2_MACOS_USER" "$NEW")"
mac_run "$NEW" "security set-keychain-password -o 'T2-Other-Keychain1!' -p '$NEW' login.keychain" >/dev/null
check "macOS: the keychain set back to the account's password" yes "$(keychain_opens "$NEW" "$NEW")"

section "macOS: an account without a login keychain"
mac_run "$NEW" "security delete-keychain login.keychain" >/dev/null
check "precondition: the account has no login keychain" no \
    "$(mac_run "$NEW" '[ -f ~/Library/Keychains/login.keychain-db ] && echo yes || echo no')"
OLD=$NEW
RESULT=$(rotate "$MAC_C")
NEW=$(parameter "$MAC_C" password)
check "macOS without a keychain: the rotation completes without a problem" "SUCCESS" "$RESULT"
check "macOS without a keychain: the Mac accepts the new password" yes "$(mac_accepts "$T2_MACOS_USER" "$NEW")"
check "macOS without a keychain: ...and refuses the old one" no "$(mac_accepts "$T2_MACOS_USER" "$OLD")"

printf '  The password of %s on %s is now: %s\n' "$T2_MACOS_USER" "$T2_MACOS_HOST" "$NEW"
