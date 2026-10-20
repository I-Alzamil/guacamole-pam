#!/bin/bash
# Testing platforms before saving them (the Test button of the Platforms
# page): LDAP (OpenLDAP and Samba AD) and Kerberos (MIT and Samba AD), with
# and without a rotation account, each way a test can fail, stored secrets
# reused only where they were entered for, nothing saved, and only for
# administrators.

LDAP_ADMIN_DN="cn=admin,dc=example,dc=org"; LDAP_ADMIN_PASSWORD="LdapAdm1n"
AD_ADMIN_PASSWORD="AdAdm1n-Pass"
MIT_ADMIN="admin/admin"; MIT_ADMIN_PASSWORD="KdcAdm1n-Pass"

LDAP_FP=$(podman exec myldaptest cat /container/service/slapd/assets/certs/ldap.crt | cert_fingerprint)
AD_FP=$(podman exec myadtest cat /var/lib/samba/private/tls/cert.pem | cert_fingerprint)
OTHER_FP="00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF"

# test_platform JSON [TOKEN] -> "STATUS BODY"
test_platform() { api POST "$PAM/platforms/test" "${2:-$ADMIN}" "$1"; }

# summary "STATUS BODY" -> "passed: STATUS TEXT | ..." or "failed: ..."
summary() {
    json_get "${1#* }" "('passed' if d['success'] else 'failed') + ': ' + ' | '.join(s['status'] + ' ' + s['text'] for s in d['steps'])"
}

# ldap SETTINGS -> a platform of that type, named for these tests
ldap() { printf '{"name":"t2 test ldap","type":"ldap","settings":{%s},"policy":{}}' "$1"; }
kerberos() { printf '{"name":"t2 test kerberos","type":"kerberos","settings":{%s},"policy":{}}' "$1"; }

OPENLDAP="\"hostname\":\"myldaptest\",\"ldap-certificate-fingerprint\":\"$LDAP_FP\""
LDAP_ADMIN="\"ldap-admin-dn\":\"$LDAP_ADMIN_DN\",\"ldap-admin-password\":\"$LDAP_ADMIN_PASSWORD\""
MIT="\"kerberos-realm\":\"EXAMPLE.ORG\",\"kerberos-kdc\":\"mykdctest\""

# ---------------------------------------------------------------- LDAP
section "Testing LDAP platforms"

R=$(summary "$(test_platform "$(ldap "$OPENLDAP,$LDAP_ADMIN")")")
check_contains "OpenLDAP over LDAPS with its rotation account: passed" "passed: " "$R"
check_contains "...the pinned certificate recognized" "Its certificate $LDAP_FP is the pinned one." "$R"
check_contains "...and the rotation account signed in" "PASSED The rotation account signed in." "$R"

R=$(summary "$(test_platform "$(ldap "$OPENLDAP,\"ldap-encryption\":\"starttls\",\"port\":\"389\",$LDAP_ADMIN")")")
check_contains "over StartTLS: passed" "passed: PASSED Connected to myldaptest:389 over StartTLS." "$R"

R=$(summary "$(test_platform "$(ldap "$OPENLDAP")")")
check "without a rotation account: passed, saying so" \
    "passed: PASSED Connected to myldaptest:636 over LDAPS. Its certificate $LDAP_FP is the pinned one. | INFO No rotation account: each account changes its own password." "$R"

R=$(summary "$(test_platform "$(ldap "$OPENLDAP,\"ldap-admin-dn\":\"$LDAP_ADMIN_DN\",\"ldap-admin-password\":\"wrong\"")")")
check_contains "a wrong rotation account password: failed" "failed: " "$R"
check_contains "...at signing in, after connecting" "| FAILED The directory rejected the rotation account credentials." "$R"

R=$(summary "$(test_platform "$(ldap "\"hostname\":\"myldaptest\",\"ldap-certificate-fingerprint\":\"$OTHER_FP\",$LDAP_ADMIN")")")
check_contains "another pinned certificate: failed, sending no credentials" \
    "failed: FAILED The LDAP server certificate $LDAP_FP does not match the pinned fingerprint. No credentials were sent." "$R"

R=$(summary "$(test_platform "$(ldap "\"hostname\":\"myldaptest\",$LDAP_ADMIN")")")
check_contains "a certificate of a CA Java does not trust: failed" "failed: FAILED The LDAP server certificate" "$R"
check_contains "...naming its fingerprint, to pin in the platform" "$LDAP_FP is not trusted" "$R"

R=$(summary "$(test_platform "$(ldap "\"hostname\":\"t2-no-such-host\",\"ldap-certificate-fingerprint\":\"$LDAP_FP\"")")")
check_contains "an unknown server: failed" "failed: FAILED Unable to reach the LDAP server" "$R"

R=$(summary "$(test_platform "{\"name\":\"t2 test ad\",\"type\":\"ldap\",\"settings\":{\"hostname\":\"myadtest\",
    \"ldap-directory-type\":\"active-directory\",\"ldap-certificate-fingerprint\":\"$AD_FP\",
    \"ldap-admin-dn\":\"CN=Administrator,CN=Users,DC=ad,DC=example,DC=org\",\"ldap-admin-password\":\"$AD_ADMIN_PASSWORD\"},\"policy\":{}}")")
check_contains "Samba AD with its administrator: passed" "passed: " "$R"
check_contains "...the administrator signed in" "PASSED The rotation account signed in." "$R"

# ---------------------------------------------------------------- Kerberos
section "Testing Kerberos platforms"

R=$(summary "$(test_platform "$(kerberos "$MIT,\"kerberos-admin-principal\":\"$MIT_ADMIN\",\"kerberos-admin-password\":\"$MIT_ADMIN_PASSWORD\"")")")
check "MIT with its admin principal: passed, ticket then password change server" \
    "passed: PASSED The KDC mykdctest:88 gave the admin principal a password change ticket, so it knows its password. | PASSED The password change server mykdctest:464 accepts connections." "$R"

R=$(summary "$(test_platform "$(kerberos "$MIT,\"kerberos-admin-principal\":\"$MIT_ADMIN\",\"kerberos-admin-password\":\"wrong\"")")")
check "a wrong admin principal password: failed" "failed: FAILED The KDC rejected the admin principal's password." "$R"

R=$(summary "$(test_platform "$(kerberos "$MIT,\"kerberos-admin-principal\":\"t2-no-such-admin\",\"kerberos-admin-password\":\"x\"")")")
check "an unknown admin principal: failed" "failed: FAILED The KDC does not know the admin principal." "$R"

R=$(summary "$(test_platform "$(kerberos "$MIT")")")
check "without an admin principal: the realm checked, saying so" \
    "passed: PASSED The KDC mykdctest:88 serves the realm EXAMPLE.ORG. | INFO No admin principal: each principal changes its own password. | PASSED The password change server mykdctest:464 accepts connections." "$R"

R=$(summary "$(test_platform "$(kerberos "\"kerberos-realm\":\"T2.NO-SUCH.REALM\",\"kerberos-kdc\":\"mykdctest\"")")")
check_contains "a realm the KDC does not serve: not confirmed, saying so" \
    "PASSED The KDC mykdctest:88 answers, without saying whether it serves the realm T2.NO-SUCH.REALM." "$R"

R=$(summary "$(test_platform "$(kerberos "$MIT,\"kerberos-kpasswd-port\":\"1\"")")")
check_contains "an unreachable password change server: failed" \
    "| FAILED Unable to reach the password change server mykdctest:1: " "$R"

R=$(summary "$(test_platform "$(kerberos "\"kerberos-realm\":\"EXAMPLE.ORG\",\"kerberos-kdc\":\"t2-no-such-host\"")")")
check_contains "an unknown KDC: failed" "failed: FAILED Unable to reach the KDC t2-no-such-host:88: " "$R"

R=$(summary "$(test_platform "{\"name\":\"t2 test ad kerberos\",\"type\":\"kerberos\",\"settings\":{\"kerberos-realm\":\"AD.EXAMPLE.ORG\",
    \"kerberos-kdc\":\"myadtest\",\"kerberos-admin-principal\":\"Administrator\",\"kerberos-admin-password\":\"$AD_ADMIN_PASSWORD\"},\"policy\":{}}")")
check "Samba AD with its administrator: passed" \
    "passed: PASSED The KDC myadtest:88 gave the admin principal a password change ticket, so it knows its password. | PASSED The password change server myadtest:464 accepts connections." "$R"

R=$(summary "$(test_platform "$(kerberos "\"kerberos-realm\":\"AD.EXAMPLE.ORG\",\"kerberos-kdc\":\"myadtest\"")")")
check_contains "Samba AD without an admin principal: the KDC answers, the realm left to the first rotation" \
    "passed: PASSED The KDC myadtest:88 answers, without saying whether it serves the realm AD.EXAMPLE.ORG." "$R"

# ---------------------------------------------------------------- stored secrets
section "Testing a saved platform: stored secrets"

create_platform STORED "$(ldap "$OPENLDAP,$LDAP_ADMIN" | sed 's/"t2 test ldap"/"t2 test stored"/')"

R=$(summary "$(test_platform "{\"id\":$STORED,\"name\":\"t2 test stored\",\"type\":\"ldap\",\"settings\":{$OPENLDAP,
    \"ldap-admin-dn\":\"$LDAP_ADMIN_DN\"},\"policy\":{}}")")
check_contains "the stored password, left empty, is the one tested" "PASSED The rotation account signed in." "$R"

R=$(test_platform "{\"id\":$STORED,\"name\":\"t2 test stored\",\"type\":\"ldap\",\"settings\":{$OPENLDAP,
    \"port\":\"389\",\"ldap-encryption\":\"starttls\",\"ldap-admin-dn\":\"$LDAP_ADMIN_DN\"},\"policy\":{}}")
check "...but never sent where it was not entered for" 400 "$(status_of "$R")"
check_contains "...asking for it again" "enter it again" "$(message_of "$R")"

R=$(summary "$(test_platform "{\"id\":$STORED,\"name\":\"t2 test stored\",\"type\":\"ldap\",\"settings\":{$OPENLDAP,
    \"ldap-admin-dn\":\"$LDAP_ADMIN_DN\",\"ldap-admin-password\":\"wrong\"},\"policy\":{}}")")
check_contains "a password typed in is tested instead" "FAILED The directory rejected the rotation account credentials." "$R"
check "...and not saved" "PASSED" \
    "$(json_get "$(test_platform "{\"id\":$STORED,\"name\":\"t2 test stored\",\"type\":\"ldap\",\"settings\":{$OPENLDAP,
        \"ldap-admin-dn\":\"$LDAP_ADMIN_DN\"},\"policy\":{}}" | cut -d' ' -f2-)" "d['steps'][-1]['status']")"

R=$(api PUT "$PAM/platforms/$STORED" "$ADMIN" "{\"name\":\"t2 test stored\",\"type\":\"ldap\",\"settings\":{$OPENLDAP,
    \"ldap-admin-dn\":\"$LDAP_ADMIN_DN\"},\"policy\":{}}")
check "saved with the password left out, it is kept" "['ldap-admin-password']" "$(json_get "${R#* }" "d.get('storedSecrets')")"
R=$(api PUT "$PAM/platforms/$STORED" "$ADMIN" "{\"name\":\"t2 test stored\",\"type\":\"ldap\",\"settings\":{$OPENLDAP,
    \"ldap-admin-password\":\"\"},\"policy\":{}}")
check "saved with the password empty, it is removed" "[]" "$(json_get "${R#* }" "d.get('storedSecrets')")"

check "a saved platform cannot be tested as another type" 400 \
    "$(status_of "$(test_platform "{\"id\":$STORED,\"name\":\"t2 test stored\",\"type\":\"kerberos\",\"settings\":{$MIT},\"policy\":{}}")")"

# ---------------------------------------------------------------- limits
section "Testing platforms: limits"

check "nothing is saved by a test" "" "$(platform_id "t2 test ldap")"
check "invalid settings are refused as when saving" 400 \
    "$(status_of "$(test_platform "$(kerberos "\"kerberos-kdc\":\"mykdctest\"")")")"
check "SSH platforms cannot be tested" 400 \
    "$(status_of "$(test_platform '{"name":"t2 test ssh","type":"ssh","settings":{"script":"passwd\n<NEWPASS>"},"policy":{}}')")"

create_user t2-test-user t2-test-user-pw
USER_TOKEN=$(token t2-test-user t2-test-user-pw)
check "a user who is not an administrator cannot test" 403 \
    "$(status_of "$(test_platform "$(ldap "$OPENLDAP,$LDAP_ADMIN")" "$USER_TOKEN")")"
