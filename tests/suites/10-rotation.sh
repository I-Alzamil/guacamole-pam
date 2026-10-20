#!/bin/bash
# Rotation over SSH, LDAP (OpenLDAP and Samba AD) and Kerberos (MIT and Samba
# AD), by an administrator account and by the account itself, each checked
# directly on the server; plus certificate and host key pinning.

LDAP_ADMIN_DN="cn=admin,dc=example,dc=org"; LDAP_ADMIN_PASSWORD="LdapAdm1n"
AD_ADMIN_PASSWORD="AdAdm1n-Pass"
MIT_ADMIN="admin/admin"; MIT_ADMIN_PASSWORD="KdcAdm1n-Pass"

LDAP_FP=$(podman exec myldaptest cat /container/service/slapd/assets/certs/ldap.crt | cert_fingerprint)
AD_FP=$(podman exec myadtest cat /var/lib/samba/private/tls/cert.pem | cert_fingerprint)

# ---------------------------------------------------------------- SSH
section "SSH: Unix, the account changes its own password"

# The image only lets its own user in, so the seeded connection's account is
# used, and its new password is written back to that connection afterwards
SEEDED=$(connection_id "PAM test (Linux)")
SSH_PASSWORD=$( [ -n "$SEEDED" ] && parameter "$SEEDED" password )
[ "$(ssh_accepts mysshtest "$SSH_PASSWORD")" = yes ] || SSH_PASSWORD='P@ssw0rd'
check "precondition: mysshtest's current password is known" yes "$(ssh_accepts mysshtest "$SSH_PASSWORD")"

LINUX=$(platform_id "Unix")
create_connection SSH_C "{\"name\":\"t2 ssh\",\"parentIdentifier\":\"ROOT\",\"protocol\":\"ssh\",
    \"parameters\":{\"hostname\":\"mysshtest\",\"port\":\"22\",\"username\":\"mysshtest\",\"password\":\"$SSH_PASSWORD\"},
    \"attributes\":{\"pam-platform\":\"$LINUX\",\"pam-request-exempt\":\"true\"}}"
# Keeps the seeded connection's password in step with the account
sync_seeded_ssh() {
    [ -n "$SEEDED" ] && edit_connection "$ADMIN" "$SEEDED" "{\"password\":\"$(parameter "$SSH_C" password)\"}" >/dev/null
}
on_cleanup sync_seeded_ssh

rotate_and_verify "$SSH_C" "SSH" ssh_accepts mysshtest

edit_connection "$ADMIN" "$SSH_C" '' '{"pam-ssh-host-key":"SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}' >/dev/null
RESULT=$(rotate "$SSH_C")
check "SSH: a host key other than the pinned one is refused" "FAILED" "${RESULT%%:*}"
check_contains "SSH: ...before any credentials are sent" "No credentials were sent" "$RESULT"
check "SSH: ...and the password still works" yes "$(ssh_accepts mysshtest "$(parameter "$SSH_C" password)")"
edit_connection "$ADMIN" "$SSH_C" '' '{"pam-ssh-host-key":null}' >/dev/null
check "SSH: with the pin removed, rotation works again" "SUCCESS" "$(rotate "$SSH_C" | cut -d: -f1)"

section "SSH: a script choosing by the prompt, as the account and as root"

# choice_platform VARIABLE NAME COMMAND: the Unix default, with COMMAND in place
# of passwd (passwd asks root for no current password)
UNIX_SCRIPT=$(json_get "$(api GET "$PAM/platforms/$LINUX" "$ADMIN" | cut -d' ' -f2-)" "d['settings']['script']")
choice_platform() {
    create_platform "$1" "$(python3 -I -c 'import json,sys; print(json.dumps({"name": sys.argv[1], "type": "ssh",
        "settings": {"script": sys.argv[3].replace("\npasswd\n", "\n" + sys.argv[2] + "\n", 1)}, "policy": {}}))' \
        "$2" "$3" "$UNIX_SCRIPT")"
}
choice_platform OWN_CHOICE "t2 ssh choice own" "passwd"
choice_platform ROOT_CHOICE "t2 ssh choice root" "sudo passwd <USER>"
check_contains "precondition: the root script runs passwd as root" "sudo passwd" \
    "$(json_get "$(api GET "$PAM/platforms/$ROOT_CHOICE" "$ADMIN" | cut -d' ' -f2-)" "d['settings']['script']")"

# Only for this test, the account may run passwd as root
podman exec mysshtest sh -c 'echo "mysshtest ALL=(root) NOPASSWD: /usr/bin/passwd mysshtest" > /etc/sudoers.d/t2-passwd'
on_cleanup "podman exec mysshtest rm -f /etc/sudoers.d/t2-passwd"

for platform in "$OWN_CHOICE:as the account" "$ROOT_CHOICE:as root"; do
    edit_connection "$ADMIN" "$SSH_C" '' "{\"pam-platform\":\"${platform%%:*}\"}" >/dev/null
    RESULT=$(rotate "$SSH_C")
    check "SSH choice, ${platform#*:}: the change completes without a problem" "SUCCESS" "$RESULT"
    check "SSH choice, ${platform#*:}: the server accepts the new password" yes \
        "$(ssh_accepts mysshtest "$(parameter "$SSH_C" password)")"
done

edit_connection "$ADMIN" "$SSH_C" '' "{\"pam-platform\":\"$OWN_CHOICE\"}" >/dev/null
podman exec mysshtest sh -c 'printf "#!/bin/sh\necho Changing password\n" > /tmp/t2-nocase; chmod 755 /tmp/t2-nocase'
on_cleanup "podman exec mysshtest rm -f /tmp/t2-nocase"
choice_platform NO_CASE "t2 ssh choice none" "$(printf '@timeout 3\n/tmp/t2-nocase')"
edit_connection "$ADMIN" "$SSH_C" '' "{\"pam-platform\":\"$NO_CASE\"}" >/dev/null
RESULT=$(rotate "$SSH_C")
check "SSH choice: when no case matches, the rotation fails" "FAILED" "${RESULT%%:*}"
check_contains "SSH choice: ...saying so" "matched none of the cases" "$RESULT"
check "SSH choice: ...and the password still works" yes "$(ssh_accepts mysshtest "$(parameter "$SSH_C" password)")"

# @fail: echo prints the text only once worked out, so the command line itself does not match
create_platform AFTER_FAIL "$(python3 -I -c 'import json,sys; print(json.dumps({"name": "t2 ssh fail after", "type": "ssh",
    "settings": {"script": sys.argv[1] + "\necho t2-$((1+1))-error\n@case t2-2-error\n@fail Second step not done.\n"
    "@case t2-nomatch\n@end\n"}, "policy": {}}))' "$UNIX_SCRIPT")"
edit_connection "$ADMIN" "$SSH_C" '' "{\"pam-platform\":\"$AFTER_FAIL\"}" >/dev/null
RESULT=$(rotate "$SSH_C")
check "SSH @fail after the change: the new password is kept" "SUCCESS" "${RESULT%%:*}"
check_contains "SSH @fail after the change: ...with the problem reported" "Second step not done." "$RESULT"
check "SSH @fail after the change: ...and the server accepts it" yes "$(ssh_accepts mysshtest "$(parameter "$SSH_C" password)")"

choice_platform BEFORE_FAIL "t2 ssh fail before" "$(printf 'echo t2-$((1+1))-error\n@case t2-2-error\n@fail Stopped on purpose.\n@case t2-nomatch\n@end\npasswd')"
edit_connection "$ADMIN" "$SSH_C" '' "{\"pam-platform\":\"$BEFORE_FAIL\"}" >/dev/null
RESULT=$(rotate "$SSH_C")
check "SSH @fail before the change: the rotation fails" "FAILED" "${RESULT%%:*}"
check_contains "SSH @fail before the change: ...saying why" "Stopped on purpose." "$RESULT"
check "SSH @fail before the change: ...and the password still works" yes "$(ssh_accepts mysshtest "$(parameter "$SSH_C" password)")"
edit_connection "$ADMIN" "$SSH_C" '' "{\"pam-platform\":\"$LINUX\"}" >/dev/null

# ---------------------------------------------------------------- OpenLDAP
section "LDAP: OpenLDAP"

LDAP_DN="uid=t2ldap,ou=people,dc=example,dc=org"
podman exec -i myldaptest ldapadd -x -H ldap://localhost -D "$LDAP_ADMIN_DN" -w "$LDAP_ADMIN_PASSWORD" >/dev/null 2>&1 <<LDIF
dn: $LDAP_DN
objectClass: inetOrgPerson
uid: t2ldap
cn: T2 LDAP
sn: Test
userPassword: T2-Ldap-Start1!
LDIF
on_cleanup "podman exec myldaptest ldapdelete -x -H ldap://localhost -D '$LDAP_ADMIN_DN' -w '$LDAP_ADMIN_PASSWORD' '$LDAP_DN'"
check "precondition: test account created" yes "$(openldap_accepts "$LDAP_DN" 'T2-Ldap-Start1!')"

ldap_platform() { # VARIABLE NAME ENCRYPTION PORT FINGERPRINT ADMIN(yes|no)
    local var=$1; shift
    local admin=""
    [ "$5" = yes ] && admin=",\"ldap-admin-dn\":\"$LDAP_ADMIN_DN\",\"ldap-admin-password\":\"$LDAP_ADMIN_PASSWORD\""
    create_platform "$var" "{\"name\":\"$1\",\"type\":\"ldap\",\"settings\":{\"hostname\":\"myldaptest\",\"port\":\"$3\",
        \"ldap-encryption\":\"$2\",\"ldap-certificate-fingerprint\":\"$4\"$admin},\"policy\":{}}"
}
ldap_platform LDAPS_ADMIN "t2 ldaps admin" "" 636 "$LDAP_FP" yes
ldap_platform LDAPS_SELF "t2 ldaps self" "" 636 "$LDAP_FP" no
ldap_platform STARTTLS_ADMIN "t2 starttls admin" starttls 389 "$LDAP_FP" yes
ldap_platform WRONG_PIN "t2 wrong pin" "" 636 "AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99" yes
ldap_platform UNPINNED "t2 unpinned" "" 636 "" yes

create_connection LDAP_C "{\"name\":\"t2 ldap\",\"parentIdentifier\":\"ROOT\",\"protocol\":\"pam-account\",
    \"parameters\":{\"username\":\"t2ldap\",\"password\":\"T2-Ldap-Start1!\"},
    \"attributes\":{\"pam-platform\":\"$LDAPS_ADMIN\",\"pam-ldap-dn\":\"$LDAP_DN\"}}"
use_platform() { edit_connection "$ADMIN" "$1" '' "{\"pam-platform\":\"$2\"}" >/dev/null; }

rotate_and_verify "$LDAP_C" "OpenLDAP over LDAPS, rotation account" openldap_accepts "$LDAP_DN"
use_platform "$LDAP_C" "$LDAPS_SELF"; rotate_and_verify "$LDAP_C" "OpenLDAP over LDAPS, account itself" openldap_accepts "$LDAP_DN"
use_platform "$LDAP_C" "$STARTTLS_ADMIN"; rotate_and_verify "$LDAP_C" "OpenLDAP over StartTLS" openldap_accepts "$LDAP_DN" 1

use_platform "$LDAP_C" "$WRONG_PIN"; RESULT=$(rotate "$LDAP_C")
check "LDAP: a certificate other than the pinned one is refused" "FAILED" "${RESULT%%:*}"
check_contains "LDAP: ...before any credentials are sent" "No credentials were sent" "$RESULT"
use_platform "$LDAP_C" "$UNPINNED"; RESULT=$(rotate "$LDAP_C")
check "LDAP: an unpinned certificate the JVM does not trust is refused" "FAILED" "${RESULT%%:*}"
check_contains "LDAP: ...naming its fingerprint, to pin" "$LDAP_FP" "$RESULT"
check "LDAP: ...and the password still works" yes "$(openldap_accepts "$LDAP_DN" "$(parameter "$LDAP_C" password)")"

# ---------------------------------------------------------------- Samba AD over LDAP
section "LDAP: Samba Active Directory (unicodePwd)"

podman exec myadtest samba-tool user create t2ad 'T2-Ad-Start1!' --use-username-as-cn >/dev/null 2>&1
on_cleanup "podman exec myadtest samba-tool user delete t2ad"
check "precondition: test account created" yes "$(samba_accepts t2ad 'T2-Ad-Start1!')"

create_platform AD_ADMIN "{\"name\":\"t2 ad admin\",\"type\":\"ldap\",\"settings\":{\"hostname\":\"myadtest\",
    \"ldap-directory-type\":\"active-directory\",\"ldap-certificate-fingerprint\":\"$AD_FP\",
    \"ldap-admin-dn\":\"CN=Administrator,CN=Users,DC=ad,DC=example,DC=org\",\"ldap-admin-password\":\"$AD_ADMIN_PASSWORD\"},\"policy\":{}}"
create_platform AD_SELF "{\"name\":\"t2 ad self\",\"type\":\"ldap\",\"settings\":{\"hostname\":\"myadtest\",
    \"ldap-directory-type\":\"active-directory\",\"ldap-certificate-fingerprint\":\"$AD_FP\"},\"policy\":{}}"
create_connection AD_C "{\"name\":\"t2 ad\",\"parentIdentifier\":\"ROOT\",\"protocol\":\"pam-account\",
    \"parameters\":{\"username\":\"t2ad\",\"password\":\"T2-Ad-Start1!\"},
    \"attributes\":{\"pam-platform\":\"$AD_ADMIN\",\"pam-ldap-dn\":\"CN=t2ad,CN=Users,DC=ad,DC=example,DC=org\"}}"

rotate_and_verify "$AD_C" "Samba AD over LDAPS, administrator" samba_accepts t2ad
use_platform "$AD_C" "$AD_SELF"; rotate_and_verify "$AD_C" "Samba AD over LDAPS, account itself" samba_accepts t2ad

# ---------------------------------------------------------------- MIT Kerberos
section "Kerberos: MIT KDC"

podman exec mykdctest kadmin.local -q "addprinc -pw T2-Mit-Start1! t2mit" >/dev/null 2>&1
on_cleanup "podman exec mykdctest kadmin.local -q 'delprinc -force t2mit'"
check "precondition: test principal created" yes "$(mit_accepts t2mit 'T2-Mit-Start1!')"

create_platform MIT_ADMIN_P "{\"name\":\"t2 mit admin\",\"type\":\"kerberos\",\"settings\":{\"kerberos-realm\":\"EXAMPLE.ORG\",
    \"kerberos-kdc\":\"mykdctest\",\"kerberos-admin-principal\":\"$MIT_ADMIN\",\"kerberos-admin-password\":\"$MIT_ADMIN_PASSWORD\"},\"policy\":{}}"
create_platform MIT_SELF '{"name":"t2 mit self","type":"kerberos","settings":{"kerberos-realm":"EXAMPLE.ORG","kerberos-kdc":"mykdctest"},"policy":{}}'
create_connection MIT_C "{\"name\":\"t2 mit\",\"parentIdentifier\":\"ROOT\",\"protocol\":\"pam-account\",
    \"parameters\":{\"username\":\"t2mit\",\"password\":\"T2-Mit-Start1!\"},\"attributes\":{\"pam-platform\":\"$MIT_ADMIN_P\"}}"

rotate_and_verify "$MIT_C" "MIT Kerberos, admin principal" mit_accepts t2mit
use_platform "$MIT_C" "$MIT_SELF"; rotate_and_verify "$MIT_C" "MIT Kerberos, principal itself" mit_accepts t2mit

# ---------------------------------------------------------------- Samba Kerberos
section "Kerberos: Samba Active Directory KDC"

podman exec myadtest samba-tool user create t2krb 'T2-Krb-Start1!' --use-username-as-cn >/dev/null 2>&1
on_cleanup "podman exec myadtest samba-tool user delete t2krb"
check "precondition: test account created" yes "$(samba_kinit_accepts t2krb 'T2-Krb-Start1!')"

create_platform AD_KRB_ADMIN "{\"name\":\"t2 ad kerberos admin\",\"type\":\"kerberos\",\"settings\":{\"kerberos-realm\":\"AD.EXAMPLE.ORG\",
    \"kerberos-kdc\":\"myadtest\",\"kerberos-admin-principal\":\"Administrator\",\"kerberos-admin-password\":\"$AD_ADMIN_PASSWORD\"},\"policy\":{}}"
create_platform AD_KRB_SELF '{"name":"t2 ad kerberos self","type":"kerberos","settings":{"kerberos-realm":"AD.EXAMPLE.ORG","kerberos-kdc":"myadtest"},"policy":{}}'
create_connection KRB_C "{\"name\":\"t2 ad kerberos\",\"parentIdentifier\":\"ROOT\",\"protocol\":\"pam-account\",
    \"parameters\":{\"username\":\"t2krb\",\"password\":\"T2-Krb-Start1!\"},\"attributes\":{\"pam-platform\":\"$AD_KRB_ADMIN\"}}"

rotate_and_verify "$KRB_C" "Samba Kerberos, Administrator" samba_kinit_accepts t2krb
use_platform "$KRB_C" "$AD_KRB_SELF"; rotate_and_verify "$KRB_C" "Samba Kerberos, account itself" samba_kinit_accepts t2krb

# ---------------------------------------------------------------- Kerberos salt
section "Kerberos: a renamed account keeps its former salt"

# Active Directory salts keys with the account name when the password is set:
# after a rename, until the next change, the KDC advertises the former name's
# salt (like a server's Administrator after promotion to domain controller)
podman exec myadtest samba-tool user create t2salt0 'T2-Salt-Start1!' --use-username-as-cn >/dev/null 2>&1
podman exec myadtest samba-tool user rename t2salt0 --samaccountname=t2salt --upn=t2salt@ad.example.org >/dev/null 2>&1
on_cleanup "podman exec myadtest samba-tool user delete t2salt"
SALT=$(printf 'T2-Salt-Start1!\n' | podman exec -i -e KRB5_CONFIG=/tmp/t2-ad-krb5.conf -e KRB5_TRACE=/dev/stderr mykdctest \
    kinit t2salt@AD.EXAMPLE.ORG 2>&1 | grep -oE 'salt "[^"]*"' | head -1)
check "precondition: the KDC advertises the former name's salt" 'salt "AD.EXAMPLE.ORGt2salt0"' "$SALT"

create_connection SALT_C "{\"name\":\"t2 salt\",\"parentIdentifier\":\"ROOT\",\"protocol\":\"pam-account\",
    \"parameters\":{\"username\":\"t2salt\",\"password\":\"T2-Salt-Start1!\"},\"attributes\":{\"pam-platform\":\"$AD_KRB_SELF\"}}"
rotate_and_verify "$SALT_C" "Renamed account changing its own password" samba_kinit_accepts t2salt 1

run_cleanup
