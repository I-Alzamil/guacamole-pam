#!/bin/bash
# Password policies: who may read and change them, rules refused when they
# cannot make a password, the default rules, a platform's policy and a
# connection's own, rotated passwords following them (checked on OpenLDAP
# too), what uses each, deletion refused while used, platforms importing a
# policy by name, and a policy gone missing stopping rotations.

LDAP_ADMIN_DN="cn=admin,dc=example,dc=org"; LDAP_ADMIN_PASSWORD="LdapAdm1n"
LDAP_FP=$(podman exec myldaptest cat /container/service/slapd/assets/certs/ldap.crt | cert_fingerprint)
POLICIES="$PAM/password-policies"

# create_policy VARIABLE JSON: creates it, sets VARIABLE to its id, and
# deletes it at cleanup, after what uses it (created later)
create_policy() {
    local id
    id=$(json_get "$(api POST "$POLICIES" "$ADMIN" "$2" | cut -d' ' -f2-)" "d.get('id')")
    [ -n "$id" ] && on_cleanup "api DELETE '$POLICIES/$id' \"\$ADMIN\""
    printf -v "$1" '%s' "$id"
    [ -n "$id" ] || fail "creating password policy for \$$1" "$(cat "$T2_TMP/body")"
}

# shape PASSWORD -> its length, and how many characters of each kind
shape() {
    python3 -I -c "
import sys,re
p=sys.argv[1]
print(len(p), len(re.findall('[a-z]',p)), len(re.findall('[A-Z]',p)), len(re.findall('[0-9]',p)),
      len(re.findall('[^a-zA-Z0-9]',p)))" "$1"
}

section "Setup"
LDAP_DN="uid=t28ldap,ou=people,dc=example,dc=org"
podman exec -i myldaptest ldapadd -x -H ldap://localhost -D "$LDAP_ADMIN_DN" -w "$LDAP_ADMIN_PASSWORD" >/dev/null 2>&1 <<LDIF
dn: $LDAP_DN
objectClass: inetOrgPerson
uid: t28ldap
cn: T28 LDAP
sn: Test
userPassword: T28-Ldap-Start1!
LDIF
on_cleanup "podman exec myldaptest ldapdelete -x -H ldap://localhost -D '$LDAP_ADMIN_DN' -w '$LDAP_ADMIN_PASSWORD' '$LDAP_DN'"
create_policy SHORT '{"name":"t28 mainframe","description":"8 letters and digits",
    "rules":{"length":8,"symbols":false,"minLowercase":0,"minUppercase":0,"startWithLetter":true}}'
create_policy OWN '{"name":"t28 digits and two symbols",
    "rules":{"length":16,"lowercase":false,"uppercase":false,"minDigits":8,"symbolSet":"#!","minSymbols":2,
    "excludeAmbiguous":false}}'
create_platform LDAPS "{\"name\":\"t28 ldaps\",\"type\":\"ldap\",\"settings\":{\"hostname\":\"myldaptest\",\"port\":\"636\",
    \"ldap-certificate-fingerprint\":\"$LDAP_FP\",\"ldap-admin-dn\":\"$LDAP_ADMIN_DN\",
    \"ldap-admin-password\":\"$LDAP_ADMIN_PASSWORD\"},\"policy\":{}}"
create_connection LDAP_C "{\"name\":\"t28 ldap\",\"parentIdentifier\":\"ROOT\",\"protocol\":\"pam-account\",
    \"parameters\":{\"username\":\"t28ldap\",\"password\":\"T28-Ldap-Start1!\"},
    \"attributes\":{\"pam-platform\":\"$LDAPS\",\"pam-ldap-dn\":\"$LDAP_DN\"}}"
create_user t28-user t28-user-pw
USER=$(token t28-user t28-user-pw)
check "setup: policies, platform, connection and account" yes "$([ -n "$SHORT$OWN$LDAPS$LDAP_C" ] \
    && [ "$(openldap_accepts "$LDAP_DN" 'T28-Ldap-Start1!')" = yes ] && echo yes)"

# ---------------------------------------------------------------- access
section "Who may read and change them"
check "a user gets their names only, for the connection editor" "t28 mainframe:None" \
    "$(api GET "$POLICIES" "$USER" | cut -d' ' -f2- | python3 -I -c "
import sys,json
print(' '.join('%s:%s' % (p['name'], p.get('rules')) for p in json.load(sys.stdin) if p['name']=='t28 mainframe'))")"
check "...cannot create one" 403 "$(status_of "$(api POST "$POLICIES" "$USER" '{"name":"t28 nope","rules":{}}')")"
check "...change one" 403 "$(status_of "$(api PUT "$POLICIES/$SHORT" "$USER" '{"name":"t28 mainframe","rules":{}}')")"
check "...delete one" 403 "$(status_of "$(api DELETE "$POLICIES/$OWN" "$USER")")"
check "...nor see examples" 403 "$(status_of "$(api POST "$POLICIES/examples" "$USER" '{}')")"
check "...nor the default's rules" 403 "$(status_of "$(api GET "$POLICIES/default" "$USER")")"
check "an administrator sees the default's rules: 24 characters of every kind, the safe symbols" \
    "24 True1 True1 True1 True1 -_=+.,:@ True False" \
    "$(json_get "$(api GET "$POLICIES/default" "$ADMIN" | cut -d' ' -f2-)" "' '.join(str(x) for x in [d['length'],
        str(d['lowercase'])+str(d['minLowercase']), str(d['uppercase'])+str(d['minUppercase']),
        str(d['digits'])+str(d['minDigits']), str(d['symbols'])+str(d['minSymbols']), d['symbolSet'],
        d['excludeAmbiguous'], d['startWithLetter']])")"

# ---------------------------------------------------------------- refused
section "Rules that cannot make a password, refused"
R=$(api POST "$POLICIES" "$ADMIN" '{"name":"t28 too many","rules":{"length":8,"minDigits":6,"minSymbols":3}}')
check "minimums beyond the length" "400 The minimums add up to 11 characters, more than the length of 8." \
    "$(status_of "$R") $(message_of "$R")"
R=$(api POST "$POLICIES" "$ADMIN" '{"name":"t28 nothing","rules":{"lowercase":false,"uppercase":false,"digits":false,"symbols":false}}')
check "no kind of character" "400 Allow at least one kind of character." "$(status_of "$R") $(message_of "$R")"
R=$(api POST "$POLICIES" "$ADMIN" '{"name":"t28 space","rules":{"symbolSet":"- "}}')
check_contains "a space among the symbols" "Symbols must be printable ASCII" "$(message_of "$R")"
R=$(api POST "$POLICIES" "$ADMIN" '{"name":"t28 mainframe","rules":{}}')
check "a name taken" "400 A password policy named \"t28 mainframe\" already exists." "$(status_of "$R") $(message_of "$R")"
check "...none of them created" "" "$(api GET "$POLICIES" "$ADMIN" | cut -d' ' -f2- | python3 -I -c "
import sys,json
print(' '.join(p['name'] for p in json.load(sys.stdin) if p['name'] in ('t28 too many','t28 nothing','t28 space')))")"
R=$(api POST "$POLICIES/examples" "$ADMIN" '{"length":8,"symbols":false,"minLowercase":0,"minUppercase":0,"startWithLetter":true}')
check "examples of rules, saved or not, with their strength" "3 46" \
    "$(json_get "${R#* }" "str(len(d['examples'])) + ' ' + str(d['bits'])")"

# ---------------------------------------------------------------- rotations
section "Rotated passwords follow the policy chosen"
rotate_and_verify "$LDAP_C" "no policy" openldap_accepts "$LDAP_DN" 1
PASSWORD=$(parameter "$LDAP_C" password)
check "...the default: 24 characters of every kind, the safe symbols, nothing ambiguous" "24 yes" \
    "$(shape "$PASSWORD" | cut -d' ' -f1) $([[ "$PASSWORD" =~ ^[a-km-zA-HJ-NP-Z2-9_=+.,:@-]+$ ]] \
    && [[ "$PASSWORD" =~ [a-z] && "$PASSWORD" =~ [A-Z] && "$PASSWORD" =~ [0-9] && "$PASSWORD" =~ [^a-zA-Z0-9] ]] && echo yes)"

api PUT "$PAM/platforms/$LDAPS" "$ADMIN" "$(curl -s "$PAM/platforms/$LDAPS?token=$ADMIN" | python3 -I -c "
import sys,json
p=json.load(sys.stdin); p['policy']['password-policy']=sys.argv[1]; print(json.dumps(p))" "$SHORT")" >/dev/null
check "the platform chooses a policy" "$SHORT" \
    "$(json_get "$(curl -s "$PAM/platforms/$LDAPS?token=$ADMIN")" "d['policy'].get('password-policy')")"
rotate_and_verify "$LDAP_C" "the platform's policy" openldap_accepts "$LDAP_DN" 2
PASSWORD=$(parameter "$LDAP_C" password)
check "...8 letters and digits, starting with a letter" "yes" \
    "$([[ "$PASSWORD" =~ ^[a-zA-Z][a-zA-Z0-9]{7}$ && "$PASSWORD" =~ [0-9] ]] && echo yes)"

edit_connection "$ADMIN" "$LDAP_C" '' "{\"pam-password-policy\":\"$OWN\"}" >/dev/null
rotate_and_verify "$LDAP_C" "the connection's own policy" openldap_accepts "$LDAP_DN" 2
PASSWORD=$(parameter "$LDAP_C" password)
check "...in place of the platform's: 16 digits and # or !, at least 8 and 2" "yes" \
    "$([[ "$PASSWORD" =~ ^[0-9#!]{16}$ ]] && python3 -I -c "
import sys; p=sys.argv[1]; sys.exit(0 if sum(c.isdigit() for c in p) >= 8 and sum(c in '#!' for c in p) >= 2 else 1)" \
    "$PASSWORD" && echo yes)"

api PUT "$POLICIES/$OWN" "$ADMIN" '{"name":"t28 digits and two symbols","rules":{"length":10,"lowercase":false,
    "uppercase":false,"minDigits":8,"symbolSet":"#!","minSymbols":2,"excludeAmbiguous":false}}' >/dev/null
rotate "$LDAP_C" >/dev/null
check "a policy changed applies to the next rotation" 10 "$(shape "$(parameter "$LDAP_C" password)" | cut -d' ' -f1)"

# ---------------------------------------------------------------- what uses them
section "What uses each, and deleting"
check "listed by name, with what uses each" "t28 digits and two symbols=[]/[t28 ldap] t28 mainframe=[t28 ldaps]/[]" \
    "$(api GET "$POLICIES" "$ADMIN" | cut -d' ' -f2- | python3 -I -c "
import sys,json
print(' '.join('%s=[%s]/[%s]' % (p['name'], ','.join(p['platforms']), ','.join(p['connections']))
               for p in json.load(sys.stdin) if p['name'].startswith('t28')))")"
R=$(api DELETE "$POLICIES/$SHORT" "$ADMIN")
check "deleting one a platform uses: refused, naming it" \
    "400 This password policy is still used by platform \"t28 ldaps\"." "$(status_of "$R") $(message_of "$R")"
R=$(api DELETE "$POLICIES/$OWN" "$ADMIN")
check "...or a connection" "400 This password policy is still used by connection \"t28 ldap\"." \
    "$(status_of "$R") $(message_of "$R")"

R=$(api PUT "$PAM/platforms/$LDAPS" "$ADMIN" "$(curl -s "$PAM/platforms/$LDAPS?token=$ADMIN" | python3 -I -c "
import sys,json
p=json.load(sys.stdin); p['policy']['password-policy']='999999'; print(json.dumps(p))")")
check "a platform choosing no such policy: refused" "400 There is no password policy 999999." \
    "$(status_of "$R") $(message_of "$R")"

# A policy deleted by hand while chosen
sql "UPDATE guacamole_connection_attribute SET attribute_value = '999999'
    WHERE connection_id = $LDAP_C AND attribute_name = 'pam-password-policy'" >/dev/null
BEFORE=$(parameter "$LDAP_C" password)
check_contains "a policy gone missing: rotation stops, saying so" \
    "Password policy 999999 no longer exists: choose another." "$(rotate "$LDAP_C")"
check "...before anything changed" "$BEFORE yes" "$(parameter "$LDAP_C" password) $(openldap_accepts "$LDAP_DN" "$BEFORE")"
edit_connection "$ADMIN" "$LDAP_C" '' '{"pam-password-policy":null}' >/dev/null

# ---------------------------------------------------------------- import
section "Platforms imported naming their policy"
R=$(api POST "$PAM/platforms/import" "$ADMIN" "{\"platforms\":[{\"name\":\"t28 imported\",\"type\":\"ssh\",
    \"settings\":{\"script\":\"passwd\\n@expect assword\\n<NEWPASS>\\n\"},\"policy\":{\"password-policy\":\"t28 mainframe\"}}]}")
IMPORTED=$(platform_id "t28 imported")
[ -n "$IMPORTED" ] && on_cleanup "api DELETE '$PAM/platforms/$IMPORTED' \"\$ADMIN\""
check "a policy named, as exports name it: stored by its identifier" "$SHORT" \
    "$(json_get "$(curl -s "$PAM/platforms/$IMPORTED?token=$ADMIN")" "d['policy'].get('password-policy')")"
R=$(api POST "$PAM/platforms/import" "$ADMIN" '{"platforms":[{"name":"t28 imported 2","type":"ssh",
    "settings":{"script":"passwd\n@expect assword\n<NEWPASS>\n"},"policy":{"password-policy":"t28 no such policy"}}]}')
check "...an unknown one: refused" "False There is no password policy \"t28 no such policy\"." \
    "$(json_get "${R#* }" "str(d['imported']) + ' ' + d['results'][0]['message']")"

# A name that is another policy's identifier is still a name
create_policy NUMBERED "{\"name\":\"$OWN\",\"rules\":{}}"
api POST "$PAM/platforms/import" "$ADMIN" "{\"platforms\":[{\"name\":\"t28 imported 3\",\"type\":\"ssh\",
    \"settings\":{\"script\":\"passwd\\n@expect assword\\n<NEWPASS>\\n\"},\"policy\":{\"password-policy\":\"$OWN\"}}]}" >/dev/null
IMPORTED3=$(platform_id "t28 imported 3")
[ -n "$IMPORTED3" ] && on_cleanup "api DELETE '$PAM/platforms/$IMPORTED3' \"\$ADMIN\""
check "...a policy named as another's identifier: the one of that name" "$NUMBERED" \
    "$(json_get "$(curl -s "$PAM/platforms/$IMPORTED3?token=$ADMIN")" "d['policy'].get('password-policy')")"

# Back to no policy, so cleanup can delete them
api PUT "$PAM/platforms/$LDAPS" "$ADMIN" "$(curl -s "$PAM/platforms/$LDAPS?token=$ADMIN" | python3 -I -c "
import sys,json
p=json.load(sys.stdin); p['policy'].pop('password-policy', None); print(json.dumps(p))")" >/dev/null
