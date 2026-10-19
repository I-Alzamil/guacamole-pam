#!/bin/bash
# Start an OpenLDAP server to test LDAP password requests against
# (hostname "myldaptest", port 389 (StartTLS) and 636 (LDAPS) with a
#  self-signed certificate, base "dc=example,dc=org",
#  admin "cn=admin,dc=example,dc=org" / "LdapAdm1n", test user "uid=ldaptest")
podman run --rm -d \
--name myldaptest \
--hostname myldaptest \
--net myguacnet \
-e LDAP_ORGANISATION="Example" \
-e LDAP_DOMAIN="example.org" \
-e LDAP_ADMIN_PASSWORD=LdapAdm1n \
-e LDAP_TLS_VERIFY_CLIENT=never \
docker.io/osixia/openldap:1.5.0

# Wait for slapd, then add a test user
until podman exec myldaptest ldapsearch -x -H ldap://localhost -b dc=example,dc=org -D cn=admin,dc=example,dc=org -w LdapAdm1n -s base >/dev/null 2>&1; do sleep 1; done
podman exec -i myldaptest ldapadd -x -H ldap://localhost -D cn=admin,dc=example,dc=org -w LdapAdm1n <<'LDIF'
dn: ou=people,dc=example,dc=org
objectClass: organizationalUnit
ou: people

dn: uid=ldaptest,ou=people,dc=example,dc=org
objectClass: inetOrgPerson
uid: ldaptest
cn: LDAP Test
sn: Test
userPassword: P@ssw0rd
LDIF
