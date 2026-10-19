#!/bin/bash
# Start a Samba Active Directory domain controller to test AD password requests
# against (hostname "myadtest", LDAPS port 636, Kerberos KDC port 88 and
# kpasswd port 464, realm "AD.EXAMPLE.ORG",
# admin "CN=Administrator,CN=Users,DC=ad,DC=example,DC=org" / "AdAdm1n-Pass",
# test user "CN=adtest,CN=Users,DC=ad,DC=example,DC=org" / "P@ssw0rd-AD1")
podman run --rm -d \
--name myadtest \
--hostname myadtest \
--net myguacnet \
-e REALM=AD.EXAMPLE.ORG \
-e DOMAIN=ADEXAMPLE \
-e ADMINPASS=AdAdm1n-Pass \
docker.io/smblds/smblds:latest

# Waits until Samba answers LDAPS. The image's own ldapsearch is a wrapper
# that already passes a password file, so the real one is used, and Samba's
# certificate is self-signed.
wait_for_samba() {
    until podman exec -e LDAPTLS_REQCERT=never myadtest /usr/bin/ldapsearch -x -H ldaps://localhost \
        -D 'Administrator@ad.example.org' -w AdAdm1n-Pass -b DC=ad,DC=example,DC=org -s base >/dev/null 2>&1; do
        sleep 2
    done
}

wait_for_samba

# Samba accepts a user's previous password for an hour after a change; turn
# that off so tests show the old password is really rejected after rotation.
# The image only runs LDAP; also run the KDC, which serves kpasswd too
podman exec myadtest sed -i '/^\[global\]/a\    old password allowed period = 0' /etc/samba/smb.conf
podman exec myadtest sed -i 's/^\(\s*server services = ldap cldap\)$/\1 kdc/' /etc/samba/smb.conf
podman restart myadtest >/dev/null
wait_for_samba

# Test user, named "adtest" in its DN too
podman exec myadtest samba-tool user create adtest 'P@ssw0rd-AD1' --given-name=AD --surname=Test --use-username-as-cn

# Allow changing a password again right away, so accounts changing their own
# password can be rotated repeatedly
podman exec myadtest samba-tool domain passwordsettings set --min-pwd-age=0 >/dev/null

# Fingerprint to pin in the platform (the certificate is regenerated with the container)
podman exec myadtest cat /var/lib/samba/private/tls/cert.pem | openssl x509 -noout -fingerprint -sha256
