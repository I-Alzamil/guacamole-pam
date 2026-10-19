#!/bin/bash
# Start an MIT Kerberos KDC to test Kerberos password rotation against
# (hostname "mykdctest", KDC port 88, kpasswd port 464, realm "EXAMPLE.ORG",
#  admin "admin/admin" / "KdcAdm1n-Pass", test user "kdctest" / "P@ssw0rd-KDC1")
# The packages are installed when the container starts, which takes a minute.
podman run --rm -d \
--name mykdctest \
--hostname mykdctest \
--net myguacnet \
docker.io/library/debian:bookworm-slim \
bash -c '
set -e
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq krb5-kdc krb5-admin-server >/dev/null
cat > /etc/krb5.conf <<CONF
[libdefaults]
    default_realm = EXAMPLE.ORG
[realms]
    EXAMPLE.ORG = {
        kdc = mykdctest
        admin_server = mykdctest
    }
CONF
echo "admin/admin@EXAMPLE.ORG *" > /etc/krb5kdc/kadm5.acl
kdb5_util create -s -r EXAMPLE.ORG -P KdcMaster-Pass >/dev/null
kadmin.local -q "addprinc -pw KdcAdm1n-Pass admin/admin" >/dev/null
kadmin.local -q "addprinc -pw P@ssw0rd-KDC1 kdctest" >/dev/null
krb5kdc
touch /tmp/ready
exec kadmind -nofork
'

# Wait for the KDC and kadmind (which serves kpasswd)
until podman exec mykdctest test -f /tmp/ready 2>/dev/null; do sleep 2; done
