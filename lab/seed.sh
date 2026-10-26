#!/bin/bash
# Fill a fresh database with the test platforms, connections, users and group,
# through the REST API of the running Guacamole (start it and the test
# servers with "lab.sh app services" first). Run by "lab.sh seed".
# Anything that already exists (by name) is left as it is.
#
#   Users (password = name + "pass"):
#     bob, dave   may request every connection
#     carol       approver of every connection
#     dave        also member of group "pam-approvers", approver of every connection
#   Platforms:
#     MYTEST_LDAP (myldaptest), MYTEST_AD (myadtest); certificates are pinned
#     from the running containers
#     MYTEST_KERBEROS (MIT KDC mykdctest, realm EXAMPLE.ORG)
#     MYTEST_TACACS (tac_plus-ng mytacacstest)
#     MYTEST_POSTGRESQL, MYTEST_MYSQL, MYTEST_MARIADB, MYTEST_SQLSERVER (the
#     test databases, as their administrators, trusting the test CA)
#   Connections:
#     PAM test (Linux)  ssh to mysshtest, rotated by "Unix", no request needed
#     LDAP: ldaptest    account on MYTEST_LDAP
#     AD: adtest        account on MYTEST_AD
#     Kerberos: kdctest account on MYTEST_KERBEROS
#     TACACS+: tactest  account on MYTEST_TACACS
#     PostgreSQL: dbtest, MySQL: dbtest, MariaDB: dbtest, SQL Server: dbtest
#                       accounts on the test databases
#     Vendor portal     stored-only account, 2 approvals
#     test              stored-only account, 1 approval

# Guacamole's data source of the test database (PAM_DATA_SOURCE)
source "$(dirname "$0")/database.sh"

# SHA-256 fingerprint of a certificate file inside a container, or empty
fingerprint() {
    podman exec "$1" cat "$2" 2>/dev/null | openssl x509 -noout -fingerprint -sha256 2>/dev/null | cut -d= -f2
}

export LDAP_FP=$(fingerprint myldaptest /container/service/slapd/assets/certs/ldap.crt)
export AD_FP=$(fingerprint myadtest /var/lib/samba/private/tls/cert.pem)
[ -z "$LDAP_FP" ] && echo "warning: myldaptest is not running, MYTEST_LDAP gets no pinned certificate"
[ -z "$AD_FP" ] && echo "warning: myadtest is not running, MYTEST_AD gets no pinned certificate"
# mysshtest's host key, pinned on its connection: SSH platforms trust no key
# on first contact by default
export SSH_HOST_KEY=$(podman exec mysshtest ssh-keygen -lf /config/ssh_host_keys/ssh_host_ed25519_key.pub \
    2>/dev/null | awk '{print $2}')
export DB_CA="$(cat "$(dirname "$0")/targets/certs/ca.crt" 2>/dev/null)"
[ -z "$DB_CA" ] && echo "warning: no test CA yet (lab.sh services): the database platforms trust Java's CAs only"

python3 -I - <<'PY'
import json, os, sys, time, urllib.error, urllib.parse, urllib.request

B = "http://localhost:8080/api"

def call(method, path, body=None, token=None, form=None):
    url = B + path + ("" if token is None else ("&" if "?" in path else "?") + "token=" + token)
    data, headers = None, {}
    if form is not None:
        data = urllib.parse.urlencode(form).encode()
    elif body is not None:
        data, headers = json.dumps(body).encode(), {"Content-Type": "application/json"}
    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req) as r:
            text = r.read().decode()
            return json.loads(text) if text else None
    except urllib.error.HTTPError as e:
        sys.exit(f"{method} {path} failed ({e.code}): {e.read().decode()}")

# Wait for Guacamole
for _ in range(60):
    try:
        urllib.request.urlopen(B + "/languages")
        break
    except Exception:
        time.sleep(3)
else:
    sys.exit("Guacamole does not answer on " + B)

T = call("POST", "/tokens", form={"username": "guacadmin", "password": "guacadmin"})["authToken"]
D, E = "/session/data/" + os.environ.get("PAM_DATA_SOURCE", "postgresql"), "/session/ext/pam"

# Platforms
platforms = {p["name"]: p["id"] for p in call("GET", E + "/platforms", token=T)}
for p in [
    {"name": "MYTEST_LDAP", "description": "OpenLDAP test server", "type": "ldap",
     "settings": {"hostname": "myldaptest", "ldap-certificate-fingerprint": os.environ["LDAP_FP"],
                  "ldap-admin-dn": "cn=admin,dc=example,dc=org", "ldap-admin-password": "LdapAdm1n"},
     "policy": {"rotation-mode": "never"}},
    {"name": "MYTEST_AD", "description": "Samba AD test domain ad.example.org", "type": "ldap",
     "settings": {"hostname": "myadtest", "ldap-directory-type": "active-directory",
                  "ldap-certificate-fingerprint": os.environ["AD_FP"],
                  "ldap-admin-dn": "CN=Administrator,CN=Users,DC=ad,DC=example,DC=org",
                  "ldap-admin-password": "AdAdm1n-Pass"},
     "policy": {"rotation-mode": "after-use"}},
    {"name": "MYTEST_KERBEROS", "description": "MIT Kerberos test realm EXAMPLE.ORG", "type": "kerberos",
     "settings": {"kerberos-realm": "EXAMPLE.ORG", "kerberos-kdc": "mykdctest",
                  "kerberos-admin-principal": "admin/admin", "kerberos-admin-password": "KdcAdm1n-Pass"},
     "policy": {"rotation-mode": "after-use"}},
    {"name": "MYTEST_TACACS", "description": "tac_plus-ng test server", "type": "tacacs",
     "settings": {"tacacs-server": "mytacacstest", "tacacs-secret": "TacacsSecr3t"},
     "policy": {"rotation-mode": "after-use"}},
] + [
    {"name": "MYTEST_" + name.upper(), "description": label + " test database " + host,
     "type": "database",
     "settings": {"database-type": kind, "database-hostname": host, "database-ca-certificates": os.environ["DB_CA"],
                  "database-admin-username": admin, "database-admin-password": password},
     "policy": {"rotation-mode": "after-use"}}
    for name, label, kind, host, admin, password in [
        ("postgresql", "PostgreSQL", "postgresql", "mypgtarget", "postgres", "PgAdm1n-Pass"),
        ("mysql", "MySQL", "mysql", "mymysqltarget", "root", "MyAdm1n-Pass"),
        ("mariadb", "MariaDB", "mysql", "mymariadbtarget", "root", "MariaAdm1n-Pass"),
        ("sqlserver", "SQL Server", "sqlserver", "mymssqltarget", "sa", "SqlAdm1n-Pass!"),
    ]
]:
    if p["name"] in platforms:
        print("platform exists:", p["name"])
        continue
    platforms[p["name"]] = call("POST", E + "/platforms", p, T)["id"]
    print("platform created:", p["name"])

# Connections
existing = {c["name"]: c["identifier"] for c in call("GET", D + "/connections", token=T).values()}
connections = {}
for c in [
    {"name": "PAM test (Linux)", "protocol": "ssh",
     "parameters": {"hostname": "mysshtest", "port": "22", "username": "mysshtest", "password": "P@ssw0rd"},
     "attributes": {"pam-platform": str(platforms["Unix"]), "pam-ssh-host-key": os.environ["SSH_HOST_KEY"],
                    "pam-request-exempt": "true", "pam-approvals-required": "0"}},
    {"name": "LDAP: ldaptest", "protocol": "pam-account",
     "parameters": {"username": "ldaptest", "password": "P@ssw0rd"},
     "attributes": {"pam-platform": str(platforms["MYTEST_LDAP"]),
                    "pam-ldap-dn": "uid=ldaptest,ou=people,dc=example,dc=org", "pam-checkout-duration": "30"}},
    {"name": "AD: adtest", "protocol": "pam-account",
     "parameters": {"username": "adtest", "password": "P@ssw0rd-AD1"},
     "attributes": {"pam-platform": str(platforms["MYTEST_AD"]),
                    "pam-ldap-dn": "CN=adtest,CN=Users,DC=ad,DC=example,DC=org", "pam-checkout-duration": "30"}},
    {"name": "Kerberos: kdctest", "protocol": "pam-account",
     "parameters": {"username": "kdctest", "password": "P@ssw0rd-KDC1"},
     "attributes": {"pam-platform": str(platforms["MYTEST_KERBEROS"]), "pam-checkout-duration": "30"}},
    {"name": "TACACS+: tactest", "protocol": "pam-account",
     "parameters": {"username": "tactest", "password": "P@ssw0rd-Tac1"},
     "attributes": {"pam-platform": str(platforms["MYTEST_TACACS"]), "pam-checkout-duration": "30"}},
] + [
    {"name": label + ": dbtest", "protocol": "pam-account",
     "parameters": {"username": "dbtest", "password": "P@ssw0rd-Db1", "account-url": url},
     "attributes": {"pam-platform": str(platforms["MYTEST_" + name.upper()]), "pam-checkout-duration": "30"}}
    for name, label, url in [
        ("postgresql", "PostgreSQL", "mypgtarget:5432"),
        ("mysql", "MySQL", "mymysqltarget:3306"),
        ("mariadb", "MariaDB", "mymariadbtarget:3306"),
        ("sqlserver", "SQL Server", "mymssqltarget:1433"),
    ]
] + [
    {"name": "Vendor portal", "protocol": "pam-account",
     "parameters": {"username": "svc-vendor", "password": "Vend0r-Pass!",
                    "account-url": "https://vendor.example.com/login",
                    "account-notes": "Shared support login.\nMFA codes: ask the service desk."},
     "attributes": {"pam-checkout-duration": "30", "pam-approvals-required": "2"}},
    {"name": "test", "protocol": "pam-account",
     "parameters": {"username": "test", "password": "Test-Pass1"},
     "attributes": {"pam-approvals-required": "1"}},
]:
    if c["name"] in existing:
        connections[c["name"]] = existing[c["name"]]
        print("connection exists:", c["name"])
        continue
    c["parentIdentifier"] = "ROOT"
    connections[c["name"]] = call("POST", D + "/connections", c, T)["identifier"]
    print("connection created:", c["name"])

ids = json.dumps(sorted(connections.values(), key=int))

# Users
users = call("GET", D + "/users", token=T)
for name, approver in [("bob", False), ("carol", True), ("dave", False)]:
    if name in users:
        print("user exists:", name)
        continue
    attributes = {"pam-approver": "true", "pam-approver-connections": ids} if approver else {}
    call("POST", D + "/users", {"username": name, "password": name + "pass", "attributes": attributes}, T)
    print("user created:", name)

# Requesters
for name in ("bob", "dave"):
    call("PATCH", f"{D}/users/{name}/permissions",
         [{"op": "add", "path": f"/connectionPermissions/{i}", "value": "READ"} for i in connections.values()], T)

# Approver group
if "pam-approvers" in call("GET", D + "/userGroups", token=T):
    print("group exists: pam-approvers")
else:
    call("POST", D + "/userGroups", {"identifier": "pam-approvers",
         "attributes": {"pam-approver": "true", "pam-approver-connections": ids}}, T)
    call("PATCH", D + "/userGroups/pam-approvers/memberUsers", [{"op": "add", "path": "/", "value": "dave"}], T)
    print("group created: pam-approvers (member dave)")

print("done")
PY
