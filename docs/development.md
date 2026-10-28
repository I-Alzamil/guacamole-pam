# Development

`build.sh` builds the jar. `check-dependencies.sh` checks the libraries it
bundles against [osv.dev](https://osv.dev)'s known vulnerabilities, sending
their names and versions only, and fails if one is affected; CI runs it on
every push and weekly, and Dependabot proposes library updates. `lab/lab.sh` runs a test lab with podman, on a
network named `myguacnet`, for development only: it uses fixed test
passwords. Its commands run in the order given:

| Command | What it does |
|---|---|
| `lab/lab.sh app` | (Re)starts Guacamole's database, guacd and Guacamole with the built jar, on http://localhost:8080. Run it again after each build. Stored secrets are encrypted with a fixed test key; set `PAM_ENCRYPTION_KEY=` to store them unencrypted |
| `lab/lab.sh app --ha` | Also a second Guacamole sharing the database and guacd, on http://localhost:8081, with the [HA module](high-availability.md#high-availability-the-ha-module) on in both, for the two-server tests (`--ha` alone restarts both servers that way, keeping the database and guacd running) |
| `lab/lab.sh app --ha=off` | The same two servers with the HA module off: the second, started once the first answers, stays on standby (alone, likewise restarts both) |
| `lab/lab.sh services` | The servers whose accounts the lab manages, keeping those already running: SSH `mysshtest` (user `mysshtest`; its ECDSA host key has a certificate of a test SSH CA, `lab/targets/certs/ssh_ca.pub`), OpenLDAP `myldaptest` (`uid=ldaptest,ou=people,dc=example,dc=org`), Samba AD `myadtest` (LDAPS and Kerberos, `CN=adtest,CN=Users,DC=ad,DC=example,DC=org`), MIT Kerberos `mykdctest` (realm `EXAMPLE.ORG`, `kdctest`), TACACS+ `mytacacstest` (tac_plus-ng, built from source into `localhost/pam-tacacs-test` the first time; `tactest`), and databases over TLS with certificates of a test CA generated into `lab/targets/certs`: PostgreSQL `mypgtarget`, MySQL `mymysqltarget`, MariaDB `mymariadbtarget`, SQL Server `mymssqltarget` (`dbtest`); a syslog receiver `mysyslogtest` (TLS with a certificate of the same CA, TCP, UDP); and a mail server `mymailtest` (Mailpit, STARTTLS with a certificate of the same CA, login `pammail`). Passwords are listed at the top of `lab/lab.sh` |
| `lab/lab.sh seed` | Adds the test platforms, connections, users and group to a fresh database, through the REST API (`lab/seed.sh`) |
| `lab/lab.sh reset` | Recreates Guacamole's database, with only Guacamole's schema and `guacadmin` / `guacadmin` |
| `lab/lab.sh stop` | Stops every container of the lab |

For example, `./build.sh && lab/lab.sh reset app services seed` starts
afresh.

Guacamole's database is PostgreSQL unless `PAM_DB` says `mysql` (MySQL 8.4),
`mariadb` (MariaDB 11.4) or `sqlserver` (SQL Server 2022) when `lab.sh`
starts it, as `PAM_DB=sqlserver lab/lab.sh app`. Later commands and
the tests use whichever is running. Each keeps its own data (`lab/db` for
PostgreSQL, podman volumes for the others), created with Guacamole's schema
and `guacadmin` / `guacadmin` on first start (`lab/database.sh`).

`lab/ha.sh` runs the HA module's own lab, on a network named `mypamhanet`:
for each database given, two Guacamole servers sharing it with `pam-ha` on
(`lab/ha.sh start postgresql`, on ports 8090 and 8091; MySQL 8092 and 8093,
MariaDB 8094 and 8095, SQL Server 8096 and 8097), with the ban, TOTP and
history recording storage extensions, an SSH server and a guacd each.
`HA=off lab/ha.sh start ...` starts them with the module off, and
`lab/ha.sh stop` stops them.

Tests are described in [tests/README.md](../tests/README.md): unit tests run
with every build, `tests/run.sh` runs the live suites against this setup, and
`tests/ha/run.sh` the HA module's against `lab/ha.sh`.

Recreating the SSH, LDAP, AD or KDC containers generates new host keys and
certificates, and resets their passwords. Pin the new fingerprints and reset the
stored passwords afterwards.
