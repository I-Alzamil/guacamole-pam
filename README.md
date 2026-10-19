# guacamole-pam

Privileged access management for [Apache Guacamole](https://guacamole.apache.org/) 1.6.

- **Password rotation.** Each connection's password is either just stored, or
  managed by a *platform*. A platform describes how passwords are changed: over
  SSH with a send/expect script, or over LDAP / Active Directory. It also sets
  when they're changed: never, after each use, or periodically. The new password
  is only stored once the target accepts it.
- **Accounts.** An "Account" connection type holds a password that users check
  out for a limited time instead of opening a session. Use it for web consoles,
  service accounts and anything else Guacamole can't connect to.
- **Access requests.** Users must request access to a connection, or an
  Account's password, giving a reason. They get a time-limited checkout, and
  their sessions are closed when it ends. Connections can require approval by
  one or more distinct approvers.
- **Audit.** The checkout and approval histories are searchable and can be
  exported as CSV.

## Requirements

- Guacamole 1.6 with **PostgreSQL authentication** (`guacamole-auth-jdbc-postgresql`)
  installed and working. The extension manages the connections stored there,
  and reuses its `postgresql-*` settings and its JDBC driver. Nothing else needs
  configuring.
- Java 11 or later, as for Guacamole.

Without PostgreSQL authentication (for example with only LDAP, MySQL or
`user-mapping.xml`), the extension stays inactive. It logs one warning saying
why, and Guacamole works exactly as without it.

## Installation

1. Build the extension with `mvn package`, or use a released jar, then copy
   `guacamole-pam-1.6.0.jar` into `GUACAMOLE_HOME/extensions/`.
2. Restart Guacamole.

The first time the extension uses the database, it creates its tables (all
named `pam_*`) and adds two default SSH platforms, "Linux (passwd)" and
"Windows (net user)". Later starts find the tables and leave them alone.

### If Guacamole's database user may not create tables

Guacamole's installation guide grants its database user only
`SELECT, INSERT, UPDATE, DELETE` on the tables, and such a user can't create
the extension's tables. The log then explains this once, naming the user. Until
the tables exist, connections stored in the database can't be opened, because
their access can't be checked.

To fix it, create the tables once as the database owner and grant them to
Guacamole's user, as for Guacamole's own tables. No restart is needed.

```sh
unzip -p guacamole-pam-1.6.0.jar schema/postgresql.sql | psql -U <owner> -d <guacamole database>
```

```sql
GRANT SELECT,INSERT,UPDATE,DELETE ON ALL TABLES IN SCHEMA public TO guacamole_user;
GRANT SELECT,USAGE ON ALL SEQUENCES IN SCHEMA public TO guacamole_user;
```

## After installing

- **Every connection requires a request by default**, including connections
  that already existed. To keep a connection usable as before, tick **Allow
  access without a request** in its *Access requests* section. Administrators
  never need requests: they connect directly, and this is logged.
- Only administrators can change a connection's *Password management* and
  *Access requests* sections, platforms, or who may approve. Other users who
  may create or edit connections can still change everything else.
- Administrators get four new settings tabs: **Platforms**, **Password
  Rotation**, **Checkouts** and **Approvals**. Approvers who aren't
  administrators only get **Approvals**, for the connections their permission
  covers.
- Approvers see a yellow badge counting requests awaiting their decision.
  Administrators also see a red badge counting failed rotations. Each user can
  turn either off under **Preferences → Notification badges**.

### Who may approve

Tick **Can approve requests** in the Permissions section of a user or user
group. Then tick **Approve** next to the connections or connection groups they
may approve in the editor's connections list. A connection group covers every
connection in it, including ones added later. Set how many distinct approvers a
connection needs in its *Access requests* section.

## Security notes

- **Secrets stay on the server.** Platform secrets, such as an LDAP rotation
  account's password, are never sent to the browser. They're stored unencrypted
  in the database, like Guacamole's own connection passwords, so protect
  database access accordingly.
- **Editors can read passwords.** Users with *edit* permission on a connection
  can read its parameters, including an Account's password. Give edit
  permission on managed connections and Accounts to administrators only.
- **SSH hosts are pinned.** The host key is trusted on first contact and
  required from then on, like SSH's `known_hosts`. If a host's key changes on
  purpose, paste the new fingerprint (shown in the error) into the connection's
  **Trusted SSH host key** field.
- **LDAP must be encrypted with a rotation account.** LDAP platforms with a
  rotation account require LDAPS or StartTLS. Pin the server certificate's
  fingerprint, or use a certificate the JVM trusts that matches the hostname.

## Development

The scripts at the top of the repository run a test setup with podman, on a
network named `myguacnet`. They're meant for development only: they use fixed
test passwords.

| Script | What it does |
|---|---|
| `reset.sh` | Recreates the Guacamole database from `podman/init/initdb.sql` (Guacamole's schema, with `guacadmin` / `guacadmin`) |
| `build.sh` | Builds the jar and (re)starts PostgreSQL, guacd and Guacamole with the extension, on http://localhost:8080 |
| `startssh.sh` | SSH server `mysshtest` on port 22, user `mysshtest` / `P@ssw0rd` |
| `startldap.sh` | OpenLDAP server `myldaptest`, test user `uid=ldaptest,ou=people,dc=example,dc=org` |
| `startad.sh` | Samba Active Directory `myadtest`, test user `CN=adtest,CN=Users,DC=ad,DC=example,DC=org`. Prints the certificate fingerprint to pin |
| `stop.sh` | Stops all of the above |

Recreating the SSH, LDAP or AD containers generates new host keys and
certificates, and resets their passwords. Pin the new fingerprints and reset the
stored passwords afterwards.
