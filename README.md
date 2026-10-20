# guacamole-pam

Privileged access management for [Apache Guacamole](https://guacamole.apache.org/) 1.6.

- **Password rotation.** Each connection's password is either just stored, or
  managed by a *platform*. A platform describes how passwords are changed: over
  SSH with a send/expect script, over LDAP / Active Directory, over Kerberos
  (kpasswd, for MIT Kerberos, Heimdal and Active Directory realms), or over
  WinRM (local Windows accounts). It also sets
  when they're changed: never, after each use, or periodically. The new password
  is only stored once the target accepts it.
- **Accounts.** An "Account" connection type holds a password that users check
  out for a limited time instead of opening a session. Use it for web consoles,
  service accounts and anything else Guacamole can't connect to.
- **Access requests.** Users must request access to a connection, or an
  Account's password, giving a reason. They get a time-limited checkout, and
  their sessions are closed when it ends. Connections can require approval by
  one or more distinct approvers. A connection can also let the holder see its
  password, which is then rotated once they're done.
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

Do the same after upgrading from a version without the `pam_session` table.
Until then the extension keeps working on a single server, and logs a warning
that servers sharing the database can't see each other's sessions.

### Several Guacamole servers

Any number of Guacamole servers may share the database, whether as a
standby or all active behind a load balancer (with sticky sessions, as
Guacamole itself needs). Nothing needs configuring:

- **Rotations are claimed in the database**, so only one server rotates a
  connection at a time. A checkout is refused while any server rotates its
  password.
- **Open sessions are recorded in the database** (`pam_session`), so
  after-use and periodic rotations wait for sessions on every server. A server
  that stops without closing its sessions leaves records that are ignored
  after 3 minutes, then removed, and the connections are rotated after use.
- **When a checkout ends**, by release, revocation or expiry, the server
  ending it closes the holder's sessions at once. Other servers close theirs
  within 15 seconds.

With encrypted secrets, every server needs the same keys.

### Encrypting stored secrets

The secrets the extension stores can be encrypted (AES-256-GCM) with a key
that is never stored in the database:

- platform secrets, such as an LDAP, Kerberos or WinRM administrator's
  password;
- every connection's passwords, private keys and passphrases (`password`,
  `passphrase`, `private-key`, `gateway-password`, `sftp-password`,
  `sftp-passphrase`, `sftp-private-key` and Kubernetes' `client-key`),
  Accounts' passwords included;
- passwords kept from rotations that could not be confirmed.

A connection's secrets are kept apart, in `pam_connection_secret`, each
encrypted for its field and connection only. The field then holds a token
naming both, such as `${PAM_PASSWORD_17}` or `${PAM_PRIVATE_KEY_17}`, which
the extension replaces with the value when the connection opens, as
Guacamole's vault extensions do. Balancing groups are given the values of all
their connections, as Guacamole chooses which one to open. Editors of the
connection only see the tokens: saving them unchanged keeps the values, and
typing a new value replaces it. A token can't be used in any other field or
connection, where Guacamole would replace it too, and encrypted values can't
be pasted into a connection.

Values containing one of Guacamole's own tokens, such as `${GUAC_PASSWORD}`
to pass the user's own password on, stay in their field for Guacamole to
replace.

Accounts' passwords never reach Guacamole's connections, but are kept the same
way, so every connection shows its password as a token. If the database user
can't create `pam_connection_secret`, Accounts' passwords are encrypted in
their field instead (`pam:v1:…`), and other connections' secrets stay
unencrypted.

Generate a key once with `openssl rand -base64 32` and set it in
`guacamole.properties` (or `PAM_ENCRYPTION_KEY` in the Docker image), then
restart Guacamole:

```
pam-encryption-key: <the key>
```

Existing secrets are encrypted shortly after the start, and new ones as
they're saved. Without a key, secrets are stored unencrypted, as in earlier
versions.

**Back up the key.** Without it, encrypted secrets can't be recovered. For
Accounts whose password is rotated, the extension is the only holder of the
password, so losing the key means resetting those accounts by other means.

- **Changing the key.** Set the new key, and list the earlier one under
  `pam-encryption-old-keys` (`PAM_ENCRYPTION_OLD_KEYS`; several are separated
  by commas). Secrets are encrypted again with the new key shortly after the
  start; once the log no longer reports secrets under the old key, remove it.
- **Before removing the key, or the extension, or installing an earlier
  version**, set `pam-encryption-decrypt: true` (`PAM_ENCRYPTION_DECRYPT`) with
  the key and restart: every secret is decrypted, and connections' secrets
  go back into their fields. Then remove both settings. Without this,
  connections would send their tokens, such as `${PAM_PASSWORD_17}`, as
  their password.
- **If the key is missing or wrong**, the extension still loads and access
  rules still apply. Unencrypted secrets keep working, and what needs an
  encrypted secret fails, saying which key it needs: opening a connection,
  checking out an Account, or rotating (before trying the target with a wrong
  password). The log says the same at start.

#### Reading an encrypted secret

To read a value by hand, such as a password kept in
`pam_rotation_state.pending_password` after a rotation that couldn't be
confirmed, decrypt it with the extension's jar. The key is passed in the
environment and the value on input, so neither appears in the process list:

```sh
psql -tAc "SELECT pending_password FROM pam_rotation_state WHERE connection_id = 42" \
  | PAM_ENCRYPTION_KEY=<the key> java -cp guacamole-pam-1.6.0.jar \
      org.apache.guacamole.pam.crypto.SecretCipher pending-password
```

The last argument is the kind of value: `pending-password`,
`connection-password` (an Account's password encrypted in its field),
`connection-secret:<connection id>:<field>` (from `pam_connection_secret`,
such as `connection-secret:17:private-key`) or `platform-secrets`.

## After installing

- **Every connection requires a request by default**, including connections
  that already existed. To keep a connection usable as before, tick **Allow
  access without a request** in its *Access requests* section.
- **Administrators skip approvals, but still give a reason** when a connection
  or Account requires a request, so their access is in the history like
  anyone else's. To let administrators connect and check out Accounts without
  any request instead (logged), set this in `guacamole.properties` (or the
  `PAM_ADMIN_BYPASS_REQUESTS` environment variable in the Docker image):

  ```
  pam-admin-bypass-requests: true
  ```
- Only administrators can change a connection's *Password management* and
  *Access requests* sections, platforms, or who may approve, nor the
  username, hostname or port of a connection whose password is managed (they
  decide whose password its platform rotates, and where). Other users who may
  create or edit connections can still change everything else.
- **Holders don't see a connection's password**, only a Connect button, so
  they can't use it outside Guacamole. To let them see it, tick **Let users
  holding access see the password** in the connection's *Access requests*
  section (off by default; Accounts always show theirs). The holder then gets
  a **Show password** button, in the request dialog and in the menu within
  the session (Ctrl+Alt+Shift), under the clipboard; each time they use it is
  recorded in the checkout history. If the password is managed, it is
  rotated once the connection is no longer in use, whatever its rotation
  mode, and retried every 15 minutes if that fails. If it isn't managed, it
  keeps working outside Guacamole, without approvals, time limits or session
  recording. Connections allowing access without a request have no
  checkout, so their password is never shown.
- Balancing connection groups refuse to connect when one of their
  connections requires a request, is an Account, or has its password
  managed: open those connections directly.
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
  in the database unless a key is set (see
  [Encrypting stored secrets](#encrypting-stored-secrets)), like
  connections' passwords and keys, so set one, or protect database access
  accordingly.
- **Editors can read passwords, unless a key is set.** Users with *edit*
  permission on a connection can read its parameters, including its password.
  With a key set, they see passwords and keys only as tokens. They can still change a connection's other
  parameters, and some protocols have parameters that could send the
  password elsewhere (such as its hostname, or a VNC repeater, unless the
  connection is managed), so give edit permission on sensitive connections
  and Accounts to administrators only.
- **A Guacamole 1.6 issue can end sessions.** Guacamole remembers the first
  request whose error it handles, and ends that request's session whenever a
  later request is refused as unauthorized, from anyone. The extension's own
  pages never send requests without a session, so they don't trigger it.
- **SSH hosts are pinned.** The host key is trusted on first contact and
  required from then on, like SSH's `known_hosts`. If a host's key changes on
  purpose, paste the new fingerprint (shown in the error) into the connection's
  **Trusted SSH host key** field.
- **LDAP must be encrypted with a rotation account.** LDAP platforms with a
  rotation account require LDAPS or StartTLS. Pin the server certificate's
  fingerprint, or use a certificate the JVM trusts that matches the hostname.
- **Kerberos needs no certificate.** Kerberos itself proves both the KDC and
  the password change server genuine, from the password's key. Only the KDC
  (port 88, TCP) and kpasswd (port 464, TCP) need to be reachable. Without an
  admin principal, each principal changes its own password, which needs its
  current one.
- **WinRM needs HTTPS, and pins each host's certificate.** WinRM platforms
  connect to port 5986 only, and log in with NTLM bound to the TLS channel, so
  they work whatever the host's `CbtHardeningLevel` (`Strict` recommended).
  Like SSH host keys, the certificate is trusted on first contact and required
  from then on; pin it in the connection's **Trusted certificate** field to
  skip that first contact. Passwords are sent on PowerShell's input, never on a
  command line. Without an administrator on the platform, each account sets its
  own password, so it must be a local administrator. Only local accounts are
  supported: manage domain accounts with an LDAP or Kerberos platform.

## Development

The scripts at the top of the repository run a test setup with podman, on a
network named `myguacnet`. They're meant for development only: they use fixed
test passwords.

| Script | What it does |
|---|---|
| `reset.sh` | Recreates the Guacamole database from `podman/init/initdb.sql` (Guacamole's schema, with `guacadmin` / `guacadmin`) |
| `build.sh` | Builds the jar and (re)starts PostgreSQL, guacd and Guacamole with the extension, on http://localhost:8080. Stored secrets are encrypted with a fixed test key; run `PAM_ENCRYPTION_KEY= ./build.sh` to store them unencrypted |
| `startssh.sh` | SSH server `mysshtest` on port 22, user `mysshtest` / `P@ssw0rd` |
| `startldap.sh` | OpenLDAP server `myldaptest`, test user `uid=ldaptest,ou=people,dc=example,dc=org` |
| `startad.sh` | Samba Active Directory `myadtest` (LDAPS and Kerberos), test user `CN=adtest,CN=Users,DC=ad,DC=example,DC=org`. Prints the certificate fingerprint to pin |
| `startkdc.sh` | MIT Kerberos KDC `mykdctest`, realm `EXAMPLE.ORG`, admin `admin/admin`, test user `kdctest` |
| `startguac2.sh` | A second Guacamole server sharing the database, on http://localhost:8081, for the two-server tests. Stopped by `build.sh`: start it again after a build |
| `seed.sh` | Adds the test platforms, connections, users and group to a fresh database, through the REST API |
| `stop.sh` | Stops all of the above |

Tests are described in [tests/README.md](tests/README.md): unit tests run
with every build, and `tests/run.sh` runs the live suites against this setup.

Recreating the SSH, LDAP, AD or KDC containers generates new host keys and
certificates, and resets their passwords. Pin the new fingerprints and reset the
stored passwords afterwards.
