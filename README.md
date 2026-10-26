# guacamole-pam

[![Build](https://github.com/I-Alzamil/guacamole-pam/actions/workflows/build.yml/badge.svg)](https://github.com/I-Alzamil/guacamole-pam/actions/workflows/build.yml)

Privileged access management for [Apache Guacamole](https://guacamole.apache.org/) 1.6.

- **Password rotation.** Each connection's password is either just stored, or
  managed by a *platform*. A platform describes how passwords are changed: over
  SSH with a send/expect script, over LDAP (OpenLDAP, Active Directory and
  other directories), over Kerberos (kpasswd, for MIT Kerberos, Heimdal and
  Active Directory realms), over WinRM (local Windows accounts, HTTPS
  only), over TACACS+ (accounts a TACACS+ server holds itself, where it
  allows password changes), or as database accounts (PostgreSQL, MySQL,
  MariaDB and SQL Server, over their JDBC drivers): its *type*. It also sets
  when they're changed (never, after each use, or periodically), and the
  *password policy* new passwords follow. The new password is only stored once
  the target accepts it.
- **Accounts.** An "Account" connection type holds a password that users check
  out for a limited time instead of opening a session. Use it for web consoles,
  service accounts and anything else Guacamole can't connect to. Users see the
  account's username; LDAP platforms can also show them its DN (*Show the DN
  to requesters*, off by default).
- **Access requests.** Users must request access to a connection, or an
  Account's password, giving a reason. They get a time-limited checkout, and
  their sessions are closed when it ends. Connections can require approval by
  one or more distinct approvers. A connection can also let the holder see its
  password, which is then rotated once they're done.
- **Requests ahead of time.** Where approval is needed, users choose between
  access as soon as it's approved, or from a date and time they pick (up to
  30 days ahead, in their browser's time zone), so it can be approved in
  advance. Once approved, the connection is reserved for them from then for
  its time limit; they open it during that time to check out, without asking
  again. Reservations of a connection checked out by one user at a time never
  overlap: someone else's checkout ends when a reservation starts, and no one
  else can check it out during it. Approving one rejects the others awaiting
  approval for an overlapping time, with the reason shown to their
  requesters. A request ahead of time that is still
  awaiting approval expires once its time is over (others after 24 hours).
  Requesters can cancel an approved reservation they haven't used.
- **Extensions.** Holders can extend a checkout at any time, giving a reason,
  by the connection's extension length (its time limit unless set). Where the
  connection needs approval, an extension needs as many approvals as a
  request; it's granted at once otherwise. An extension still awaiting
  approval when the checkout ends expires. A checkout may be extended twice
  by default; requests can also ask for several time limits at once, up to
  one more than the extensions allowed, which uses those extensions up. On a
  connection held by one user at a time, an extension ends no later than
  someone else's next reservation. The checkout history shows how often each
  checkout was extended, and each extension's reason and approvers.
- **Audit.** The checkout and approval histories are searchable and can be
  exported as CSV. Times are stored as absolute times (in UTC where the
  database's type has no time zone), shown in the browser's time zone with
  its name (the UTC time on hover), and exported in ISO 8601 in that time
  zone with its offset from UTC, such as `2026-10-22T16:18:20.372+03:00`,
  which every reader and tool takes for the same moment. Every step records
  the address it came from: requests, each approval, denials and
  cancellations, checkouts, and their release or revocation. In both
  histories, click a user, an approver or who ended a checkout for when and
  from where they acted, or a scheduled request for its start and end.
  Every event can also go to a [syslog server](#syslog), over TLS.
- **High availability, if wanted.** Several Guacamole servers can share the
  database as one, active-active: the optional
  [HA module](#high-availability-the-ha-module) shares sessions, connection
  limits, Active Sessions, logins, share links, failed logins, TOTP codes and
  recordings between them. A single server leaves it off; without it, other
  servers on the database wait on standby, read-only for PAM, and take over
  once it stops.

## Requirements

- Guacamole 1.6 with one of its **database authentications** installed and
  working: PostgreSQL (`guacamole-auth-jdbc-postgresql`), MySQL or MariaDB
  (`guacamole-auth-jdbc-mysql`), or SQL Server (`guacamole-auth-jdbc-sqlserver`).
  The extension manages the connections stored there, and reuses its settings
  (`postgresql-*`, `mysql-*` or `sqlserver-*`, SSL settings included) and its
  JDBC driver. Nothing else needs configuring.
- Java 11 or later, as for Guacamole.

Supported databases: PostgreSQL 13 or later, MySQL 8.0 or later, MariaDB 10.6
or later, and SQL Server 2017 or later, with Microsoft's driver (the default
`sqlserver-driver`, `microsoft2005`). The extension connects as Guacamole's
own authentication does, with the same SSL mode, certificates and driver:
MySQL's `mysql-driver` choosing between the MySQL and MariaDB drivers is
followed too.

Two problems of Guacamole 1.6.0 itself, not of this extension, affect
these databases:

- **SQL Server**: Guacamole's SQL Server authentication doesn't start, as two
  of its MyBatis mappers aren't valid XML (`UserGroupPermissionMapper.xml`
  has `<test>` where `<otherwise>` belongs, and `ConnectionRecordMapper.xml`
  `<hen` for `<when`). It needs those two lines fixed in its jar
  (`lab/database.sh` shows how) until a Guacamole release fixes them.
- **MySQL and MariaDB**: Guacamole can't delete user groups (its statement
  lacks an `AND`), nor add a group to another (its statement calls a
  misspelled method).

If several database authentications are configured, set which one's
connections the extension manages in `guacamole.properties` (or
`PAM_DATABASE` in the Docker image):

```
pam-database: mysql
```

Without a database authentication (for example with only LDAP or
`user-mapping.xml`), the extension stays inactive. It logs one warning saying
why, and Guacamole works exactly as without it.

The extension has its own version (`1.0.0`, following semantic versioning),
and each build is made for one Guacamole release, 1.6.0 for now: Guacamole
skips extensions built for another release. To build for another release, set
`guacamole.version` in `pom.xml`.

## Installation

1. Build the extension with `mvn package`, or use a released jar, then copy
   `guacamole-pam-<version>.jar` into `GUACAMOLE_HOME/extensions/`.
2. Restart Guacamole.

The first time the extension uses the database, it creates its tables (all
named `pam_*`, from `schema/postgresql.sql`, `schema/mysql.sql` or
`schema/sqlserver.sql` in the jar) and adds three default SSH platforms,
"Unix", "macOS" and "Windows". Later starts find the tables and leave them
alone. On MySQL and SQL Server, the extension stores its times in UTC.

### If Guacamole's database user may not create tables

Guacamole's installation guide grants its database user only
`SELECT, INSERT, UPDATE, DELETE` on the tables (on SQL Server, the roles
`db_datareader` and `db_datawriter`), and such a user can't create the
extension's tables. The log then explains this once, naming the user and what
to run. Until the tables exist, connections stored in the database can't be
opened, because their access can't be checked.

To fix it, create the tables once as the database owner. No restart is needed.

- **PostgreSQL**: create them, then grant them to Guacamole's user, as for
  Guacamole's own tables:

  ```sh
  unzip -p guacamole-pam-<version>.jar schema/postgresql.sql | psql -U <owner> -d <guacamole database>
  ```

  ```sql
  GRANT SELECT,INSERT,UPDATE,DELETE ON ALL TABLES IN SCHEMA public TO guacamole_user;
  GRANT SELECT,USAGE ON ALL SEQUENCES IN SCHEMA public TO guacamole_user;
  ```
- **MySQL or MariaDB**: the grants of Guacamole's guide cover the whole
  database, so new tables need none:

  ```sh
  unzip -p guacamole-pam-<version>.jar schema/mysql.sql | mysql -u <owner> -p <guacamole database>
  ```
- **SQL Server**: the roles of Guacamole's guide cover new tables too:

  ```sh
  unzip -p guacamole-pam-<version>.jar schema/sqlserver.sql > pam.sql
  sqlcmd -S <server> -U <owner> -d <guacamole database> -i pam.sql
  ```

Tables created this way start without the three default platforms: add them
with **Restore defaults** on the **Platforms** tab.

Do the same after upgrading to a version that changes the tables: until then,
connections stored in the database can't be opened, as above.

### Several Guacamole servers

Without the [HA module](#high-availability-the-ha-module), PAM runs on one
Guacamole server at a time. The server working holds a database lock for as
long as it runs; any other server sharing the database finds it held and
stays **on standby**:

- PAM is **read-only** there: it lists connections, requests, checkouts and
  histories, but refuses checkouts, approvals, rotations, setting changes and
  sessions of managed connections, saying why. The **PAM Settings** tab says
  so too, and the server logs it once.
- It **takes over** within seconds of the other one stopping, even crashing:
  the database frees a lock once its server or connection is gone. Taking
  over, it removes the sessions the stopped server left recorded
  (`pam_session`), and rotates their connections after use.

So a standby server can wait behind a load balancer sending it nothing, or
an upgrade can start the new server before stopping the old one. To run
several servers at once, turn the HA module on in every server: one without
it, sharing the database with servers running it, stays on standby, and puts
them on standby if it was working first.

A single server needs nothing of this: it claims rotations and counts
sessions in memory, and reads the settings again only after changing them.

Each server keeps its own pool of up to 10 database connections, besides
Guacamole's own, plus one held for the lock and one for each rotation
running with the HA module. Change the limit with
`pam-database-max-connections` in `guacamole.properties`, keeping the total
across servers within the database's own limit (`max_connections` on
PostgreSQL and MySQL). The lock needs the database's own locks to reach the
server holding them: not through a connection pooler sharing database
sessions (PgBouncer in transaction mode), nor across the nodes of a Galera
cluster.

### High availability (the HA module)

The extension includes an HA module, off unless turned on, that makes
several Guacamole servers sharing one database work as one, so they can run
**active-active** behind a load balancer. Without it, Guacamole keeps much of
its state in memory, so each server only knows its own:

- **"Currently in use by N users"** only counts the sessions of the server
  showing it, and **connection limits** ("Maximum number of connections",
  "... per user", the absolute maximum) apply to each server alone.
- **Active Sessions** only lists, and can only end or join, the sessions of
  the server showing it.
- **Logins** only work on the server that made them: a request reaching
  another server is refused, and a user whose server fails must log in
  again.
- **Share links** only open on the server that made them.
- **Failed logins** (the ban extension) are counted on each server, so
  spreading attempts over the servers multiplies the attempts allowed.
- **TOTP codes** used on one server can be used once more on another.
- **Recordings** are only shown by the server whose guacd wrote them.

The HA module keeps all of that in the database, for every server, on
every database Guacamole's authentication supports, and lets PAM work on
every server at once:

- **Rotations are claimed in the database**, so only one server rotates a
  connection at a time. A checkout is refused while any server rotates its
  password.
- **Open sessions are counted from the database** (`pam_session`), so
  after-use and periodic rotations wait for sessions on every server. A server
  that stops without closing its sessions leaves records that are ignored
  after 45 seconds, then removed, and the connections are rotated after use.
- **When a checkout ends**, by release, revocation or expiry, the server
  ending it closes the holder's sessions at once. Other servers close theirs
  within 2 seconds.
- **Settings** (see [Settings](#settings)) changed on one server apply to the
  others within 5 seconds.

With encrypted secrets, every server needs the same keys. A single server
needs none of this: leave the module off, and it creates no tables, starts
no threads and shows no tab.

#### Turning it on

Set these in `guacamole.properties` on every server (in Docker, as
environment variables: `PAM_HA`, `PAM_HA_URL`, ...), and restart them:

| Property | Purpose |
|---|---|
| `pam-ha` | `true` turns the HA module on. Every server sharing the database needs it. |
| `pam-ha-url` | The URL other servers reach this one at, such as `http://10.0.0.11:8080/guacamole`. Other servers fetch this server's recordings from it, and the status tab shows it and checks it. |
| `pam-ha-secret` | A secret shared by all servers, required to fetch recordings from one another, and to check their URLs. Use a long random value. |
| `pam-ha-guacd-hostname` | The host name other servers reach this server's guacd at, when its connections use `localhost` (the default `guacd-hostname`). Without it, other servers cannot join or share sessions running on a local guacd. |

Only `pam-ha` is required; the module also follows Guacamole's own settings:
`api-session-timeout`, `guacd-hostname`/`-port`/`-ssl`, the ban extension's
`ban-max-invalid-attempts` and `ban-address-duration`, `totp-period`, and
`recording-search-path`. It also needs:

- Guacamole's **WebSocket tunnel**, or a load balancer keeping each HTTP
  tunnel on one server. A session's tunnel always lives on the server that
  opened it.
- For sessions to be joined and shared across servers: each server's guacd
  reachable from the other servers.
- For recordings: the history recording storage extension, and either a
  recording storage shared by all servers or `pam-ha-url` and
  `pam-ha-secret`.
- Behind a load balancer, the client's address passed to Guacamole
  (`X-Forwarded-For` with Tomcat's RemoteIpValve; in Docker,
  `REMOTE_IP_VALVE_ENABLED=true`). Otherwise every login seems to come from
  the load balancer, and failed logins ban it.

It creates its tables at startup if they are missing: `pam_ha_server`,
`_session`, `_lock`, `_share`, `_login`, `_ban`, `_totp` and `_recording`.
If the database user may not create tables, run the script for your database
once instead, from [src/main/resources/schema/ha](src/main/resources/schema/ha).
Until the tables exist, the module logs why and shares nothing, trying again
every minute. With several database authentications configured, the
sessions of each are shared on their own, and logins, failed logins, TOTP
codes and recordings through the first one (PostgreSQL, then MySQL or
MariaDB, then SQL Server).

#### What it shares

- **Sessions.** Each is recorded when it opens, with where it runs (its
  guacd, and its connection there), and removed when Guacamole closes its
  tunnel. Each server reports in every 10 seconds; the sessions of a server
  not heard from for 45 seconds stop counting and are removed, and a server
  that stops cleanly removes its own at once. "Currently in use by" counts
  the sessions of every server, read again at most every 2 seconds.
- **Limits** are Guacamole's own (each connection's and balancing group's
  "max-connections" and "max-connections-per-user", or the defaults of
  `guacamole.properties`), checked against the sessions of every server while
  holding a lock in the database, so two servers never both let the last
  user in. A refusal is Guacamole's own, with its message.
- **Active Sessions** lists the sessions of every server, with Guacamole's
  rules: administrators see all of them, other users those of connections
  they may use. **Ending** a session from another server asks the server
  running it, which ends it within 2 seconds. **Joining** one, or opening its
  **share link** on another server, connects to the guacd it runs on and
  joins it there, with the sharing profile's parameters.
- **Logins.** Each is recorded with who logged in, their groups (as found by
  any extension, such as LDAP), where from, and which extensions gave them a
  context; the token itself only as its SHA-256. A server given a token it
  does not know rebuilds that login from the record, as Guacamole does when
  it refreshes a login, unless the user's database account is disabled,
  expired or outside its access window. Logging out on any server ends the
  login on every server within 10 seconds. Guacamole keeps logins in a map no
  extension API can reach: the module replaces it through Guacamole 1.6.0's
  internals, and if a Guacamole version keeps logins differently, it logs
  that logins are not shared, and shares everything else.
- **Failed logins** are counted per address on every server, with the ban
  extension's limits, when it is installed. **TOTP codes**, when the TOTP
  extension is installed, are refused on every server for two periods once
  used. **Recordings**: each server lists those in its
  `recording-search-path` every 30 seconds, and a server showing a
  connection's history without a recording of its own fetches it from the
  server that has it, giving the shared secret.

System administrators see a **High Availability** tab in the settings,
refreshed every 10 seconds: the servers sharing the database (running or not
heard from, host name, URL, version, sessions and recordings), what this
server shares given the extensions installed, and warnings for what is
missing. **Check server URLs** asks each server who it is at its
`pam-ha-url`, with the shared secret.

#### Limits

- **A server's sessions end with it.** Their tunnels live on that server, so
  if it fails, users reconnect through another server.
- **Balancing groups:** the group's sessions and limits are shared, but the
  connection Guacamole picks in it is still decided by each server from its
  own sessions.
- **Rebuilt logins** need every extension that gave the login a context to
  give it one again. Extensions that keep their own logins, such as LDAP,
  RADIUS or SSO, give none for a user they did not log in themselves: those
  users log in again on another server. Database users are rebuilt.
- **Share links opened on another server** need Guacamole's database
  authentication to accept anonymous users. With `<database>-user-required`
  or `<database>-auto-create-accounts` set, share links only open on the
  server running the session, and the module logs that.
- **Recordings** fetched from another server are available while that server
  runs. A shared recording storage avoids this.
- **Sessions ended by the browser** over Guacamole's HTTP tunnel end once
  Guacamole closes the tunnel, about 15 seconds later; over WebSocket at once.

#### Security of the HA module

- Tokens and share keys are stored only as SHA-256 hashes.
- The recordings endpoint (`/api/ext/pam-ha/recordings/...`) requires the
  shared secret, and only serves files of `recording-search-path` named by a
  history UUID. `/api/ext/pam-ha/ping` answers only those giving the secret.
  Servers never follow redirects when giving it, so each `pam-ha-url` must
  reach its server directly. Use HTTPS, or a network between the servers
  only.
- **The database is trusted as Guacamole trusts it.** With the module, its
  records also make logins, choose the guacd a join connects to, and the URLs
  servers give the secret to. Keep its credentials as safe as an
  administrator's.
- **guacd has no authentication of its own.** Let only the Guacamole servers
  reach each guacd, and use `guacd-ssl` where that network is not trusted.

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
connection, and Guacamole's API, see neither the values nor the tokens, only
`********`, as for a platform's stored passwords: saving it unchanged keeps
the value, and typing a new value replaces it. `********` can't be copied to
another connection (cloning one asks for its passwords again), nor can a
token be used in any other field or connection, where Guacamole would replace
it too, and encrypted values can't be pasted into a connection.

Values containing one of Guacamole's own tokens, such as `${GUAC_PASSWORD}`
to pass the user's own password on, stay in their field for Guacamole to
replace.

Accounts' passwords never reach Guacamole's connections, but are kept the same
way, so every connection shows its password the same way.

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
  | PAM_ENCRYPTION_KEY=<the key> java -cp guacamole-pam-<version>.jar \
      io.github.ialzamil.guacamole.pam.crypto.SecretCipher pending-password
```

The last argument is the kind of value: `pending-password`,
`connection-secret:<connection id>:<field>` (from `pam_connection_secret`,
such as `connection-secret:17:private-key`), `setting-secret:<setting>` (from
`pam_setting`, such as `setting-secret:pam-email-password`) or
`platform-secrets`.

## After installing

- **Every connection requires a request by default**, including connections
  that already existed. To keep a connection usable as before, tick **Allow
  access without a request** in its *Access requests* section.
- **Administrators skip approvals, but still give a reason** when a connection
  or Account requires a request, so their access is in the history like
  anyone else's. To let administrators connect and check out Accounts without
  any request instead (logged), tick **Administrators bypass requests** on
  the **PAM Settings** tab.
- **Extensions are allowed by default**, twice per checkout. Each
  connection's *Access requests* section can allow or refuse them, and set
  how many and how long. The default for every connection is set on the
  **PAM Settings** tab.
- Only administrators can change a connection's *Password management* and
  *Access requests* sections, platforms, or who may approve. Nor can anyone
  else change, on a connection whose password is managed:
  - its credentials (username, password, domain, private key and
    passphrase), which decide whose password its platform rotates;
  - where it connects, so where guacd sends the password: its hostname and
    port, an RDP gateway, SFTP, a VNC repeater;
  - how it checks the server: SSH's host key, RDP's security mode and
    certificate settings, Kubernetes' TLS settings; and where Telnet types
    the credentials (its prompt patterns);
  - its protocol, and the guacd it is opened through (guacd receives the
    password).

  Other users who may create or edit connections can still change
  everything else, such as display and recording settings.
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
- **Rotations wait for sessions, and sessions for rotations.** Automatic
  rotations wait until a connection has no open session or checkout, and a
  session or checkout of a connection being rotated is refused until the
  rotation ends ("Please try again in a moment"). A session ending as its
  server stops still gets its after-use rotation, from the server working
  next.
- Balancing connection groups refuse to connect when one of their
  connections requires a request, is an Account, or has its password
  managed: open those connections directly.
- **Deleting a connection keeps its history.** Its checkouts and requests
  stay in the history under the name it had. Deleting it ends its active
  checkouts ("connection deleted"), closing their sessions, and cancels its
  requests awaiting approval and its reservations.
- **Revoking access ends open sessions.** Within 15 seconds of a user losing
  the permission to read a connection, or of its deletion, their sessions of
  it close (Guacamole alone lets them run until they end). Removing a user's
  administrator permission takes effect at once, without them logging in
  again.
- Administrators get four new settings tabs: **Platforms**, **Password
  Rotation**, **Checkouts** and **Approvals**. Approvers who aren't
  administrators only get **Approvals**, for the connections their permission
  covers.
- **Platforms can be exported and imported**, from the **Platforms** tab, to
  copy them to another server or keep them under version control. **Export**
  downloads the platforms listed (so the filter narrows it down) as JSON,
  without their passwords, which never leave the server. **Import** checks
  every platform as the editor does when saving one, and imports all of them
  or none, on an import page laid out as Guacamole's own connection import
  (with its format tips). Platforms are matched by name: a platform that
  already exists makes the import fail, unless **Update existing platforms**
  is ticked.
  Updated platforms keep their stored passwords, unless where they are sent
  changes; one given empty is removed. A new platform that needs a password
  can be given it among its settings in the file, such as
  `"winrm-admin-password"`. **Restore
  defaults** adds back "Unix", "macOS" and "Windows" if missing;
  a platform with one of their names is left as it is, even if changed.
- **LDAP, Kerberos, TACACS+ and Database platforms can be tested before
  saving**, with **Test** in the platform editor. It checks the settings as
  they are, changing no password: the server is reached and trusted (LDAP: its
  certificate; a Kerberos KDC: its realm, then the password change server; a
  TACACS+ server, and its backup: that it accepts the shared secret, by
  starting a login it abandons before any password; a database: its
  certificate), and the rotation account, admin principal or administrator
  account, if any, signs in (for a database, also whether it may change other
  accounts' passwords). A database platform without an administrator signs in
  as an account that doesn't exist, `guacamole-pam-test`, which the server
  must refuse and may log as a failed login. Each step's outcome
  is listed, and the test is logged, with the servers it reached. The test
  connects from the Guacamole server, to whatever host and port the
  administrator gives, and its errors tell whether they answered: like
  connections themselves, which reach any host through guacd, it is for
  administrators only. Stored passwords, shown masked, are the
  ones tested, unless where they are sent changed: enter them again then.
  Without an admin principal, Active Directory and some KDCs don't say
  whether they serve the realm: the first rotation checks it. Likewise, a
  TACACS+ server only says whether it allows password changes when asked to
  change one. To find out,
  the test asks for the realm's `krbtgt` principal with a wrong password,
  which the KDC logs as a failed login: expect one per test.
- Approvers see a yellow badge counting requests awaiting their decision.
  Administrators also see a red badge counting failed rotations. Each user can
  turn either off under **Preferences → Notification badges**.

### Settings

The **PAM Settings** tab (administrators only) holds the settings shared by
every Guacamole server using the database: whether administrators bypass
requests, and whether and how many times checkouts may be extended by
default. They're stored in the database (`pam_setting`), apply without a
restart, and reach every server within 5 seconds. Each change is logged with
who made it. Secrets set there, such as a mail server's password, are
encrypted like other stored secrets, and never shown again: leave the field
empty to keep one, or tick **Remove**. **Restore defaults** resets one
section.

They used to be set in `guacamole.properties` (`pam-admin-bypass-requests`,
`pam-extensions-enabled`, `pam-max-extensions`, or their `PAM_*` variables in
the Docker image). A value still set there is imported once, by the first
server reading the settings, unless the setting was already decided in the
database; from then on it's ignored, with a warning in the log until removed.

Some settings stay in each server's `guacamole.properties`, as they're needed
to reach the database, or protect what it stores: `pam-database`,
`pam-database-max-connections` and the `pam-encryption-*` keys: keep them
alike on every server.

### Syslog

The **Syslog** section of the **PAM Settings** tab sends every PAM event to a
syslog server as it happens, so a SIEM sees who requested, approved, checked
out, connected to and viewed what. It's off by default. Each Guacamole server
sends the events that happened on it, so with the HA module each event is
sent once.

Events are rotations (succeeded or failed); requests submitted, approved,
granted, denied and cancelled; checkouts started, extended, released,
expired and revoked; passwords viewed; sessions started and ended; a server
going on standby and working again; and changes to the PAM settings.
Passwords are never sent.

- **Transport**: TLS (RFC 5425, the default, port 6514) checks that the
  server's certificate is trusted and names the host set; paste the CA
  certificates that issued it, in PEM, unless Java already trusts them. TCP
  (port 514 usually) sends in the clear; UDP also loses messages silently
  when the server is down.
- **Format**: RFC 5424, framed by length over TLS and TCP (RFC 6587). The
  MSGID is the event, and the message a sentence followed by the event's
  fields as `name="value"` pairs, which log servers and SIEMs split without
  configuration:

  ```
  <85>1 2026-10-27T10:00:00.123Z guac1 guacamole-pam - checkout-started - User "bob" checked out "web01". event="checkout-started" user="bob" connection="web01" connection-id="3" checkout="12" starts="2026-10-27T10:00:00.120Z" ends="2026-10-27T11:00:00.120Z" remote-host="10.0.0.5" reason="Ticket 4521"
  ```

  Fields: `user` (whose request, checkout or session), `actor` (who decided,
  revoked or changed), `connection`, `connection-id`, `request`, `checkout`,
  `starts`, `ends`, `remote-host`, `reason`, `detail`. Severities: error for
  failed rotations, warning for revoked checkouts and standby, notice for
  checkouts, grants, denials, viewed passwords and setting changes,
  informational otherwise. The facility is `authpriv` unless set.
  Messages are cut at 8 KB.
- **Delivery**: each server queues up to 1,000 events, sent one at a time on
  a connection kept open. An event that can't be sent is tried again after 2,
  5 and 10 seconds, then dropped; the log says when sending fails, and when it
  works again. **Send a test message** sends one with the saved settings, and
  says why it couldn't.

### Password policies

New passwords are random, and follow a *password policy*, so they meet each
target system's requirements. Without one, they have 24 characters, with at
least one lowercase letter, uppercase letter, digit and symbol, using only
`- _ = + . , : @` as symbols (no meaning on command lines), and none of the
characters easily mistaken for others (`l`, `I`, `O`, `0`, `1`).

The **Password Policies** tab (administrators only) holds named policies.
Each sets:

- the length, from 4 to 128 characters;
- for lowercase letters, uppercase letters, digits and symbols: whether they
  are allowed, and at least how many;
- which symbols, which may be any printable ASCII characters;
- whether to leave out characters easily mistaken for others, and whether
  passwords start with a letter.

Rules that can't make a password are refused, such as minimums adding up to
more than the length. The editor shows examples and how strong the passwords
are. It warns of symbols with a meaning on command lines (such as `$`, `!`
or quotes), which break SSH scripts typing the password into a command
rather than at a prompt; the other platform types pass passwords safely.

A platform chooses a policy in its rotation policy, and a connection may
choose another in its own (*Password policy*), for a host with its own
requirements. A policy in use can't be deleted. Exported platforms name
their policy, which an import must find by that name.

### Who may approve

Tick **Can approve requests** in the Permissions section of a user or user
group. Then tick **Approve** next to the connections or connection groups they
may approve in the editor's connections list. A connection group covers every
connection in it, including ones added later. Set how many distinct approvers a
connection needs in its *Access requests* section.

### Database accounts

A **Database** platform manages the passwords of PostgreSQL roles, MySQL and
MariaDB accounts, or SQL Server logins on one database server, for its
**Account** connections: Guacamole opens no sessions to databases, so a DBA
checks out the password and uses it in their own client. Each connection's
account is its username; on MySQL and MariaDB, set its **Account host** if it
isn't `'name'@'%'`. Opened sessions keep working when a password changes.

The platform uses the database's JDBC driver from `GUACAMOLE_HOME/lib`, where
Guacamole's own is: put there the driver of each other database you manage
(PostgreSQL JDBC, MariaDB Connector/J or MySQL Connector/J, the Microsoft JDBC
Driver for SQL Server), then restart Guacamole. A missing driver is named when
testing or rotating. The Docker image ships all three in
`/opt/guacamole/drivers`, but only links its own database's: link the others,
for example from a script in `/opt/guacamole/entrypoint.d` (as this
repository's test setup does in `lab/entrypoint.d/855-add-pam.sh`):

```
for driver in /opt/guacamole/drivers/*.jar; do
    [ -e "$GUACAMOLE_HOME/lib/$(basename "$driver")" ] || ln -s "$driver" "$GUACAMOLE_HOME/lib/"
done
```

Connections use TLS with the server's certificate checked by default,
against the platform's **CA certificates** (or the server's own certificate),
or those Java trusts; the certificate must name the server's hostname.

MariaDB accounts using another authentication method than
`mysql_native_password`, such as `ed25519`, need MariaDB Connector/J: MySQL
Connector/J (the Docker image's) can't sign in with them, so their passwords
are left unchanged, saying so.

Without an administrator account, each account changes its own password.
With one, it needs:

| Database | Administrator account | The account itself |
|---|---|---|
| PostgreSQL | Superuser, or `CREATEROLE` and (since PostgreSQL 16) the ADMIN option on each role: `GRANT role TO admin WITH ADMIN OPTION` | Any login role |
| MySQL | `CREATE USER` | Any account (changing with its current password, as `password_require_current` may require) |
| MariaDB | `CREATE USER`, and `SELECT` on `mysql.global_priv` to read each account's authentication method, which is kept | Any account (with `SET PASSWORD`: `ALTER USER` needs `CREATE USER` even for one's own account) |
| SQL Server | `ALTER ANY LOGIN`, and `CONTROL SERVER` for sysadmin logins | Any SQL login (giving its current password). Windows logins are domain accounts: use LDAP or Kerberos |

### Setting up WinRM over HTTPS

Windows doesn't listen for WinRM over HTTPS by default, and WinRM platforms
need it (see [Security notes](#security-notes)). Each host needs an HTTPS
listener with a certificate. How the extension trusts that certificate is up
to the platform:

| Platform's *CA certificates* | Host certificates | Renewals |
|---|---|---|
| Empty | Any, such as self-signed. The first one seen is trusted from then on, or the fingerprint pinned on the connection | A new certificate fails until its fingerprint is pinned on the connection |
| Your CA's certificate | Issued by that CA, naming the host as Guacamole reaches it | Trusted as they come |

#### One host, with a self-signed certificate

In an elevated PowerShell on the host:

```powershell
Enable-PSRemoting -Force   # if WinRM isn't enabled yet (it is on Windows Server)
$cert = New-SelfSignedCertificate -DnsName $env:COMPUTERNAME -CertStoreLocation Cert:\LocalMachine\My
New-Item -Path WSMan:\localhost\Listener -Transport HTTPS -Address * -CertificateThumbPrint $cert.Thumbprint -Force
New-NetFirewallRule -Name WinRM-HTTPS -DisplayName 'WinRM over HTTPS' -Direction Inbound -LocalPort 5986 -Protocol TCP -Action Allow
Set-Item WSMan:\localhost\Service\Auth\CbtHardeningLevel Strict
```

Leave the platform's *CA certificates* empty. To skip trusting the first
certificate seen, pin it in the connection's **Trusted certificate** field.
Get its fingerprint on the host:

```powershell
[BitConverter]::ToString([Security.Cryptography.SHA256]::Create().ComputeHash($cert.RawData)).Replace('-', ':')
```

Or get it from the Guacamole server:

```sh
openssl s_client -connect <host>:5986 </dev/null 2>/dev/null | openssl x509 -noout -fingerprint -sha256
```

#### Many hosts, with certificates from Active Directory Certificate Services

1. **A certificate template.** In *Certificate Templates*, duplicate **Web
   Server**. Under *Subject Name*, choose **Build from this Active Directory
   information**, with the DNS name. Under *Security*, give **Domain
   Computers** (or the servers' group) *Enroll* and *Autoenroll*. Then issue
   the template on the CA.
2. **Auto-enrollment, by Group Policy.** In *Computer Configuration →
   Policies → Windows Settings → Security Settings → Public Key Policies*,
   enable **Certificate Services Client – Auto-Enrollment**, with renewal and
   updating of certificates.
3. **The listener, by a startup script.** A WinRM listener keeps the
   certificate it was created with, so a renewed certificate isn't used
   until the listener changes. Run this as a computer startup script in the
   same policy, or also as a daily scheduled task. It creates the listener
   with the newest valid certificate naming the computer, and moves it to a
   renewed one:

   ```powershell
   $fqdn = [Net.Dns]::GetHostEntry($env:COMPUTERNAME).HostName
   $cert = Get-ChildItem Cert:\LocalMachine\My |
       Where-Object { $_.HasPrivateKey -and $_.NotAfter -gt (Get-Date) -and
                      $_.EnhancedKeyUsageList.ObjectId -contains '1.3.6.1.5.5.7.3.1' -and
                      $_.DnsNameList.Unicode -contains $fqdn } |
       Sort-Object NotAfter -Descending | Select-Object -First 1
   if (-not $cert) { return }
   $listener = Get-ChildItem WSMan:\localhost\Listener | Where-Object { $_.Keys -contains 'Transport=HTTPS' }
   $current = if ($listener) { (Get-ChildItem $listener.PSPath | Where-Object Name -eq CertificateThumbprint).Value }
   if ($current -ne $cert.Thumbprint) {
       if ($listener) { $listener | Remove-Item -Recurse -Force }
       New-Item -Path WSMan:\localhost\Listener -Transport HTTPS -Address * -CertificateThumbPrint $cert.Thumbprint -Force | Out-Null
   }
   Set-Item WSMan:\localhost\Service\Auth\CbtHardeningLevel Strict
   ```

   Also allow TCP 5986 inbound in *Windows Defender Firewall with Advanced
   Security*, in the same policy.
4. **The platform.** Export the CA's certificate in PEM, on the CA:

   ```
   certutil -ca.cert ca.cer
   certutil -encode ca.cer ca.pem
   ```

   Paste `ca.pem` into the WinRM platform's **CA certificates**. Paste the
   root CA's certificate, or the issuing CA's; several may follow each other.
   Give each connection the host's name as the certificate names it (its
   DNS name, not an IP address), in its **WinRM hostname** if its own
   hostname differs.

## Security notes

- **Secrets stay on the server.** Platform secrets, such as an LDAP rotation
  account's password, are never sent to the browser. They're stored unencrypted
  in the database unless a key is set (see
  [Encrypting stored secrets](#encrypting-stored-secrets)), like
  connections' passwords and keys, so set one, or protect database access
  accordingly.
- **A stored platform password only goes where it was entered for.** Saving
  a platform with another server, port, encryption or trusted certificate
  (LDAP), realm or KDC (Kerberos), port or CA certificates (WinRM), server,
  port or backup server (TACACS+), or database type, hostname, port, name,
  encryption or CA certificates (Database) needs its administrator password
  (TACACS+: its shared secret) entered again, so whoever may edit platforms
  can't have it sent to a server of their choosing. WinRM hosts are set on
  each connection, which only administrators can change.
- **Editors can read passwords, unless a key is set.** Users with *edit*
  permission on a connection can read its parameters, including its password.
  With a key set, they only see `********` in their place. They can still
  change the parameters of a connection whose password isn't managed,
  including those sending it elsewhere (its hostname, an RDP gateway, SFTP,
  a VNC repeater), so give edit permission on sensitive connections and
  Accounts to administrators only, or have their passwords managed.
- **A Guacamole 1.6 issue can end sessions.** Guacamole remembers the first
  request whose error it handles, and ends that request's session whenever a
  later request is refused as unauthorized, from anyone. The extension's own
  pages never send requests without a session, so they don't trigger it.
- **SSH hosts are pinned.** A host is refused, before any credential is sent,
  until its key's fingerprint is in the connection's **Trusted SSH host key**
  field: the error shows the key presented and its type, to check on the
  host (such as `ssh-keygen -lf /etc/ssh/ssh_host_ecdsa_key.pub`) and paste. With
  **Trust new host keys** on the platform, the key seen first is trusted
  instead and required from then on, like SSH's `known_hosts`. If a host's key
  changes on purpose, paste the new fingerprint likewise. With **SSH CA keys**
  on the platform (the public keys of the CAs that sign your hosts' SSH host
  certificates, as in the CA's `.pub` file), a host presenting a certificate
  one of them signed, valid now and naming the host as the connection reaches
  it, is trusted without a pinned key, like `@cert-authority` in
  `known_hosts`; a host presenting none is refused unless its key is pinned.
  A pinned key is required instead, if set. Revocation isn't checked.
- **LDAP must be encrypted with a rotation account.** LDAP platforms with a
  rotation account require LDAPS or StartTLS. Pin the server certificate's
  fingerprint, or use a certificate the JVM trusts that matches the hostname.
- **Kerberos needs no certificate.** Kerberos itself proves both the KDC and
  the password change server genuine, from the password's key. Only the KDC
  (port 88, TCP) and kpasswd (port 464, TCP) need to be reachable. Without an
  admin principal, each principal changes its own password, which needs its
  current one.
- **WinRM needs HTTPS, and checks each host's certificate.** WinRM platforms
  connect over HTTPS only (port 5986 by default), and log in with NTLM bound
  to the TLS channel, so they work whatever the host's `CbtHardeningLevel`
  (`Strict` recommended). With CA certificates on the platform, a host's
  certificate must be issued by one of them and name the host. Without any, it
  must be pinned in the connection's **Trusted certificate** field (the error
  shows its fingerprint), or, with **Trust new certificates** on the platform,
  the certificate seen first is trusted and required from then on. Either
  way, a pinned fingerprint is required instead. Revocation isn't checked. See
  [Setting up WinRM over HTTPS](#setting-up-winrm-over-https). Passwords are
  sent on PowerShell's input, never on a
  command line. Without an administrator on the platform, each account sets its
  own password, so it must be a local administrator. Only local accounts are
  supported: manage domain accounts with an LDAP or Kerberos platform.
- **Database passwords stay out of the servers' logs.** PostgreSQL is sent a
  SCRAM-SHA-256 verifier computed by the extension, and MariaDB, for accounts
  using `mysql_native_password` (its default), that method's hash, never the
  password: both would log it in the clear when logging statements. MySQL and
  SQL Server mask passwords in their logs themselves. MariaDB accounts using
  another method, such as `ed25519`, keep it, so are given the password
  itself, which MariaDB's general log (off by default) would show. Without an
  administrator account, SQL Server and MySQL are given the current password
  too, which they check.
- **TACACS+ is only as safe as its network.** TACACS+ (RFC 8907) hides
  packets with an MD5 pad derived from the shared secret, which the RFC
  itself calls weak; the server is trusted only by knowing that secret. Use
  TACACS+ platforms over a trusted management network only, with a long
  random shared secret. Passwords are changed with the current one, as the
  account itself: only on servers allowing it, such as tac_plus-ng with a
  backend storing passwords (Facebook's tac_plus never allows it). For
  accounts the server checks in a directory, use an LDAP or Kerberos
  platform instead.

## Development

`build.sh` builds the jar. `check-dependencies.sh` checks the libraries it
bundles against [osv.dev](https://osv.dev)'s known vulnerabilities, sending
their names and versions only, and fails if one is affected; CI runs it on
every push and weekly, and Dependabot proposes library updates. `lab/lab.sh` runs a test lab with podman, on a
network named `myguacnet`, for development only: it uses fixed test
passwords. Its commands run in the order given:

| Command | What it does |
|---|---|
| `lab/lab.sh app` | (Re)starts Guacamole's database, guacd and Guacamole with the built jar, on http://localhost:8080. Run it again after each build. Stored secrets are encrypted with a fixed test key; set `PAM_ENCRYPTION_KEY=` to store them unencrypted |
| `lab/lab.sh app --ha` | Also a second Guacamole sharing the database and guacd, on http://localhost:8081, with the [HA module](#high-availability-the-ha-module) on in both, for the two-server tests (`--ha` alone restarts both servers that way, keeping the database and guacd running) |
| `lab/lab.sh app --ha=off` | The same two servers with the HA module off: the second, started once the first answers, stays on standby (alone, likewise restarts both) |
| `lab/lab.sh services` | The servers whose accounts the lab manages, keeping those already running: SSH `mysshtest` (user `mysshtest`; its ECDSA host key has a certificate of a test SSH CA, `lab/targets/certs/ssh_ca.pub`), OpenLDAP `myldaptest` (`uid=ldaptest,ou=people,dc=example,dc=org`), Samba AD `myadtest` (LDAPS and Kerberos, `CN=adtest,CN=Users,DC=ad,DC=example,DC=org`), MIT Kerberos `mykdctest` (realm `EXAMPLE.ORG`, `kdctest`), TACACS+ `mytacacstest` (tac_plus-ng, built from source into `localhost/pam-tacacs-test` the first time; `tactest`), and databases over TLS with certificates of a test CA generated into `lab/targets/certs`: PostgreSQL `mypgtarget`, MySQL `mymysqltarget`, MariaDB `mymariadbtarget`, SQL Server `mymssqltarget` (`dbtest`); and a syslog receiver `mysyslogtest` (TLS with a certificate of the same CA, TCP, UDP). Passwords are listed at the top of `lab/lab.sh` |
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

Tests are described in [tests/README.md](tests/README.md): unit tests run
with every build, `tests/run.sh` runs the live suites against this setup, and
`tests/ha/run.sh` the HA module's against `lab/ha.sh`.

Recreating the SSH, LDAP, AD or KDC containers generates new host keys and
certificates, and resets their passwords. Pin the new fingerprints and reset the
stored passwords afterwards.
