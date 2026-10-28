# Several servers and high availability

## Several Guacamole servers

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
running with the HA module, whose own pool holds up to 10 more (one while
idle). Change the limit with
`pam-database-max-connections` in `guacamole.properties`, keeping the total
across servers within the database's own limit (`max_connections` on
PostgreSQL and MySQL). The lock needs the database's own locks to reach the
server holding them: not through a connection pooler sharing database
sessions (PgBouncer in transaction mode), nor across the nodes of a Galera
cluster.

## High availability (the HA module)

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
- **Settings** (see [Settings](configuration.md#settings)) changed on one server apply to the
  others within 5 seconds.

With encrypted secrets, every server needs the same keys. A single server
needs none of this: leave the module off, and it creates no tables, starts
no threads and shows no tab.

### Turning it on

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
once instead, from [src/main/resources/schema/ha](../src/main/resources/schema/ha).
Until the tables exist, the module logs why and shares nothing, trying again
every minute. With several database authentications configured, the
sessions of each are shared on their own, and logins, failed logins, TOTP
codes and recordings through the first one (PostgreSQL, then MySQL or
MariaDB, then SQL Server).

### What it shares

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

### Limits

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

### Security of the HA module

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
