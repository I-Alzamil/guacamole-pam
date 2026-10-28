# Overview

What the extension does, in more detail than the [README](../README.md).

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
  Every event can also go to a [syslog server](configuration.md#syslog), over TLS, and by
  [email](configuration.md#email) to those it concerns.
- **High availability, if wanted.** Several Guacamole servers can share the
  database as one, active-active: the optional
  [HA module](high-availability.md#high-availability-the-ha-module) shares sessions, connection
  limits, Active Sessions, logins, share links, failed logins, TOTP codes and
  recordings between them. A single server leaves it off; without it, other
  servers on the database wait on standby, read-only for PAM, and take over
  once it stops.
