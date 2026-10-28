# Changelog

Notable changes of each release. Versions follow
[semantic versioning](https://semver.org/); each is built for one Guacamole
release, named below.

## 1.0.0 (2026-10-28)

The first release, for Guacamole 1.6.0, on PostgreSQL, MySQL, MariaDB or SQL
Server. See the [README](README.md), and the guides in [docs](docs), for
installing and using it.

### Password rotation

- Connections whose password is only stored, or managed by a platform that
  changes it: over SSH with a send/expect script (Unix, macOS with its login
  keychain, Windows over OpenSSH), LDAP (OpenLDAP, Active Directory and other
  directories), Kerberos (kpasswd), WinRM (local Windows accounts, over
  HTTPS), TACACS+, or as database accounts (PostgreSQL, MySQL, MariaDB, SQL
  Server).
- Rotation never, after each use, or periodically, and once the holder has
  been shown the password. A new password is stored only once the target
  accepts it. Platforms can be tested before they are saved.
- Password policies, for systems with their own requirements.
- Three default SSH platforms, with platforms imported and exported as JSON.
- Secrets stored encrypted (AES-256-GCM) with a key of
  `guacamole.properties`, which can be replaced; connections' passwords kept
  apart from Guacamole's parameters, behind tokens.

### Access

- An "Account" connection type: a password checked out for a limited time,
  for what Guacamole can't connect to.
- Access requests with a reason, time-limited checkouts, and sessions closed
  when they end.
- Approval by one or more distinct approvers, chosen per connection or
  connection group, users or groups. Administrators skip approvals, unless
  set to need them, or bypass requests altogether if allowed.
- Requests ahead of time, reserving the connection; extensions of a checkout,
  approved like requests.
- Viewing the password, rotated once the holder is done.

### Audit and notifications

- Searchable checkout and approval histories, exported as CSV, with the
  address of every step.
- Every event sent to a syslog server (RFC 5424, over TLS, TCP or UDP).
- Emails to those an event concerns: administrators, approvers and
  requesters, each able to turn each kind off. Their templates and languages
  are edited, imported and exported on their own tab; English is built in.

### Multi-instance support

- Without the HA module, one server works and the others wait on standby,
  taking over once it stops.
- With the optional HA module, servers share the database active-active:
  sessions, connection limits, Active Sessions, logins, share links, failed
  logins, TOTP codes and recordings.

### Database

The tables (`pam_*`, and `pam_ha_*` for the HA module) are created on first
use, as schema version 1. Later releases upgrade them from it.
