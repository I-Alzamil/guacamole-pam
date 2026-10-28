# guacamole-pam

[![Build](https://github.com/I-Alzamil/guacamole-pam/actions/workflows/build.yml/badge.svg)](https://github.com/I-Alzamil/guacamole-pam/actions/workflows/build.yml)

PAM (Privileged Access Management) extension for [Apache
Guacamole](https://guacamole.apache.org/) 1.6.0. It rotates the passwords of
the connections Guacamole stores, and lets users reach them only through
time-limited requests that, where enabled, require approval, with everything
logged.

## Capabilities

- **Password rotation** over SSH (send/expect scripts for Unix, macOS and
  Windows), LDAP and Active Directory, Kerberos, WinRM, TACACS+, and database
  accounts (PostgreSQL, MySQL, MariaDB, SQL Server). A new password is only
  stored once the target accepts it.
- **Rotation schedules and password policies**: passwords are rotated after
  each use, periodically, or only on demand, and new ones follow a password
  policy, for systems with their own requirements.
- **Accounts**: a new connection type for accounts Guacamole can't connect to,
  such as LDAP and database accounts, web consoles and service accounts. Their
  passwords are managed and rotated like any connection's, and users check
  them out for a limited time instead of opening a session.
- **Access requests** with a reason and a time limit, sessions closed when
  access ends, approval by one or more approvers, requests ahead of time, and
  extensions.
- **Audit**: searchable checkout and approval histories exported as CSV, and
  every event sent to syslog (RFC 5424, over TLS) and by email to those it
  concerns.
- **Encryption** of stored secrets (AES-256-GCM), with a key kept out of the
  database.
- **Multi-instance support**: several Guacamole instances share the database,
  one working while the others wait on standby, or all of them active-active
  with the optional HA module.

## Quick start

You need Guacamole 1.6.0 with its database authentication (PostgreSQL 13+,
MySQL 8.0+, MariaDB 10.6+ or SQL Server 2017+) installed and working, and Java
11 or later.

1. Download `guacamole-pam-<version>.jar` from the
   [releases](https://github.com/I-Alzamil/guacamole-pam/releases), or build
   it with `mvn package`, and copy it into `GUACAMOLE_HOME/extensions/`.
2. Optionally, to encrypt stored secrets, generate a key with `openssl rand
   -base64 32`, set it in `guacamole.properties`, and back it up:

   ```
   pam-encryption-key: <the key>
   ```

3. Restart Guacamole. The extension creates its tables on first use (if
   Guacamole's database user may not create tables, see
   [Installation](docs/installation.md#if-guacamoles-database-user-may-not-create-tables)).
4. Log in as an administrator. **Every connection now requires a request**: to
   keep one usable as before, tick **Allow access without a request** in its
   *Access requests* section. To rotate a connection's password, pick a
   platform in its *Password management* section; the **Platforms** tab has
   three to start with, "Unix", "macOS" and "Windows".

## Documentation

| Guide | What it covers |
|---|---|
| [Overview](docs/overview.md) | What each capability does, in detail |
| [Installation](docs/installation.md) | Requirements, supported databases, creating the tables by hand |
| [Access, requests and approvals](docs/access.md) | How connections behave once installed, and who may approve |
| [Platforms and password rotation](docs/platforms.md) | Managing platforms, password policies, database accounts, WinRM over HTTPS |
| [Settings and notifications](docs/configuration.md) | The PAM Settings tab, syslog, email and its templates |
| [Several servers and high availability](docs/high-availability.md) | Standby servers, and the HA module |
| [Encrypting stored secrets](docs/encryption.md) | The key, changing it, and reading an encrypted value |
| [Security notes](docs/security.md) | What the extension protects, and how |
| [Development](docs/development.md) | Building, the test lab and the tests |

[CHANGELOG.md](CHANGELOG.md) lists what each release changes.

## License

Licensed under the [Apache License 2.0](LICENSE). The libraries bundled in the
jar, and their licenses, are listed in [NOTICE](NOTICE).
