# Tests

Two tiers, from cheapest to most realistic. What only real Windows does
(WinRM's channel binding hardening, how a domain controller checks
passwords) is not automated: check it by hand against a Windows machine.
Nor is MariaDB Connector/J, which the Docker image lacks (the suites use the
image's drivers): with it in Guacamole's `lib`, check that a MariaDB `ed25519`
account rotates, by the administrator and by itself, and stays `ed25519`.

| Tier | What | Needs | Run |
|---|---|---|---|
| 1 | Unit tests (JUnit) | Nothing | `mvn test` (also part of every build) |
| 2 | Live suites against the extension running in Guacamole | The podman test setup | `tests/run.sh` |
| 2 | The HA module, against two servers per database | `lab/ha.sh start DATABASE...` | `tests/ha/run.sh [DATABASE...]` |

## Tier 1: unit tests

Run with every build. Highlights:

- **WinRM** (`winrm/`): the client runs against a fake Windows endpoint
  (`FakeWinRmServer`) answering with an NTLM challenge recorded from
  Windows 11. Covers the remote shell lifecycle, retries after WinRM's
  timeout fault, chunked HTTP, values passed only on stdin (never on a
  command line), certificate pinning (no request at all to a wrong
  certificate), and how Windows' errors are reported.
- **NTLM channel binding**: hashes checked against values computed
  independently, for SHA-256 and SHA-384 certificates.
- **Kerberos**: the RFC 3244 request data against an independently computed
  DER encoding; settings parsing.
- **SSH transcripts**: passwords never shown, even partly, however output is
  cut.
- Settings of every platform type (`*TargetTest`).

## Tier 2: live suites

Everything is checked through Guacamole's REST API, and every new password
is also checked directly on the server, with a tool independent of the
extension (OpenSSH, `ldapwhoami`, Samba's `ldapsearch`, MIT `kinit`, and
`tests/tacacs.py`, a TACACS+ client written apart from the extension's,
and each database's own client).

### Prerequisites

```
./build.sh
lab/lab.sh app --ha services   # --ha: a second server, both with the HA module, for 40-servers (--ha=off: without it, the second on standby)
```

`lab.sh seed` is not needed: suites create what they use.

The suites run against whichever database `lab.sh` started: PostgreSQL by
default, or `PAM_DB=mysql`, `mariadb` or `sqlserver` (see the main README's
Development section). Queries they make directly go through `sql` in
`lab/database.sh`, so every suite runs on each of them.

Importing settings from `guacamole.properties` needs a server started with
them, so it's checked by hand: start another Guacamole on the lab's database
with `-e PAM_EXTENSIONS_ENABLED=false -e PAM_MAX_EXTENSIONS=4` (as `lab.sh`
starts one, on another port), on a database where only `pam-max-extensions`
was set on the tab, then open the PAM Settings tab there. The log shows
`pam-extensions-enabled` imported, and `pam-max-extensions` ignored with a
warning.

### Running

```
tests/run.sh                 # every suite (about 1 minute, 3.5 minutes with 40-servers)
tests/run.sh rotation        # suites whose name contains "rotation"
tests/run.sh access security
```

The exit code is 0 when every check passed, 1 otherwise; failures are listed
at the end. `GUAC_URL`, `GUAC_ADMIN` and `GUAC_ADMIN_PASSWORD` override the
defaults (`http://localhost:8080`, `guacadmin` / `guacadmin`).

### Suites

| Suite | Covers |
|---|---|
| `10-rotation` | SSH (the Unix default, as the account and as root, with `@case` choosing by the prompt; `@fail` before and after the change), LDAP (OpenLDAP over LDAPS and StartTLS, Samba AD), Kerberos (MIT and Samba AD), TACACS+ (tac_plus-ng: the account itself, through a backup server, with a TACACS+ username; another shared secret and a password changed elsewhere refused, unchanged), each by an administrator account and by the account itself; host key and certificate pinning; SSH hosts refused until their key is pinned, recorded or trusted on first contact by the platform; SSH host certificates of the platform's CA trusted, refused when not naming the host as reached; untrusted certificates; Kerberos accounts whose salt is not the default (a renamed account, as for a promoted domain controller's Administrator) |
| `15-databases` | PostgreSQL, MySQL, MariaDB and SQL Server accounts, by their administrators and by the accounts themselves, over TLS checked against the test CA: what each administrator needs (PostgreSQL's ADMIN option, MySQL's CREATE USER, SQL Server's CONTROL SERVER for sysadmin logins), MySQL's `password_require_current` and account hosts, MariaDB accounts' authentication methods kept (an `ed25519` account left unchanged with MySQL Connector/J, the image's driver, saying MariaDB Connector/J is needed), passwords kept out of PostgreSQL's and MariaDB's statement logs, certificates of another CA refused, unverified TLS, and the Test button |
| `20-access` | Requests and reasons; two approvals, directly and through a group; the last two given at once; approvers through connection groups (nested, and ROOT) and nested user groups, never a disabled one; non-approvers; self-approval; denials with reasons; cancellations; checkouts of Accounts and of connections, release and revocation; an expired checkout not ended yet opening no session; what administrators skip; deleting a connection keeping its checkouts and requests in the history |
| `25-ahead` | Requests ahead of time: what is refused (no approval needed, a past start, more than 30 days ahead); approval reserving the connection; overlapping requests refused, or no longer approvable once another is approved (the approval withdrawn); others' checkouts ending when a reservation starts, and refused during it; checking out with a reservation, until its end, and only once; cancelling one; expiry at its end rather than after 24 hours; deleting a connection cancelling its reservations |
| `26-extensions` | Several time limits at once (up to one more than the extensions allowed, using them up); extensions without approval (a reason needed, granted at once, by the time limit, until none is left) and with approval (as many approvals as requests, not by the holder, by the extension length); a connection allowing none; cancelling one; one expiring with its checkout; others' reservations bounding them; the checkout history listing them with their approvers |
| `27-settings` | The PAM Settings tab: read and changed by administrators only; invalid values and unknown settings (the encryption key among them) refused, with the whole change; administrators bypassing requests, and the extensions allowed by default, applied to requests at once, and on the second server within its 5-second cache (skipped without `lab.sh --ha`); each change recorded as whose, and logged; defaults restored, still recorded as decided in the database |
| `28-password-policies` | Who may read and change password policies (users get names only); rules that can make no password refused, and duplicate names; examples and their strength; rotated passwords following the default rules, a platform's policy, and a connection's own in place of it, checked on OpenLDAP too; a policy changed applying to the next rotation; what uses each, and deletion refused while used; platforms choosing no such policy refused; a policy gone missing stopping rotations before any change; platforms imported naming their policy |
| `30-security` | What editors who are not administrators cannot change (password management, access requests; and of managed connections their credentials, the password included, where they connect, an RDP gateway, SFTP or a VNC repeater included, how they check the server, their protocol and guacd), while display parameters and saving unchanged still work, the original account-takeover attack end to end; balancing groups; administrator endpoints; platform secrets |
| `40-servers` | Two servers sharing the database (skipped without `lab.sh --ha` or `--ha=off`), as the PAM Settings tab tells administrators. With the HA module: both working; sessions counted by every server; a checkout revoked on one server closing the session on the other; after-use rotation waiting for sessions on the other server; one rotation at a time, and no checkout or session during it, across servers; records of a stopped server ignored once stale, removed, then the connection rotated. Without it: the second server on standby, refusing checkouts, rotations, setting changes and sessions of managed connections; taking over within seconds of the first stopping, removing the session that ended as it stopped and rotating its connection after use; both then restarted. Sessions are held open by `session.py`, as a browser would |
| `45-syslog` | Events sent to syslog (receiver `mysyslogtest`): off by default, over TLS on 6514, the insecure transports last; turning it on without a server, bad hosts, transports, CA certificates and application names refused; the test button for administrators only, saying why it failed (no server, an untrusted CA, a certificate not naming the host reached, nothing listening), sent once the lab CA is trusted, and logged; events sent once on: the setting change itself, a checkout framed by its length as RFC 5424 says (facility, severity, host, name, fields), a session, a release; a connection closed by the server opened again; TCP and UDP with another facility and name; nothing sent once off |
| `50-encryption` | Stored secrets with the test key of `lab.sh` (skipped without one): platform secrets and pending passwords encrypted at rest; every connection's passwords, private keys and passphrases, Accounts' included, kept apart behind tokens such as `${PAM_PASSWORD_17}`; Guacamole's own tokens left in place; what the API shows editors (`********`, never a token); editor saves keeping, replacing or refusing values (`********` sent back, or the token by an API client; another field's or connection's token or value; `********` in a clone or where nothing is stored; an unknown key); sessions logging in with kept passwords and with a kept private key and passphrase (checked in guacd's log, against a wrong-password control); a balancing group opening both its connections, each with its own secrets; a kept value moved to another connection in the database refused; rotations. Suites read encrypted values with the jar's own decryption tool |
| `60-reveal` | Showing a connection's password to the holder of its checkout: refused by default and without a checkout; shown with its username when allowed, uncached, each display recorded in the history and logged, never to another user; a managed password rotated once released although its rotation mode is never, the SSH server refusing the one shown; no rotation after a checkout that showed nothing; nothing shown for a password that is Guacamole's `${GUAC_PASSWORD}` |
| `70-revocation` | Revoked access: a session closing once its user may no longer read the connection, another of theirs staying open; a session closing when its connection is deleted; an administrator losing the permission losing its powers within the same login |
| `80-platforms` | Importing platforms: created with their settings, policy and secrets (never shown); refused when one exists unless updating; updates keeping a stored secret left out, but refused when the port changes without it, or the type changes; one invalid platform, or a name given twice, importing nothing; restoring the default platforms, adding only a missing one and changing none; administrators only |
| `85-testing` | Testing platforms before saving: OpenLDAP over LDAPS and StartTLS and Samba AD, MIT and Samba AD Kerberos, TACACS+ (another shared secret, an unknown server, a backup server), with and without a rotation account; a wrong password, another pinned certificate, an untrusted CA (naming the certificate to pin), an unknown server, an unknown admin principal, a realm the KDC does not confirm, an unreachable password change server; a saved platform's stored password tested, but refused once where it is sent changes, and a typed password tested instead without being saved; nothing saved; invalid settings, SSH platforms and users who are not administrators refused |
| `90-macos` | The macOS default against a real Mac (skipped unless `T2_MACOS_HOST`, `T2_MACOS_USER` and `T2_MACOS_PASSWORD` name a throwaway standard account with Remote Login allowed, whose login keychain uses the same password): the account's password and its login keychain's both changed by the account itself, each checked on the Mac; a keychain on another password reported while the new password is kept; an account without a login keychain changed without a problem. Prints the account's last password and deletes its login keychain |

### Test data

Suites name everything they create `t2...` (Guacamole users, groups,
platforms and connections; accounts in the LDAP, Samba and MIT servers) and
remove it when they end, even after a failed check. They leave existing data
alone, except the SSH image's single account (`mysshtest`): its new password
is written back to the seeded "PAM test (Linux)" connection.

### The HA module

`tests/ha/run.sh` checks the HA module on each database given (every one by
default), against the two servers `lab/ha.sh` starts for it, which also have
the ban, TOTP and history recording storage extensions. Their connections
need no access request, so PAM lets them open as Guacamole alone would. It
holds real sessions open on them (`tests/session.py`), and checks:

- sessions counted on both servers, and ended on both;
- a connection's limit, a limit per user, and a balancing group's limit
  (with the connection it picks) across the servers;
- logins made on one server working on the other, with their connections
  and sessions, and logging out on one ending them on both;
- sessions of one server listed on the other, hidden details for other
  users, ending a session from the other server (with a session joining
  it), and joining it from there;
- share links opening on either server, made from either, and ending with
  the session shared;
- a recording made on one server shown and played by the other;
- a TOTP code used on one server refused on the other;
- a server stopping cleanly freeing its sessions at once, a server killed
  no longer counting once no longer heard from, and its logins going on on
  the other;
- failed logins on both servers banning an address on both.

To see the checks fail as with Guacamole alone, start the servers with the
module off (the checks restart servers, so both need it):

```
lab/ha.sh stop postgresql
HA=off lab/ha.sh start postgresql
HA=off tests/ha/run.sh postgresql
```

### Trusting the tests

Each security-relevant test was checked to fail when the code it protects is
broken on purpose: the SHA-384 channel binding, certificate pinning, the
Kerberos salt handling, the protection of managed connections' parameters,
the balancing group check, each part of the two-server support (shared
rotation claims, sessions counted across servers, stale records, closing
sessions of checkouts ended elsewhere), and encryption at rest (editor saves,
rotated Account passwords, pending passwords, supplying tokens to
connections and balancing groups, refusing them elsewhere, leaving
Guacamole's tokens alone, binding kept values to their connection, refusing
encrypted values pasted into connections), platform tests sending stored
passwords only where they were entered for, and the protected parameters of
managed connections being checked before a new password is kept (a replaced
password otherwise looked unchanged). Do the same when adding a test for
a fix: a test that cannot fail proves nothing.
