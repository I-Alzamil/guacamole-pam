# Tests

Two tiers, from cheapest to most realistic. What only real Windows does
(WinRM's channel binding hardening, how a domain controller checks
passwords) is not automated: check it by hand against a Windows machine.

| Tier | What | Needs | Run |
|---|---|---|---|
| 1 | Unit tests (JUnit) | Nothing | `mvn test` (also part of every build) |
| 2 | Live suites against the extension running in Guacamole | The podman test setup | `tests/run.sh` |

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
extension (OpenSSH, `ldapwhoami`, Samba's `ldapsearch`, MIT `kinit`).

### Prerequisites

```
./build.sh
./startssh.sh
./startldap.sh
./startad.sh
./startkdc.sh
./startguac2.sh   # optional: a second server, for 40-servers
```

`seed.sh` is not needed: suites create what they use.

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
| `10-rotation` | SSH (the Unix default, as the account and as root, with `@case` choosing by the prompt; `@fail` before and after the change), LDAP (OpenLDAP over LDAPS and StartTLS, Samba AD), Kerberos (MIT and Samba AD), each by an administrator account and by the account itself; host key and certificate pinning; untrusted certificates; Kerberos accounts whose salt is not the default (a renamed account, as for a promoted domain controller's Administrator) |
| `20-access` | Requests and reasons; two approvals, directly and through a group; non-approvers; self-approval; denials with reasons; cancellations; checkouts of Accounts and of connections, release and revocation; an expired checkout not ended yet opening no session; what administrators skip; deleting a connection keeping its checkouts and requests in the history |
| `30-security` | What editors who are not administrators cannot change (password management, access requests, and the username, hostname, port, protocol and guacd of managed connections), the original account-takeover attack end to end; balancing groups; administrator endpoints; platform secrets |
| `40-servers` | Two servers sharing the database (skipped without `startguac2.sh`): sessions counted by every server; a checkout revoked on one server closing the session on the other; after-use rotation waiting for sessions on the other server; one rotation at a time, and no checkout during it, across servers; records of a stopped server ignored once stale, removed, then the connection rotated. Sessions are held open by `session.py`, as a browser would |
| `50-encryption` | Stored secrets with the test key of `build.sh` (skipped without one): platform secrets and pending passwords encrypted at rest; every connection's passwords, private keys and passphrases, Accounts' included, kept apart behind tokens such as `${PAM_PASSWORD_17}`; Guacamole's own tokens left in place; what the API shows editors; editor saves keeping, replacing or refusing values (another field's or connection's token or value, an unknown key); sessions logging in with kept passwords and with a kept private key and passphrase (checked in guacd's log, against a wrong-password control); a balancing group opening both its connections, each with its own secrets; a kept value moved to another connection in the database refused; rotations. Suites read encrypted values with the jar's own decryption tool |
| `60-reveal` | Showing a connection's password to the holder of its checkout: refused by default and without a checkout; shown with its username when allowed, uncached, each display recorded in the history and logged, never to another user; a managed password rotated once released although its rotation mode is never, the SSH server refusing the one shown; no rotation after a checkout that showed nothing; nothing shown for a password that is Guacamole's `${GUAC_PASSWORD}` |
| `70-revocation` | Revoked access: a session closing once its user may no longer read the connection, another of theirs staying open; a session closing when its connection is deleted; an administrator losing the permission losing its powers within the same login |
| `80-platforms` | Importing platforms: created with their settings, policy and secrets (never shown); refused when one exists unless updating; updates keeping a stored secret left out, but refused when the port changes without it, or the type changes; one invalid platform, or a name given twice, importing nothing; restoring the default platforms, adding only a missing one and changing none; administrators only |
| `90-macos` | The macOS default against a real Mac (skipped unless `T2_MACOS_HOST`, `T2_MACOS_USER` and `T2_MACOS_PASSWORD` name a throwaway standard account with Remote Login allowed, whose login keychain uses the same password): the account's password and its login keychain's both changed by the account itself, each checked on the Mac; a keychain on another password reported while the new password is kept; an account without a login keychain changed without a problem. Prints the account's last password and deletes its login keychain |

### Test data

Suites name everything they create `t2...` (Guacamole users, groups,
platforms and connections; accounts in the LDAP, Samba and MIT servers) and
remove it when they end, even after a failed check. They leave existing data
alone, except the SSH image's single account (`mysshtest`): its new password
is written back to the seeded "PAM test (Linux)" connection.

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
encrypted values pasted into connections). Do the same when adding a test for
a fix: a test that cannot fail proves nothing.
