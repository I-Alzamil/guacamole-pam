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

The extension has its own version (`1.0.0`, following semantic versioning),
and each build is made for one Guacamole release, 1.6.0 for now: Guacamole
skips extensions built for another release. To build for another release, set
`guacamole.version` in `pom.xml`.

## Installation

1. Build the extension with `mvn package`, or use a released jar, then copy
   `guacamole-pam-<version>.jar` into `GUACAMOLE_HOME/extensions/`.
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
unzip -p guacamole-pam-<version>.jar schema/postgresql.sql | psql -U <owner> -d <guacamole database>
```

```sql
GRANT SELECT,INSERT,UPDATE,DELETE ON ALL TABLES IN SCHEMA public TO guacamole_user;
GRANT SELECT,USAGE ON ALL SEQUENCES IN SCHEMA public TO guacamole_user;
```

Do the same after upgrading to a version that changes the tables: until then,
connections stored in the database can't be opened, as above.

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

Each server keeps its own pool of up to 10 database connections, besides
Guacamole's own, plus one for each rotation running. Change the limit with
`pam-database-max-connections` in `guacamole.properties`, keeping the total
across servers within PostgreSQL's `max_connections`.

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
way, so every connection shows its password as a token.

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
      org.apache.guacamole.pam.crypto.SecretCipher pending-password
```

The last argument is the kind of value: `pending-password`,
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
  decide whose password its platform rotates, and where), its protocol, or
  the guacd it is opened through (guacd receives the password). Other users
  who may create or edit connections can still change everything else.
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
- **Deleting a connection keeps its history.** Its checkouts and requests
  stay in the history under the name it had. Deleting it ends its active
  checkouts ("connection deleted"), closing their sessions, and cancels its
  requests awaiting approval.
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
  or none. Platforms are matched by name: a platform that already exists makes
  the import fail, unless **Update platforms that already exist** is ticked.
  Updated platforms keep their stored passwords, unless where they are sent
  changes. A new platform that needs a password can be given it among its
  settings in the file, such as `"winrm-admin-password"`.
- Approvers see a yellow badge counting requests awaiting their decision.
  Administrators also see a red badge counting failed rotations. Each user can
  turn either off under **Preferences → Notification badges**.

### Who may approve

Tick **Can approve requests** in the Permissions section of a user or user
group. Then tick **Approve** next to the connections or connection groups they
may approve in the editor's connections list. A connection group covers every
connection in it, including ones added later. Set how many distinct approvers a
connection needs in its *Access requests* section.

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
  (LDAP), realm or KDC (Kerberos), or port or CA certificates (WinRM) needs
  its administrator password entered again, so whoever may edit platforms
  can't have it sent to a server of their choosing. WinRM hosts are set on
  each connection, which only administrators can change.
- **Editors can read passwords, unless a key is set.** Users with *edit*
  permission on a connection can read its parameters, including its password.
  With a key set, they see passwords and keys only as tokens. They can still
  change a connection's other parameters, and some protocols have parameters
  that could send the password elsewhere (such as its hostname, or a VNC
  repeater, unless the connection is managed), so give edit permission on
  sensitive connections and Accounts to administrators only.
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
- **WinRM needs HTTPS, and checks each host's certificate.** WinRM platforms
  connect over HTTPS only (port 5986 by default), and log in with NTLM bound
  to the TLS channel, so they work whatever the host's `CbtHardeningLevel`
  (`Strict` recommended). With CA certificates on the platform, a host's
  certificate must be issued by one of them and name the host. Without any,
  like SSH host keys, the certificate is trusted on first contact and required
  from then on. Either way, a fingerprint in the connection's **Trusted
  certificate** field is required instead. Revocation isn't checked. See
  [Setting up WinRM over HTTPS](#setting-up-winrm-over-https). Passwords are
  sent on PowerShell's input, never on a
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
