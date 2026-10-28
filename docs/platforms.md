# Platforms and password rotation

A platform says how a connection's password is changed (its type), when, and
what new passwords look like (see the [overview](overview.md)). Platforms are
edited on the **Platforms** tab, and chosen in a connection's *Password
management* section.

## Managing platforms

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

## Password policies

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

## Database accounts

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

## Setting up WinRM over HTTPS

Windows doesn't listen for WinRM over HTTPS by default, and WinRM platforms
need it (see [Security notes](security.md)). Each host needs an HTTPS
listener with a certificate. How the extension trusts that certificate is up
to the platform:

| Platform's *CA certificates* | Host certificates | Renewals |
|---|---|---|
| Empty | Any, such as self-signed. The first one seen is trusted from then on, or the fingerprint pinned on the connection | A new certificate fails until its fingerprint is pinned on the connection |
| Your CA's certificate | Issued by that CA, naming the host as Guacamole reaches it | Trusted as they come |

### One host, with a self-signed certificate

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

### Many hosts, with certificates from Active Directory Certificate Services

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
