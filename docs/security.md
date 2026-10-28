# Security notes

- **Secrets stay on the server.** Platform secrets, such as an LDAP rotation
  account's password, are never sent to the browser. They're stored unencrypted
  in the database unless a key is set (see
  [Encrypting stored secrets](encryption.md)), like
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
  [Setting up WinRM over HTTPS](platforms.md#setting-up-winrm-over-https). Passwords are
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
