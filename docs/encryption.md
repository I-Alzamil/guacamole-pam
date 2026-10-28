# Encrypting stored secrets

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
they're saved. Without a key, secrets are stored unencrypted.

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

## Reading an encrypted secret

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
