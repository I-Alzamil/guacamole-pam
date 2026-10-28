# Settings and notifications

## Settings

The **PAM Settings** tab (administrators only) holds the settings shared by
every Guacamole server using the database: whether administrators bypass
requests, or need approvals, and whether and how many times checkouts may be
extended by default. They're stored in the database (`pam_setting`), apply without a
restart, and reach every server within 5 seconds. Each change is logged with
who made it. Secrets set there, such as a mail server's password, are
encrypted like other stored secrets, and never shown again: leave the field
empty to keep one, or tick **Remove**. **Restore defaults** resets one
section.

Four of them can also be given in `guacamole.properties`
(`pam-admin-bypass-requests`, `pam-admin-require-approvals`,
`pam-extensions-enabled`, `pam-max-extensions`, or their `PAM_*` variables in
the Docker image), to set them up front. A
value set there is imported once, by the first server reading the settings,
unless the setting was already decided in the database; from then on it's
ignored, with a warning in the log until removed.

Some settings stay in each server's `guacamole.properties`, as they're needed
to reach the database, or protect what it stores: `pam-database`,
`pam-database-max-connections` and the `pam-encryption-*` keys: keep them
alike on every server.

## Syslog

The **Syslog** section of the **PAM Settings** tab sends every PAM event to a
syslog server as it happens, so a SIEM sees who requested, approved, checked
out, connected to and viewed what. It's off by default. Each Guacamole server
sends the events that happened on it, so with the HA module each event is
sent once.

Events are rotations (succeeded or failed); requests submitted, approved,
granted, denied, cancelled and expired undecided; checkouts started,
extended, released, expired and revoked; passwords viewed; sessions started
and ended; a server going on standby and working again; and changes to the
PAM settings. Passwords are never sent.

- **Transport**: TLS (RFC 5425, the default, port 6514) checks that the
  server's certificate is trusted and names the host set; paste the CA
  certificates that issued it, in PEM, unless Java already trusts them. TCP
  (port 514 usually) sends in the clear; UDP also loses messages silently
  when the server is down.
- **Format**: RFC 5424, framed by length over TLS and TCP (RFC 6587). The
  MSGID is the event, and the message a sentence followed by the event's
  fields as `name="value"` pairs, which log servers and SIEMs split without
  configuration:

  ```
  <85>1 2026-10-27T10:00:00.123Z guac1 guacamole-pam - checkout-started - User "bob" checked out "web01". event="checkout-started" user="bob" connection="web01" connection-id="3" checkout="12" starts="2026-10-27T10:00:00.120Z" ends="2026-10-27T11:00:00.120Z" remote-host="10.0.0.5" reason="Ticket 4521"
  ```

  Fields: `user` (whose request, checkout or session), `actor` (who decided,
  revoked or changed), `connection`, `connection-id`, `request`, `checkout`,
  `minutes` (of an extension), `approvals` and `approvals-required`,
  `starts`, `ends`, `remote-host`, `reason`, `detail`. Severities: error for
  failed rotations, warning for revoked checkouts and standby, notice for
  checkouts, grants, denials, viewed passwords and setting changes,
  informational otherwise. The facility is `authpriv` unless set.
  Messages are cut at 8 KB.
- **Delivery**: each server queues up to 1,000 events, sent one at a time on
  a connection kept open. An event that can't be sent is tried again after 2,
  5 and 10 seconds, then dropped; the log says when sending fails, and when it
  works again. **Send a test message** sends one with the saved settings, and
  says why it couldn't.

## Email

The **Email** section of the **PAM Settings** tab emails PAM events, through
your mail server, to those they concern, at the email address of their
Guacamole profile. It's off by default.

- **Administrators** receive every event (the same as syslog).
- **Approvers** receive requests awaiting their approval, the other
  approvers' approvals and denials of requests for their connections, and
  those requests expiring undecided.
- **Users** receive the approval or denial of their requests, or their
  expiry undecided, and the end of their access: expired, or ended by an
  administrator.
- Nobody is emailed what they did themselves. Each user receives an event
  once, and can turn each kind off under **Preferences → Email
  notifications**, which shows the address emails go to.
- **Additional recipient** adds an address receiving every event, as
  administrators do, such as a security team's mailbox; **Guacamole address** adds
  links to Guacamole, such as to the Approvals tab.

Emails are plain text, and never contain a password. The connection to the
mail server requires STARTTLS by default (a server not offering it is
refused), or uses TLS from the start, checking the server's certificate and
name either way (paste the CA certificates, in PEM, unless Java trusts
them); unencrypted is offered last. The mail server's password is encrypted
like other stored secrets. **Send a test email** sends one to your own
address with the saved settings, and says why it couldn't. Delivery is as
for syslog: queued, and tried again for a few seconds.

### Email templates and languages

The **Email Templates** tab (administrators only) holds the languages emails
are written in. English is built in; others are added there, or imported.
Each user receives their emails in the language they choose under
**Preferences → Email notifications**, or in the **Default language** of
the PAM Settings tab, which also applies to the extra address. A language
whose users are deleted leaves them the default one.

Each language has:

- **Templates**: a subject and text for each kind of email: requests
  awaiting approval, decisions, access ending, and everything else.
  Placeholders such as `{user}`, `{connection}`, `{reason}` or `{starts}`
  are replaced by the event's values, as plain text (a value is never read
  as a template); `{summary}`, `{details}`, `{action}` (what to do next,
  with a link), `{link}` and `{why}` (why the recipient receives it, and
  how to stop) are the parts of the built-in text. The tab lists every
  placeholder, refuses a mistyped one, and previews each kind with a
  sample event. Write `{{` and `}}` for a brace.
- **Messages**: what PAM writes into them, in that language: the sentence
  of each event, the labels of the details, what to do next and why.

A field left empty takes English (for English, the built-in text), shown in
it, so a partial translation still sends complete emails. Details PAM
writes are in the language too; those it passes on, such as a target
system's error when a rotation fails, stay as received, as in the log.
Times are shown in the **Time zone** of the PAM Settings tab (UTC unless
set), with their offset from UTC.

**Export** saves a language as a JSON file, complete, to translate
elsewhere; **Import** adds one from such a file, asking before replacing a
language of the same code. English can be changed, and **Restore built-in**
brings back what the extension ships; it can't be deleted. Languages are
stored in the database (`pam_email_language`), so every server has them
within seconds; each change is logged, and sent to syslog and
administrators like other setting changes.

Approvers and administrators are found in Guacamole's database: users and
groups with the approval permission or the **Administer system**
permission, and the members of those groups. Memberships stored in the
database count, and so do those another extension, such as LDAP, gave a
user when they last logged in (kept in `pam_login_group`): a group of the
same name in the database, holding the permission, then reaches them. A
user who left such a group still receives its emails until they next log
in.
