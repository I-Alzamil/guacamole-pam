# Access, requests and approvals

How connections behave once the extension is installed, and who may approve
requests.

## After installing

- **Every connection requires a request by default**, including connections
  that already existed. To keep a connection usable as before, tick **Allow
  access without a request** in its *Access requests* section.
- **Administrators skip approvals, but still give a reason** when a connection
  or Account requires a request, so their access is in the history like
  anyone else's. To let administrators connect and check out Accounts without
  any request instead (logged), tick **Administrators bypass requests** on
  the **PAM Settings** tab.
- **Extensions are allowed by default**, twice per checkout. Each
  connection's *Access requests* section can allow or refuse them, and set
  how many and how long. The default for every connection is set on the
  **PAM Settings** tab.
- Only administrators can change a connection's *Password management* and
  *Access requests* sections, platforms, or who may approve. Nor can anyone
  else change, on a connection whose password is managed:
  - its credentials (username, password, domain, private key and
    passphrase), which decide whose password its platform rotates;
  - where it connects, so where guacd sends the password: its hostname and
    port, an RDP gateway, SFTP, a VNC repeater;
  - how it checks the server: SSH's host key, RDP's security mode and
    certificate settings, Kubernetes' TLS settings; and where Telnet types
    the credentials (its prompt patterns);
  - what it runs as the account when a session opens: SSH's command, RDP's
    initial program and RemoteApp, Kubernetes' command;
  - its protocol, and the guacd it is opened through (guacd receives the
    password).

  Other users who may create or edit connections can still change
  everything else, such as display and recording settings.
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
- **Rotations wait for sessions, and sessions for rotations.** Automatic
  rotations wait until a connection has no open session or checkout, and a
  session or checkout of a connection being rotated is refused until the
  rotation ends ("Please try again in a moment"). A session ending as its
  server stops still gets its after-use rotation, from the server working
  next.
- Balancing connection groups refuse to connect when one of their
  connections requires a request, is an Account, or has its password
  managed: open those connections directly.
- **Deleting a connection keeps its history.** Its checkouts and requests
  stay in the history under the name it had. Deleting it ends its active
  checkouts ("connection deleted"), closing their sessions, and cancels its
  requests awaiting approval and its reservations.
- **Revoking access ends open sessions.** Within 15 seconds of a user losing
  the permission to read a connection, or of its deletion, their sessions of
  it close (Guacamole alone lets them run until they end). Removing a user's
  administrator permission takes effect at once, without them logging in
  again.
- Administrators get four new settings tabs: **Platforms**, **Password
  Rotation**, **Checkouts** and **Approvals**. Approvers who aren't
  administrators only get **Approvals**, for the connections their permission
  covers.
- Approvers see a yellow badge counting requests awaiting their decision.
  Administrators also see a red badge counting failed rotations. Each user can
  turn either off under **Preferences → Notification badges**.

## Who may approve

Tick **Can approve requests** in the Permissions section of a user or user
group. Then tick **Approve** next to the connections or connection groups they
may approve in the editor's connections list. A connection group covers every
connection in it, including ones added later. Set how many distinct approvers a
connection needs in its *Access requests* section.
