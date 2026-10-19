#!/bin/bash
# What users other than administrators can and cannot do: change how a
# connection is managed, or the account and host it names; connect through
# balancing groups around request checks; use administrator endpoints; read
# platform secrets.

MIT_ADMIN_PASSWORD="KdcAdm1n-Pass"

section "Setup"
podman exec mykdctest kadmin.local -q "addprinc -pw T2-Sec-Start1! t2sec" >/dev/null 2>&1
podman exec mykdctest kadmin.local -q "addprinc -pw T2-Victim-Start1! t2victim" >/dev/null 2>&1
on_cleanup "podman exec mykdctest kadmin.local -q 'delprinc -force t2sec'"
on_cleanup "podman exec mykdctest kadmin.local -q 'delprinc -force t2victim'"

create_platform KERBEROS "{\"name\":\"t2 security kerberos\",\"type\":\"kerberos\",\"settings\":{\"kerberos-realm\":\"EXAMPLE.ORG\",
    \"kerberos-kdc\":\"mykdctest\",\"kerberos-admin-principal\":\"admin/admin\",\"kerberos-admin-password\":\"$MIT_ADMIN_PASSWORD\"},
    \"policy\":{\"rotation-mode\":\"never\"}}"
LINUX=$(platform_id "Linux (passwd)")
create_connection MANAGED "{\"name\":\"t2 managed account\",\"parentIdentifier\":\"ROOT\",\"protocol\":\"pam-account\",
    \"parameters\":{\"username\":\"t2sec\",\"password\":\"T2-Sec-Start1!\"},\"attributes\":{\"pam-platform\":\"$KERBEROS\"}}"
create_connection MANAGED_SSH "{\"name\":\"t2 managed ssh\",\"parentIdentifier\":\"ROOT\",\"protocol\":\"ssh\",
    \"parameters\":{\"hostname\":\"mysshtest\",\"port\":\"22\",\"username\":\"nobody\",\"password\":\"unused\"},
    \"attributes\":{\"pam-platform\":\"$LINUX\",\"pam-request-exempt\":\"true\",\"pam-rotation-mode\":\"never\"}}"
create_connection UNMANAGED "{\"name\":\"t2 stored account\",\"parentIdentifier\":\"ROOT\",\"protocol\":\"pam-account\",
    \"parameters\":{\"username\":\"svc-stored\",\"password\":\"Stored-Pw1!\"},\"attributes\":{}}"

# An editor: may update these connections and create others, but is no administrator
create_user t2-editor t2-editor-pw
P='[{"op":"add","path":"/systemPermissions","value":"CREATE_CONNECTION"}'
for c in $MANAGED $MANAGED_SSH $UNMANAGED; do
    P="$P,{\"op\":\"add\",\"path\":\"/connectionPermissions/$c\",\"value\":\"READ\"},{\"op\":\"add\",\"path\":\"/connectionPermissions/$c\",\"value\":\"UPDATE\"}"
done
grant t2-editor "$P]"
EDITOR=$(token t2-editor t2-editor-pw)
check "setup: editor and connections exist" yes "$([ -n "$EDITOR" ] && [ -n "$MANAGED$MANAGED_SSH$UNMANAGED" ] && echo yes)"

# ---------------------------------------------------------------- managed connections
section "An editor cannot change whose password is managed, or where"
REFUSED_PARAMS="403 Only administrators can change the username, hostname or port of a connection whose password is managed."
REFUSED_ATTRS="403 Only administrators can change password management or access requests."
outcome() { printf '%s %s' "$(status_of "$1")" "$(message_of "$1")" | sed 's/ $//'; }

check "Account: username to another principal" "$REFUSED_PARAMS" "$(outcome "$(edit_connection "$EDITOR" "$MANAGED" '{"username":"t2victim"}')")"
check "Account: username removed" "$REFUSED_PARAMS" "$(outcome "$(edit_connection "$EDITOR" "$MANAGED" '{"username":null}')")"
check "Account: hostname added" "$REFUSED_PARAMS" "$(outcome "$(edit_connection "$EDITOR" "$MANAGED" '{"hostname":"evil.example"}')")"
check "Account: port added" "$REFUSED_PARAMS" "$(outcome "$(edit_connection "$EDITOR" "$MANAGED" '{"port":"88"}')")"
check "SSH: hostname to another host" "$REFUSED_PARAMS" "$(outcome "$(edit_connection "$EDITOR" "$MANAGED_SSH" '{"hostname":"evil.example"}')")"
check "SSH: port" "$REFUSED_PARAMS" "$(outcome "$(edit_connection "$EDITOR" "$MANAGED_SSH" '{"port":"2222"}')")"
check "SSH: username" "$REFUSED_PARAMS" "$(outcome "$(edit_connection "$EDITOR" "$MANAGED_SSH" '{"username":"root"}')")"
check "managed: platform removed" "$REFUSED_ATTRS" "$(outcome "$(edit_connection "$EDITOR" "$MANAGED" '' '{"pam-platform":null}')")"
check "stored: platform added" "$REFUSED_ATTRS" "$(outcome "$(edit_connection "$EDITOR" "$UNMANAGED" '' "{\"pam-platform\":\"$KERBEROS\"}")")"
check "stored: allowed without a request" "$REFUSED_ATTRS" "$(outcome "$(edit_connection "$EDITOR" "$UNMANAGED" '' '{"pam-request-exempt":"true"}')")"
R=$(api POST "$DATA/connections" "$EDITOR" "{\"name\":\"t2 editor managed\",\"parentIdentifier\":\"ROOT\",\"protocol\":\"pam-account\",
    \"parameters\":{\"username\":\"t2victim\"},\"attributes\":{\"pam-platform\":\"$KERBEROS\"}}")
check "creating a managed connection" "$REFUSED_ATTRS" "$(outcome "$R")"
check "the managed account still names t2sec" t2sec "$(parameter "$MANAGED" username)"
check "the managed SSH connection still names mysshtest" mysshtest "$(parameter "$MANAGED_SSH" hostname)"

section "...but can still edit everything else"
check "managed: saved unchanged" 204 "$(status_of "$(edit_connection "$EDITOR" "$MANAGED")")"
check "managed: renamed" 204 "$(status_of "$(edit_connection "$EDITOR" "$MANAGED_SSH" '' '' 't2 managed ssh renamed')")"
check "managed: another parameter" 204 "$(status_of "$(edit_connection "$EDITOR" "$MANAGED_SSH" '{"font-size":"14"}')")"
check "stored: username" 204 "$(status_of "$(edit_connection "$EDITOR" "$UNMANAGED" '{"username":"svc-stored-2"}')")"
R=$(api POST "$DATA/connections" "$EDITOR" '{"name":"t2 editor stored","parentIdentifier":"ROOT","protocol":"pam-account","parameters":{"username":"x"},"attributes":{}}')
check "creating a stored connection" 200 "$(status_of "$R")"
CREATED=$(json_get "${R#* }" "d.get('identifier')"); [ -n "$CREATED" ] && on_cleanup "api DELETE '$DATA/connections/$CREATED' '$ADMIN'"
check "an administrator may change a managed connection's username" "204 204" \
    "$(status_of "$(edit_connection "$ADMIN" "$MANAGED" '{"username":"t2victim"}')") $(status_of "$(edit_connection "$ADMIN" "$MANAGED" '{"username":"t2sec"}')")"

section "The original attack, end to end"
edit_connection "$EDITOR" "$MANAGED" '{"username":"t2victim"}' >/dev/null
check "rotation by the administrator succeeds" SUCCESS "$(rotate "$MANAGED" | cut -d: -f1)"
check "...it rotated t2sec, whose new password works" yes "$(mit_accepts t2sec "$(parameter "$MANAGED" password)")"
check "...and left t2victim's password untouched" yes "$(mit_accepts t2victim 'T2-Victim-Start1!')"

# ---------------------------------------------------------------- balancing groups
section "Balancing groups do not route around checks"
create_group BALANCED_GATED '{"name":"t2 balancing gated","parentIdentifier":"ROOT","type":"BALANCING","attributes":{}}'
create_group BALANCED_MANAGED '{"name":"t2 balancing managed","parentIdentifier":"ROOT","type":"BALANCING","attributes":{}}'
create_group BALANCED_OPEN '{"name":"t2 balancing open","parentIdentifier":"ROOT","type":"BALANCING","attributes":{}}'
create_group FOLDER '{"name":"t2 folder","parentIdentifier":"ROOT","type":"ORGANIZATIONAL","attributes":{}}'
ssh_in() { # VARIABLE NAME GROUP ATTRIBUTES
    create_connection "$1" "{\"name\":\"$2\",\"parentIdentifier\":\"$3\",\"protocol\":\"ssh\",
        \"parameters\":{\"hostname\":\"mysshtest\",\"port\":\"22\",\"username\":\"nobody\",\"password\":\"unused\"},\"attributes\":$4}"
}
ssh_in IN_GATED "t2 in gated" "$BALANCED_GATED" '{}'
ssh_in IN_MANAGED "t2 in managed" "$BALANCED_MANAGED" "{\"pam-request-exempt\":\"true\",\"pam-platform\":\"$LINUX\",\"pam-rotation-mode\":\"never\"}"
ssh_in IN_OPEN "t2 in open" "$BALANCED_OPEN" '{"pam-request-exempt":"true"}'
ssh_in IN_FOLDER "t2 in folder" "$FOLDER" '{"pam-request-exempt":"true"}'

create_user t2-viewer t2-viewer-pw
P='['
for g in $BALANCED_GATED $BALANCED_MANAGED $BALANCED_OPEN $FOLDER; do P="$P{\"op\":\"add\",\"path\":\"/connectionGroupPermissions/$g\",\"value\":\"READ\"},"; done
for c in $IN_GATED $IN_MANAGED $IN_OPEN $IN_FOLDER; do P="$P{\"op\":\"add\",\"path\":\"/connectionPermissions/$c\",\"value\":\"READ\"},"; done
grant t2-viewer "${P%,}]"
VIEWER=$(token t2-viewer t2-viewer-pw)

check_contains "a group over a connection requiring a request is refused" "400 Connection group \"t2 balancing gated\" balances over" "$(tunnel "$VIEWER" "$BALANCED_GATED" g)"
check_contains "...for administrators too" "400 Connection group" "$(tunnel "$ADMIN" "$BALANCED_GATED" g)"
check_contains "a group over a managed connection is refused" "400 Connection group \"t2 balancing managed\"" "$(tunnel "$VIEWER" "$BALANCED_MANAGED" g)"
check "a group over unchecked connections connects" 200 "$(tunnel "$VIEWER" "$BALANCED_OPEN" g)"
check "a folder's connection opens as usual" 200 "$(tunnel "$VIEWER" "$IN_FOLDER" c)"
check "the connection tree still loads" 200 "$(status_of "$(api GET "$DATA/connectionGroups/ROOT/tree" "$VIEWER")")"

# ---------------------------------------------------------------- administrator endpoints
section "Administrator endpoints and secrets"
for endpoint in "GET $PAM/connections" "POST $PAM/connections/$MANAGED/rotate" "GET $PAM/checkouts/active" \
        "GET $PAM/checkouts/history" "GET $PAM/platforms/$KERBEROS" "POST $PAM/validate"; do
    check "not an administrator: ${endpoint%% *} ${endpoint##*/pam/}" 403 "$(status_of "$(api ${endpoint%% *} "${endpoint#* }" "$VIEWER" '{}')")"
done
check "not an administrator: creating a platform" 403 "$(status_of "$(api POST "$PAM/platforms" "$VIEWER" '{"name":"x","type":"ssh","settings":{},"policy":{}}')")"
LISTED=$(api GET "$PAM/platforms" "$VIEWER" | cut -d' ' -f2-)
check "not an administrator: platforms are listed by name and type only" "kerberos, no settings, no policy, no description" \
    "$(json_get "$LISTED" "(lambda p: p['type'] + (', no settings' if not p.get('settings') else ', SETTINGS') + (', no policy' if not p.get('policy') else ', POLICY') + (', no description' if not p.get('description') else ', DESCRIPTION'))([p for p in d if p['name']=='t2 security kerberos'][0])")"
DETAIL=$(api GET "$PAM/platforms/$KERBEROS" "$ADMIN" | cut -d' ' -f2-)
case "$DETAIL" in *"$MIT_ADMIN_PASSWORD"*) fail "platform secrets are never returned" "found in: $DETAIL";; *) pass "platform secrets are never returned, even to administrators";; esac
check "...only which ones are stored" "['kerberos-admin-password']" "$(json_get "$DETAIL" "d.get('storedSecrets')")"
