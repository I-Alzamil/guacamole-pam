#!/bin/bash
# Importing platforms, as exported from the Platforms page: all or nothing,
# by name, updates keeping stored secrets unless where they are sent changes,
# and only for administrators.

SSH_SCRIPT='passwd\n@expect assword:\n<OLDPASS>\n@expect assword:\n<NEWPASS>\n@expect assword:\n<NEWPASS>\n'

# import JSON-OF-PLATFORMS [update] -> "STATUS BODY"
import_platforms() { api POST "$PAM/platforms/import" "${3:-$ADMIN}" "{\"platforms\":$1,\"update\":${2:-false}}"; }

# outcomes "STATUS BODY" -> "imported: NAME=OUTCOME ..."
outcomes() {
    json_get "${1#* }" "('imported' if d['imported'] else 'refused') + ': ' + ' '.join(r['name'] + '=' + r['outcome'] for r in d['results'])"
}

# message_for "STATUS BODY" NAME -> the message of that platform's result
message_for() { json_get "${1#* }" "[r.get('message') for r in d['results'] if r['name'] == '$2'][0]"; }

platform_field() { json_get "$(api GET "$PAM/platforms/$(platform_id "$1")" "$ADMIN" | cut -d' ' -f2-)" "$2"; }

cleanup_platform() { local id; id=$(platform_id "$1"); [ -n "$id" ] && api DELETE "$PAM/platforms/$id" "$ADMIN" >/dev/null; }
for name in "t2 import ssh" "t2 import winrm" "t2 import extra"; do
    cleanup_platform "$name"
    on_cleanup "cleanup_platform '$name'"
done

SSH_PLATFORM="{\"name\":\"t2 import ssh\",\"description\":\"first\",\"type\":\"ssh\",\"settings\":{\"script\":\"$SSH_SCRIPT\"},
    \"policy\":{\"rotation-mode\":\"periodic\",\"rotation-interval\":\"24\"}}"
WINRM_PLATFORM='{"name":"t2 import winrm","type":"winrm","settings":{"winrm-admin-username":"Administrator",
    "winrm-admin-password":"Imported-Pw1!"},"policy":{}}'

# ---------------------------------------------------------------- creating
section "Importing new platforms"
R=$(import_platforms "[$SSH_PLATFORM,$WINRM_PLATFORM]")
check "both are created" "imported: t2 import ssh=CREATED t2 import winrm=CREATED" "$(outcomes "$R")"
check "...with their settings and policy" "first periodic 24" \
    "$(platform_field "t2 import ssh" "d['description'] + ' ' + d['policy']['rotation-mode'] + ' ' + d['policy']['rotation-interval']")"
check "...and the secret given in the file stored, not shown" "['winrm-admin-password'] None" \
    "$(platform_field "t2 import winrm" "str(d.get('storedSecrets')) + ' ' + str(d['settings'].get('winrm-admin-password'))")"

# ---------------------------------------------------------------- existing
section "Platforms that already exist"
R=$(import_platforms "[$SSH_PLATFORM]")
check "without updating, the import is refused" "refused: t2 import ssh=INVALID" "$(outcomes "$R")"
check_contains "...saying it exists" "exists" "$(message_for "$R" "t2 import ssh")"

UPDATED=$(printf '%s' "[$SSH_PLATFORM,$WINRM_PLATFORM]" | sed 's/"first"/"second"/; s/"Imported-Pw1!"/""/')
R=$(import_platforms "$UPDATED" true)
check "with updating, both are updated" "imported: t2 import ssh=UPDATED t2 import winrm=UPDATED" "$(outcomes "$R")"
check "...the description changed" second "$(platform_field "t2 import ssh" "d['description']")"
check "...the secret left out kept" "['winrm-admin-password']" "$(platform_field "t2 import winrm" "str(d.get('storedSecrets'))")"

MOVED='[{"name":"t2 import winrm","type":"winrm","settings":{"winrm-port":"15986","winrm-admin-username":"Administrator"},"policy":{}}]'
R=$(import_platforms "$MOVED" true)
check "another port without the secret is refused" "refused: t2 import winrm=INVALID" "$(outcomes "$R")"
check_contains "...as where the stored secret goes would change" "enter it again" "$(message_for "$R" "t2 import winrm")"

R=$(import_platforms '[{"name":"t2 import ssh","type":"winrm","settings":{},"policy":{}}]' true)
check "an update cannot change the type" "refused: t2 import ssh=INVALID" "$(outcomes "$R")"

# ---------------------------------------------------------------- all or nothing
section "All or nothing"
R=$(import_platforms "[{\"name\":\"t2 import extra\",\"type\":\"ssh\",\"settings\":{\"script\":\"$SSH_SCRIPT\"},\"policy\":{}},
    {\"name\":\"t2 import broken\",\"type\":\"nonsense\",\"settings\":{},\"policy\":{}}]")
check "one invalid platform refuses the import" "refused: t2 import extra=CREATED t2 import broken=INVALID" "$(outcomes "$R")"
check "...so the valid one was not created" "" "$(platform_id "t2 import extra")"
R=$(import_platforms "[$SSH_PLATFORM,$SSH_PLATFORM]" true)
check "a name given twice is refused" "refused: t2 import ssh=UPDATED t2 import ssh=INVALID" "$(outcomes "$R")"
check "an empty import is refused" 400 "$(status_of "$(import_platforms '[]')")"

# ---------------------------------------------------------------- permission
section "Administrators only"
create_user t2-platform-user t2-platform-user-pw
USER_TOKEN=$(token t2-platform-user t2-platform-user-pw)
check "a user who is not an administrator cannot import" 403 \
    "$(status_of "$(import_platforms "[$SSH_PLATFORM]" true "$USER_TOKEN")")"

# ---------------------------------------------------------------- defaults
section "Restoring the default platforms"

# rename_platform OLD NEW: connections refer to platforms by identifier
rename_platform() {
    local id body
    id=$(platform_id "$1")
    body=$(api GET "$PAM/platforms/$id" "$ADMIN" | cut -d' ' -f2- | python3 -I -c "
import sys,json; p=json.load(sys.stdin); print(json.dumps({'name':sys.argv[1],'description':p.get('description'),
    'type':p['type'],'settings':p['settings'],'policy':p['policy']}))" "$2")
    api PUT "$PAM/platforms/$id" "$ADMIN" "$body" >/dev/null
}

LINUX_MODIFIED=$(platform_field "Unix" "d['lastModified']")
R=$(api POST "$PAM/platforms/defaults" "$ADMIN")
check "with all there, nothing is added" "imported: Unix=SKIPPED macOS=SKIPPED Windows=SKIPPED" "$(outcomes "$R")"
check "...nor changed" "$LINUX_MODIFIED" "$(platform_field "Unix" "d['lastModified']")"

WINDOWS=$(platform_id "Windows")
rename_platform "Windows" "t2 renamed default"
on_cleanup "cleanup_platform 'Windows'; rename_platform 't2 renamed default' 'Windows'"
R=$(api POST "$PAM/platforms/defaults" "$ADMIN")
check "the missing one is added back" "imported: Unix=SKIPPED macOS=SKIPPED Windows=CREATED" "$(outcomes "$R")"
check "...as a new platform" yes "$([ -n "$(platform_id "Windows")" ] && [ "$(platform_id "Windows")" != "$WINDOWS" ] && echo yes)"
check_contains "...with its script" "net user <USER> *" "$(platform_field "Windows" "d['settings']['script']")"
check "a user who is not an administrator cannot restore them" 403 \
    "$(status_of "$(api POST "$PAM/platforms/defaults" "$USER_TOKEN")")"
