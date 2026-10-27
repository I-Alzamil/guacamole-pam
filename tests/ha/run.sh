#!/bin/bash
# Checks the HA module against each database given (every one by default),
# with the two Guacamole servers of lab/ha.sh sharing it: sessions are
# counted and limited on both, listed, ended, joined and shared from either;
# logins, TOTP codes and failed logins are known to both, and recordings of
# one are shown by the other; and the sessions of a server that stopped are
# freed, at once when it stops cleanly, after the timeout when it dies.
#
#   tests/ha/run.sh [postgresql] [mysql] [mariadb] [sqlserver]
#
# Start them first: lab/ha.sh start DATABASE...
# Exits with 0 when every check passed.

cd "$(dirname "$0")" || exit 1
. ./lib.sh

GUAC_ADMIN=guacadmin
GUAC_ADMIN_PASSWORD=guacadmin

# How long a dead server's sessions may still count, with a margin
STALE_WAIT=75

# How long Guacamole takes to close the tunnel of a session ended by its
# client over HTTP, which ends the session for it and for this extension
ENDED_WAIT=25

# How long a login ended on one server may go on on the other, with a margin
LOGOUT_WAIT=20

# How long a server takes to list a new recording for the others, with a
# margin
RECORDING_WAIT=60

# The TOTP secret of the test user who has one, and the ban of lab/ha.sh
TOTP_SECRET=JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP
BAN_ATTEMPTS=3
BAN_SECONDS=20

port_of() {
    case "$1" in postgresql) echo 8090;; mysql) echo 8092;; mariadb) echo 8094;; sqlserver) echo 8096;; esac
}

# connection NAME ATTRIBUTES-JSON [PARENT] [PARAMETERS-JSON] -> its identifier.
# Open without an access request, as PAM would otherwise require one
connection() {
    local attributes=${2%\}}
    [ "$attributes" = "{" ] || attributes+=","
    attributes+='"pam-request-exempt":"true"}'
    json_get "$(api POST "$DATA/connections" "$ADMIN" "{\"name\":\"$1\",\"parentIdentifier\":\"${3:-ROOT}\",
        \"protocol\":\"ssh\",\"parameters\":{\"hostname\":\"mypamha-ssh\",\"port\":\"2222\",\"username\":\"t2user\",
        \"password\":\"t2-ssh-pw\"${4:+,$4}},\"attributes\":$attributes}")" "d.get('identifier')"
}

# user_attribute USER NAME VALUE: sets an attribute in the database, as the
# TOTP extension keeps its keys
user_attribute() {
    sql "INSERT INTO guacamole_user_attribute (user_id, attribute_name, attribute_value) SELECT u.user_id,
        '$2', '$3' FROM guacamole_user u JOIN guacamole_entity e ON u.entity_id = e.entity_id
        WHERE e.name = '$1'" >/dev/null
}

grant_read() {
    api PATCH "$DATA/users/$1/permissions" "$ADMIN" "[{\"op\":\"add\",\"path\":\"/$2/$3\",\"value\":\"READ\"}]" \
        >/dev/null
}

suite() {

    DB=$1
    case "$DB" in mariadb) DS=mysql;; *) DS=$DB;; esac
    A=http://localhost:$(port_of "$DB")
    B=http://localhost:$(($(port_of "$DB") + 1))
    DATA=$A/api/session/data/$DS

    printf '\n######## %s\n' "$DB"
    if ! curl -sf -o /dev/null "$A/api/languages" || ! curl -sf -o /dev/null "$B/api/languages"; then
        fail "both servers answer" "start them: lab/ha.sh start $DB"
        return
    fi

    section "$DB: setup"
    ADMIN=$(token "$A" $GUAC_ADMIN $GUAC_ADMIN_PASSWORD)
    ADMIN_B=$(token "$B" $GUAC_ADMIN $GUAC_ADMIN_PASSWORD)
    for user in t2alice t2bob t2carol; do
        api POST "$DATA/users" "$ADMIN" \
            "{\"username\":\"$user\",\"password\":\"$user-pw\",\"attributes\":{}}" >/dev/null
    done
    user_attribute t2alice guac-totp-disabled true
    user_attribute t2bob guac-totp-disabled true
    user_attribute t2carol guac-totp-key-secret "$TOTP_SECRET"
    user_attribute t2carol guac-totp-key-confirmed true

    OPEN=$(connection "t2 open" '{}')
    SINGLE=$(connection "t2 single" '{"max-connections":"1"}')
    PER_USER=$(connection "t2 one per user" '{"max-connections-per-user":"1"}')
    GROUP=$(json_get "$(api POST "$DATA/connectionGroups" "$ADMIN" '{"name":"t2 balancing",
        "parentIdentifier":"ROOT","type":"BALANCING",
        "attributes":{"max-connections":"1","max-connections-per-user":"1"}}')" "d.get('identifier')")
    MEMBER=$(connection "t2 member" '{}' "$GROUP")
    RECORDED=$(connection "t2 recorded" '{}' ROOT \
        '"recording-path":"${HISTORY_PATH}/${HISTORY_UUID}","create-recording-path":"true"')
    VIEW=$(json_get "$(api POST "$DATA/sharingProfiles" "$ADMIN" "{\"name\":\"t2 view\",
        \"primaryConnectionIdentifier\":\"$OPEN\",\"parameters\":{\"read-only\":\"true\"},\"attributes\":{}}")" \
        "d.get('identifier')")
    for user in t2alice t2bob; do
        for c in $OPEN $SINGLE $PER_USER $RECORDED; do grant_read $user connectionPermissions "$c"; done
        grant_read $user connectionGroupPermissions "$GROUP"
    done
    # Bob may use the balancing group only, not the connection in it
    grant_read t2alice connectionPermissions "$MEMBER"
    grant_read t2alice sharingProfilePermissions "$VIEW"
    check "connections, a balancing group, a sharing profile and users created" yes \
        "$([ -n "$OPEN" ] && [ -n "$SINGLE" ] && [ -n "$PER_USER" ] && [ -n "$GROUP" ] && [ -n "$MEMBER" ] \
            && [ -n "$RECORDED" ] && [ -n "$VIEW" ] && echo yes)"

    ALICE_A=$(token "$A" t2alice t2alice-pw); ALICE_B=$(token "$B" t2alice t2alice-pw)
    BOB_A=$(token "$A" t2bob t2bob-pw); BOB_B=$(token "$B" t2bob t2bob-pw)
    check "the tables were created, both servers recorded" 2 \
        "$(sql "SELECT COUNT(*) FROM pam_ha_server" | tr -d '[:space:]')"

    section "$DB: sessions counted on both servers"
    check "Alice opens a session on server A" open "$(hold a1 "$A" "$ALICE_A" "$OPEN")"
    eventually "server B shows it in use by 1" 1 5 active "$B" "$ADMIN_B" "$OPEN"
    check "Bob opens one on server B" open "$(hold b1 "$B" "$BOB_B" "$OPEN")"
    eventually "server A shows it in use by 2" 2 5 active "$A" "$ADMIN" "$OPEN"
    check "...as recorded in the database" 2 \
        "$(sql "SELECT COUNT(*) FROM pam_ha_session WHERE connection_id = '$OPEN'" | tr -d '[:space:]')"
    release a1; release b1
    eventually "once both end, server B shows it unused" 0 $ENDED_WAIT active "$B" "$ADMIN_B" "$OPEN"

    section "$DB: a connection's limit on both servers"
    check "Alice holds the single-session connection on server A" open "$(hold a2 "$A" "$ALICE_A" "$SINGLE")"
    check_contains "Bob is refused on server B, as Guacamole refuses it" "refused" "$(hold b2 "$B" "$BOB_B" "$SINGLE")"
    check_contains "...saying it is in use" "This connection is in use." "$(cat "$T2_TMP/session-b2")"
    release a2
    eventually "once Alice ends it, Bob opens it on server B" open $ENDED_WAIT \
        hold_until_open b3 "$B" "$BOB_B" "$SINGLE"
    release b3

    section "$DB: a limit per user on both servers"
    check "Alice opens the one-per-user connection on server A" open "$(hold a3 "$A" "$ALICE_A" "$PER_USER")"
    check_contains "Alice is refused a second one on server B" "Connection already in use by this user." \
        "$(hold a4 "$B" "$ALICE_B" "$PER_USER")"
    check "Bob still opens one on server B" open "$(hold b4 "$B" "$BOB_B" "$PER_USER")"
    release a3; release b4
    eventually "...and once they end, both are counted as ended" 0 $ENDED_WAIT active "$B" "$ADMIN_B" "$PER_USER"

    section "$DB: a balancing group's limit on both servers"
    check "Alice opens the balancing group on server A" open "$(hold a5 "$A" "$ALICE_A" "$GROUP" g)"
    eventually "server B shows the group in use by 1" 1 5 active "$B" "$ADMIN_B" "$GROUP" g
    eventually "...and the connection Guacamole picked in it, too" 1 5 active "$B" "$ADMIN_B" "$MEMBER"
    check_contains "Bob is refused the group on server B" "This connection group is in use." \
        "$(hold b5 "$B" "$BOB_B" "$GROUP" g)"
    release a5
    eventually "once Alice ends it, the group is unused" 0 $ENDED_WAIT active "$B" "$ADMIN_B" "$GROUP" g
    check "Bob, who may use the group but not the connection in it, opens the group on server A" open \
        "$(hold b9 "$A" "$BOB_A" "$GROUP" g)"
    eventually "...server B shows the connection Guacamole picked in use, too" 1 5 active "$B" "$ADMIN_B" "$MEMBER"
    release b9
    eventually "...and once Bob ends it, unused" 0 $ENDED_WAIT active "$B" "$ADMIN_B" "$GROUP" g
    eventually "...and the single-session connection, for what follows" 0 $ENDED_WAIT active "$B" "$ADMIN_B" "$SINGLE"

    section "$DB: logins shared between servers"
    check "a login made on server A works on server B" t2alice "$(self_name "$B" "$ALICE_A")"
    check "...through the database it was made through, as the web application finds it" "$DS" \
        "$(json_get "$(curl -s -d "token=$ALICE_A" "$B/api/tokens")" "d.get('dataSource')")"
    check "...so the user's own profile and preferences show there" t2alice \
        "$(json_get "$(api GET "$B/api/session/data/$DS/users/t2alice" "$ALICE_A")" "d.get('username')")"
    check_contains "...with the user's connections" "\"$OPEN\"" \
        "$(api GET "$B/api/session/data/$DS/connections" "$ALICE_A")"
    check "...and opens sessions there" open "$(hold a10 "$B" "$ALICE_A" "$OPEN")"
    release a10
    eventually "...which end" 0 $ENDED_WAIT active "$B" "$ADMIN_B" "$OPEN"
    BOB_X=$(token "$A" t2bob t2bob-pw)
    check "Bob logs in on server A, his login works on server B" t2bob "$(self_name "$B" "$BOB_X")"
    api DELETE "$A/api/tokens/$BOB_X" "$BOB_X" >/dev/null
    check "Bob logs out on server A, his login ends there" "" "$(self_name "$A" "$BOB_X")"
    eventually "...and on server B within ${LOGOUT_WAIT}s" "" $LOGOUT_WAIT self_name "$B" "$BOB_X"

    section "$DB: active sessions of both servers"
    check "Alice opens a session on server A" open "$(hold a11 "$A" "$ALICE_A" "$OPEN")"
    eventually "server B lists it among its active sessions" t2alice 5 active_users "$B" "$ADMIN_B" "$OPEN"
    ALICE_SESSION=$(active_session "$A" "$ADMIN" "$OPEN" t2alice)
    check "...under the identifier server A gives it" "$ALICE_SESSION" \
        "$(active_session "$B" "$ADMIN_B" "$OPEN" t2alice)"
    check "Bob, who may use the connection, sees it on server B, without who opened it" None \
        "$(active_users "$B" "$BOB_B" "$OPEN")"
    check_contains "Bob may not end it from server B" "Permission denied" \
        "$(api PATCH "$B/api/session/data/$DS/activeConnections" "$BOB_B" \
            "[{\"op\":\"remove\",\"path\":\"/$ALICE_SESSION\"}]")"
    sleep 3
    check "...and it goes on" open "$(state a11)"
    check "the administrator joins it from server B" open "$(hold j1 "$B" "$ADMIN_B" "$ALICE_SESSION" a)"
    eventually "server A lists the joining session of server B too" 2 5 active_count "$A" "$ADMIN" "$OPEN"
    check "the administrator joins it from server A too, where it runs" open \
        "$(hold j2 "$A" "$ADMIN" "$ALICE_SESSION" a)"
    eventually "server B lists that joining session too" 3 5 active_count "$B" "$ADMIN_B" "$OPEN"
    api PATCH "$B/api/session/data/$DS/activeConnections" "$ADMIN_B" \
        "[{\"op\":\"remove\",\"path\":\"/$ALICE_SESSION\"}]" >/dev/null
    eventually "the administrator ends Alice's session from server B: it ends on server A" closed 10 state a11
    eventually "...with the sessions joining it" closed 10 state j1
    eventually "...on both servers" closed 10 state j2
    release a11; release j1; release j2
    eventually "...and neither server lists them" 0 $ENDED_WAIT active_count "$B" "$ADMIN_B" "$OPEN"

    section "$DB: share links open on either server"
    check "Alice opens a session on server A" open "$(hold a12 "$A" "$ALICE_A" "$OPEN")"
    ALICE_SESSION=$(active_session "$A" "$ADMIN" "$OPEN" t2alice)
    KEY=$(share_key "$(api GET "$A/api/session/tunnels/$ALICE_SESSION/activeConnection/sharingCredentials/$VIEW" \
        "$ALICE_A")")
    check "Alice shares it, read only" yes "$([ -n "$KEY" ] && echo yes)"
    # As server B does when server A is not heard from for a while
    SERVER_A=$(sql "SELECT server_id FROM pam_ha_session WHERE tunnel_id = '$ALICE_SESSION'" | tr -d '[:space:]')
    sql "DELETE FROM pam_ha_server WHERE server_id = '$SERVER_A'; DELETE FROM pam_ha_session WHERE server_id =
        '$SERVER_A'; DELETE FROM pam_ha_share WHERE session_id NOT IN (SELECT session_id FROM pam_ha_session)" \
        >/dev/null
    check "server A not heard from, the other servers remove her session and its share link" 0 "$(share_count)"
    eventually "...which server A records again when heard from" 1 20 share_count
    SHARED_B=$(curl -s -d "key=$KEY" "$B/api/tokens")
    check_contains "her share link opens on server B" '"pam-ha"' "$SHARED_B"
    SHARED_B=$(json_get "$SHARED_B" "d.get('authToken')")
    SHARED_ID=$(json_get "$(api GET "$B/api/session/data/pam-ha/connections" "$SHARED_B")" "list(d)[0]")
    check "...and joins her session there" open "$(HOLD_DS=pam-ha hold s1 "$B" "$SHARED_B" "$SHARED_ID")"
    eventually "server A lists it" 2 5 active_count "$A" "$ADMIN" "$OPEN"
    check "...joining with the sharing profile" "$VIEW" "$(sql "SELECT sharing_profile_id FROM pam_ha_session
        WHERE joined = 1" | tr -d '[:space:]')"
    check "...recorded in the connection history" 1 "$(sql "SELECT COUNT(*) FROM guacamole_connection_history
        WHERE sharing_profile_id = $VIEW" | tr -d '[:space:]')"
    KEY_B=$(share_key "$(api GET "$B/api/session/data/$DS/activeConnections/$ALICE_SESSION/sharingCredentials/$VIEW" \
        "$ADMIN_B")")
    SHARED_A=$(json_get "$(curl -s -d "key=$KEY_B" "$A/api/tokens")" "d.get('authToken')")
    SHARED_ID=$(json_get "$(api GET "$A/api/session/data/pam-ha/connections" "$SHARED_A")" "list(d)[0]")
    check "the administrator shares it from server B, the link opens on server A" open \
        "$(HOLD_DS=pam-ha hold s2 "$A" "$SHARED_A" "$SHARED_ID")"
    release a12
    eventually "Alice ends her session: those opening her links end with it" closed $ENDED_WAIT state s1
    eventually "...on both servers" closed 10 state s2
    release s1; release s2
    eventually "...and neither server lists them" 0 $ENDED_WAIT active_count "$A" "$ADMIN" "$OPEN"

    section "$DB: recordings of one server shown by the other"
    # Every database numbers its history from the start, so the recordings
    # of databases tested before would match this one's
    podman unshare sh -c 'rm -rf ../tests/rec/a/* ../tests/rec/b/*'
    check "Alice opens a recorded session on server A" open "$(hold a13 "$A" "$ALICE_A" "$RECORDED")"
    sleep 4; release a13
    eventually "...which ends" 0 $ENDED_WAIT active "$A" "$ADMIN" "$RECORDED"
    check "server A shows its recording" 1 "$(recordings "$A" "$ADMIN")"
    eventually "server B shows it too, within ${RECORDING_WAIT}s" 1 $RECORDING_WAIT recordings "$B" "$ADMIN_B"
    check "...and plays it, fetched from server A" yes "$(recording_plays "$B" "$ADMIN_B")"

    section "$DB: TOTP codes used once on both servers"
    # A code is valid for its 30 seconds, and the one before: wait for a new one
    sleep $(( (35 - $(date +%s) % 30) % 30 ))
    CODE=$(totp "$TOTP_SECRET")
    check "Carol logs in on server A with her TOTP code" yes \
        "$(login "$A" t2carol t2carol-pw "$CODE" | grep -qv '^refused' && echo yes)"
    check_contains "...and may not log in with it again on server B" "Provided TOTP code is not valid." \
        "$(login "$B" t2carol t2carol-pw "$CODE")"

    section "$DB: a server stopping cleanly frees its sessions at once"
    check "Alice holds the single-session connection on server A" open "$(hold a6 "$A" "$ALICE_A" "$SINGLE")"
    podman stop -t 20 "mypamha-$DB-a" >/dev/null
    check "server A stopped, Bob opens it on server B at once" open "$(hold b6 "$B" "$BOB_B" "$SINGLE")"
    release a6; release b6
    eventually "...and once Bob ends it, it is unused" 0 $ENDED_WAIT active "$B" "$ADMIN_B" "$SINGLE"
    ../../lab/ha.sh start "$DB" >/dev/null
    ADMIN=$(token "$A" $GUAC_ADMIN $GUAC_ADMIN_PASSWORD)
    ALICE_A=$(token "$A" t2alice t2alice-pw); BOB_A=$(token "$A" t2bob t2bob-pw)

    section "$DB: the sessions of a server that died stop counting"
    check "Alice holds the single-session connection on server B" open "$(hold a7 "$B" "$ALICE_B" "$SINGLE")"
    podman kill "mypamha-$DB-b" >/dev/null
    check "server B killed, logins made there go on on server A" t2alice "$(self_name "$A" "$ALICE_B")"
    check "...through the database they were made through" "$DS" \
        "$(json_get "$(curl -s -d "token=$ALICE_B" "$A/api/tokens")" "d.get('dataSource')")"
    check_contains "server B killed, Bob is still refused on server A at first" "This connection is in use." \
        "$(hold b7 "$A" "$BOB_A" "$SINGLE")"
    eventually "...and Bob opens it within ${STALE_WAIT}s, once server B is no longer heard from" open "$STALE_WAIT" \
        hold_until_open b8 "$A" "$BOB_A" "$SINGLE"
    release a7; release b8
    ../../lab/ha.sh start "$DB" >/dev/null
    ADMIN_B=$(token "$B" $GUAC_ADMIN $GUAC_ADMIN_PASSWORD)
    eventually "...and the dead server is removed from the database, the restarted one recorded" 2 60 \
        server_count

    section "$DB: failed logins counted on both servers"
    # From one address, as a load balancer in front of both forwards it
    export LOGIN_FROM=203.0.113.7
    sql "DELETE FROM pam_ha_ban" >/dev/null
    login "$A" t2nobody wrong >/dev/null; login "$B" t2nobody wrong >/dev/null
    login "$A" t2nobody wrong >/dev/null
    check_contains "after $BAN_ATTEMPTS failed logins on both servers, server B refuses even Alice" \
        "Too many failed authentication attempts" "$(login "$B" t2alice t2alice-pw)"
    sleep $((BAN_SECONDS + 2))
    check "...until ${BAN_SECONDS}s after the last" yes \
        "$(login "$B" t2alice t2alice-pw | grep -qv '^refused' && echo yes)"
    unset LOGIN_FROM

    section "$DB: cleanup"
    release_all
    ADMIN=$(token "$A" $GUAC_ADMIN $GUAC_ADMIN_PASSWORD)
    api DELETE "$DATA/sharingProfiles/$VIEW" "$ADMIN" >/dev/null
    for c in $OPEN $SINGLE $PER_USER $MEMBER $RECORDED; do
        api DELETE "$DATA/connections/$c" "$ADMIN" >/dev/null
    done
    api DELETE "$DATA/connectionGroups/$GROUP" "$ADMIN" >/dev/null
    for user in t2alice t2bob t2carol; do api DELETE "$DATA/users/$user" "$ADMIN" >/dev/null; done
    check "test data removed" "" "$(json_get "$(api GET "$DATA/connections/$OPEN" "$ADMIN")" "d.get('identifier')")"

}

share_count() { sql "SELECT COUNT(*) FROM pam_ha_share" | tr -d '[:space:]'; }
server_count() { sql "SELECT COUNT(*) FROM pam_ha_server" | tr -d '[:space:]'; }

# recordings URL TOKEN -> how many recordings the last session of the
# recorded connection shows there
recordings() {
    json_get "$(api GET "$1/api/session/data/$DS/connections/$RECORDED/history" "$2")" \
        "len([l for l in (d[0].get('logs') or {}).values() if l.get('type') == 'GUACAMOLE_SESSION_RECORDING'])"
}

# recording_plays URL TOKEN -> "yes" if the recording of the last session
# of the recorded connection is given there, as Guacamole protocol
recording_plays() {
    local history record log
    history=$(api GET "$1/api/session/data/$DS/connections/$RECORDED/history" "$2")
    record=$(json_get "$history" "d[0]['identifier']")
    log=$(json_get "$history" "next(n for n, l in d[0]['logs'].items() if l['type'] == 'GUACAMOLE_SESSION_RECORDING')")
    curl -s "$1/api/session/data/$DS/history/connections/$record/logs/$log?token=$2" | head -c 100 \
        | grep -qE '^[0-9]+\.[a-z]' && echo yes
}

# hold_until_open NAME URL TOKEN ID: one try at opening, kept open if it did
hold_until_open() {
    local result
    result=$(hold "$@")
    [ "$result" = open ] || release "$1"
    echo "$result" | cut -d' ' -f1
}

for db in ${@:-postgresql mysql mariadb sqlserver}; do
    suite "$db"
    release_all
    rm -f "$T2_TMP"/session-*
done

printf '\n%d passed, %d failed\n' "$T2_PASSED" "$T2_FAILED"
for failure in "${T2_FAILURES[@]}"; do printf '  FAIL  %s\n' "$failure"; done
rm -rf "$T2_TMP"
[ "$T2_FAILED" -eq 0 ]
