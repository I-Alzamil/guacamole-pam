#!/bin/bash
# Events sent to syslog: settings checked, the test button, TLS checking the
# server's certificate and name, TCP and UDP, the messages' format, and a
# connection opened again once the server closed it. Needs the receiver
# mysyslogtest (lab/lab.sh services).

SETTINGS="$PAM/settings"
SYSLOG_NAMES='"pam-syslog-enabled","pam-syslog-host","pam-syslog-port","pam-syslog-transport","pam-syslog-ca-certificates","pam-syslog-facility","pam-syslog-app-name"'

reset_syslog() {
    api PUT "$SETTINGS" "$ADMIN" "$(python3 -I -c "import json,sys;print(json.dumps({n: None for n in json.loads('[' + sys.argv[1] + ']')}))" "$SYSLOG_NAMES")" >/dev/null
}

syslog_set() { api PUT "$SETTINGS" "$ADMIN" "$1"; }

# What the receiver got over a transport: tls, tcp or udp
received() { podman exec mysyslogtest cat "/tmp/$1.log" 2>/dev/null; }

# Waits up to 10 s for the receiver to get a message containing TEXT over a
# transport, printing yes or no
arrives() { # TRANSPORT TEXT
    local i
    for i in $(seq 20); do
        received "$1" | grep -qF -- "$2" && { echo yes; return; }
        sleep 0.5
    done
    echo no
}

test_syslog() { api POST "$SETTINGS/test/syslog" "$ADMIN"; }

CA=$(python3 -I -c "import json,sys;print(json.dumps(open(sys.argv[1]).read()))" ../lab/targets/certs/ca.crt)

section "Setup"
create_connection GATED "{\"name\":\"t45 gated ssh\",\"parentIdentifier\":\"ROOT\",\"protocol\":\"ssh\",
    \"parameters\":{\"hostname\":\"mysshtest\",\"port\":\"22\"},\"attributes\":{}}"
create_user t45-user t45-user-pw
grant_read t45-user "$GATED"
USER=$(token t45-user t45-user-pw)
reset_syslog
on_cleanup reset_syslog
podman exec mysyslogtest sh -c ': > /tmp/tls.log; : > /tmp/tcp.log; : > /tmp/udp.log' 
check "setup: a connection, a user, and the receiver exist" yes \
    "$([ -n "$GATED" ] && [ -n "$USER" ] && [ "$(podman inspect -f '{{.State.Running}}' mysyslogtest 2>/dev/null)" = true ] && echo yes)"

# ---------------------------------------------------------------- settings
section "Settings"
check "off by default, over TLS on 6514, facility authpriv" "False tls 6514 authpriv" \
    "$(curl -s "$SETTINGS?token=$ADMIN" | python3 -I -c "
import sys,json
e={e['name']: e for e in json.load(sys.stdin)}
print(e['pam-syslog-enabled']['value'], e['pam-syslog-transport']['value'], e['pam-syslog-port']['value'], e['pam-syslog-facility']['value'])")"
check "...the insecure transports last" "tls tcp udp" \
    "$(curl -s "$SETTINGS?token=$ADMIN" | python3 -I -c "
import sys,json
print(' '.join([e for e in json.load(sys.stdin) if e['name']=='pam-syslog-transport'][0]['options']))")"
R=$(syslog_set '{"pam-syslog-enabled":true}')
check "turning it on needs a server" "400 \"pam-syslog-host\" is needed while \"pam-syslog-enabled\" is on." \
    "$(status_of "$R") $(message_of "$R")"
R=$(syslog_set '{"pam-syslog-host":"bad host"}')
check "a server must be a host name or address" "400 \"pam-syslog-host\": not a host name or address." \
    "$(status_of "$R") $(message_of "$R")"
R=$(syslog_set '{"pam-syslog-transport":"ssl"}')
check "a transport must be one of the options" "400 \"pam-syslog-transport\" must be one of tls, tcp, udp." \
    "$(status_of "$R") $(message_of "$R")"
R=$(syslog_set '{"pam-syslog-ca-certificates":"not a certificate"}')
check_contains "CA certificates must be PEM certificates" "400 \"pam-syslog-ca-certificates\": The CA certificates are not valid PEM" \
    "$(status_of "$R") $(message_of "$R")"
R=$(syslog_set '{"pam-syslog-app-name":"guac pam"}')
check_contains "an application name has no spaces" "400 \"pam-syslog-app-name\": only letters" "$(status_of "$R") $(message_of "$R")"

# ---------------------------------------------------------------- test
section "The test button"
check "a user cannot test" 403 "$(status_of "$(api POST "$SETTINGS/test/syslog" "$USER")")"
check "an unknown output" 404 "$(status_of "$(api POST "$SETTINGS/test/pager" "$ADMIN")")"
R=$(test_syslog)
check "without a server, it says so" "200 False No syslog server is set." \
    "$(status_of "$R") $(json_get "${R#* }" "d['sent']") $(message_of "$R")"

syslog_set '{"pam-syslog-host":"mysyslogtest"}' >/dev/null
R=$(test_syslog)
check_contains "over TLS, a certificate of a CA Java does not trust is refused" \
    "False The certificate of syslog server mysyslogtest:6514 over TLS is not trusted" \
    "$(json_get "${R#* }" "d['sent']") $(message_of "$R")"
check_contains "...which is logged" "User \"$GUAC_ADMIN\" tested syslog: The certificate of syslog server" \
    "$(podman logs --since 1m myguactest 2>&1)"

syslog_set "{\"pam-syslog-ca-certificates\":$CA}" >/dev/null
SYSLOG_IP=$(podman inspect -f '{{(index .NetworkSettings.Networks "myguacnet").IPAddress}}' mysyslogtest)
syslog_set "{\"pam-syslog-host\":\"$SYSLOG_IP\"}" >/dev/null
R=$(test_syslog)
check_contains "a trusted certificate not naming the host reached is refused" "does not name \"$SYSLOG_IP\"" \
    "$(message_of "$R")"

syslog_set '{"pam-syslog-host":"mysyslogtest","pam-syslog-port":6515}' >/dev/null
R=$(test_syslog)
check_contains "a server not listening" "False Unable to reach syslog server mysyslogtest:6515 over TLS" \
    "$(json_get "${R#* }" "d['sent']") $(message_of "$R")"

syslog_set '{"pam-syslog-port":null}' >/dev/null
R=$(test_syslog)
check "with the CA trusted, the test is sent" \
    "True A test message was sent to syslog server mysyslogtest:6514 over TLS." \
    "$(json_get "${R#* }" "d['sent']") $(message_of "$R")"
check "...and received" yes "$(arrives tls "event=\"test\" actor=\"$GUAC_ADMIN\"")"
check "...while sending events stays off" "no" "$(arrives tls "event=\"settings-changed\"")"

# ---------------------------------------------------------------- events
section "Events over TLS"
syslog_set '{"pam-syslog-enabled":true}' >/dev/null
check "turning it on is itself sent" yes \
    "$(arrives tls "event=\"settings-changed\" actor=\"$GUAC_ADMIN\" detail=\"pam-syslog-enabled: true (was the default (false))\"")"
api POST "$PAM/requests/$GATED" "$USER" '{"reason":"T45 ticket"}' >/dev/null
check "a checkout" yes "$(arrives tls "event=\"checkout-started\" user=\"t45-user\" connection=\"t45 gated ssh\" connection-id=\"$GATED\"")"
check "...framed by its length (RFC 6587), as RFC 5424: authpriv.notice, from this server, by guacamole-pam" yes \
    "$(received tls | python3 -I -c "
import sys,re
data=sys.stdin.read()
ok=False
while data:
    m=re.match(r'(\d+) ', data)
    if not m: break
    n=int(m.group(1)); start=m.end(); msg=data[start:start+n]; data=data[start+n:]
    if 'event=\"checkout-started\"' in msg and 't45-user' in msg:
        ok=bool(re.match(r'<85>1 \d{4}-\d\d-\d\dT[0-9:.]+Z myguactest guacamole-pam - checkout-started - User \"t45-user\" checked out \"t45 gated ssh\"\. ', msg)) and 'reason=\"T45 ticket\"' in msg
print('yes' if ok else 'no')")"
tunnel "$USER" "$GATED" c >/dev/null
check "a session" yes "$(arrives tls "event=\"session-started\" user=\"t45-user\" connection=\"t45 gated ssh\"")"
api POST "$PAM/requests/$GATED/release" "$USER" >/dev/null
check "a release" yes "$(arrives tls "event=\"checkout-released\" user=\"t45-user\"")"

# The receiver's processes serving connections, all but the listening one
podman exec mysyslogtest sh -c 'kill $(pgrep -f "^socat -u OPENSSL" | grep -vx "$(pgrep -o -f "^socat -u OPENSSL")")'
api POST "$PAM/requests/$GATED" "$USER" '{"reason":"T45 after closing"}' >/dev/null
check "the server closing the connection: the next event opens a new one" yes \
    "$(arrives tls "reason=\"T45 after closing\"")"
api POST "$PAM/requests/$GATED/release" "$USER" >/dev/null

# ---------------------------------------------------------------- tcp, udp
section "TCP and UDP"
syslog_set '{"pam-syslog-transport":"tcp","pam-syslog-port":514,"pam-syslog-facility":"local3","pam-syslog-app-name":"t45-pam"}' >/dev/null
check "over TCP, the change itself" yes "$(arrives tcp "event=\"settings-changed\"")"
check "...with the facility and name set: local3.notice, by t45-pam" yes \
    "$(received tcp | grep -q '<157>1 [^ ]* myguactest t45-pam - settings-changed' && echo yes || echo no)"
syslog_set '{"pam-syslog-transport":"udp"}' >/dev/null
R=$(test_syslog)
check "over UDP, the test says nothing confirms it" \
    "A test message was sent to syslog server mysyslogtest:514 over UDP. UDP never confirms it arrived: look for it there." \
    "$(message_of "$R")"
check "...which arrives" yes "$(arrives udp "event=\"test\"")"
api POST "$PAM/requests/$GATED" "$USER" '{"reason":"T45 over UDP"}' >/dev/null
check "...as events do" yes "$(arrives udp "reason=\"T45 over UDP\"")"
api POST "$PAM/requests/$GATED/release" "$USER" >/dev/null

# ---------------------------------------------------------------- off
section "Turned off"
syslog_set '{"pam-syslog-enabled":false}' >/dev/null
api POST "$PAM/requests/$GATED" "$USER" '{"reason":"T45 while off"}' >/dev/null
check "nothing is sent" no "$(arrives udp "reason=\"T45 while off\"")"
api POST "$PAM/requests/$GATED/release" "$USER" >/dev/null
