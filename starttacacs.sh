#!/bin/bash
# Start a TACACS+ server to test TACACS+ password rotation against
# (hostname "mytacacstest", port 49, shared secret "TacacsSecr3t",
#  test user "tactest" / "P@ssw0rd-Tac1"). tac_plus-ng is built from source
# into the image "localhost/pam-tacacs-test" the first time, which takes a
# few minutes.
cd "$(dirname "$0")" || exit 1
podman image exists localhost/pam-tacacs-test \
    || podman build -t localhost/pam-tacacs-test podman/tacacs || exit 1
# Already running: keep its accounts, which the rest would reset
if [ "$(podman inspect -f '{{.State.Running}}' mytacacstest 2>/dev/null)" = true ]; then
    echo "mytacacstest is already running."
    exit 0
fi
podman run --rm -d \
--name mytacacstest \
--hostname mytacacstest \
--net myguacnet \
localhost/pam-tacacs-test || exit 1

# Accounts live in its shadow file: user:hash:last change (days):...
HASH=$(podman exec mytacacstest mkpasswd -m sha-512 'P@ssw0rd-Tac1')
podman exec mytacacstest sh -c "echo 'tactest:$HASH:$(( $(date +%s) / 86400 )):0:99999:7:::' > /etc/tacacs/shadow"
