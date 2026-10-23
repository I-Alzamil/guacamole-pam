#!/bin/bash
# Runs the Tier 2 suites against the podman test setup (see tests/README.md):
#   tests/run.sh            every suite
#   tests/run.sh rotation   suites whose name contains "rotation"
# Exits with 1 if any check failed.

cd "$(dirname "$0")" || exit 2
source ./lib.sh
trap 'rm -rf -- "${T2_TMP:?}"' EXIT

missing=()
for container in myguactest myguacdbtest myguacdtest mysshtest myldaptest myadtest mykdctest mytacacstest mypgtarget mymysqltarget mymariadbtarget mymssqltarget; do
    [ "$(podman inspect -f '{{.State.Running}}' "$container" 2>/dev/null)" = true ] || missing+=("$container")
done
if [ ${#missing[@]} -gt 0 ]; then
    echo "Not running: ${missing[*]}. Start them with lab/lab.sh guacamole services."
    exit 2
fi
wait_for_guacamole
if [ -z "$ADMIN" ]; then
    echo "Unable to log in to Guacamole at $GUAC_URL as $GUAC_ADMIN."
    exit 2
fi

# Guacamole 1.6 remembers the first request whose error it handles, and ends
# that request's session whenever any later request is refused as
# unauthorized (such as a browser still polling with an ended session). Let
# it remember a throwaway login rather than one a suite relies on
curl -s -o /dev/null "$DATA/connections/0?token=$(admin_token)"

for suite in suites/*.sh; do
    if [ $# -gt 0 ]; then
        wanted=no
        for name in "$@"; do case "$suite" in *"$name"*) wanted=yes;; esac; done
        [ $wanted = yes ] || continue
    fi
    printf '\n######## %s\n' "$(basename "$suite" .sh)"
    source "$suite"
    run_cleanup
done

printf '\n%d passed, %d failed\n' "$T2_PASSED" "$T2_FAILED"
for failure in "${T2_FAILURES[@]}"; do printf '  FAIL  %s\n' "$failure"; done
[ "$T2_FAILED" -eq 0 ]
