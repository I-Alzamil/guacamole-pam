#!/bin/bash
# Prints the path of the extension's jar built in target/, whatever its
# version (the shade plugin keeps the unshaded jar as original-*.jar).
cd "$(dirname "$0")/.." || exit 1
for jar in target/guacamole-pam-*.jar; do
    [ -e "$jar" ] && { printf '%s/%s\n' "$PWD" "$jar"; exit 0; }
done
echo "No guacamole-pam jar in target/: build it with mvn package." >&2
exit 1
