#!/bin/bash
# Builds the extension's jar into target/. To run it, (re)start the test lab's
# Guacamole with lab/lab.sh guacamole.
cd "$(dirname "$0")" || exit 1
mvn clean package
