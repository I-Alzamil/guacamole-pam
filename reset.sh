#!/bin/bash
# Starts the test database afresh, with only Guacamole's schema and its
# guacadmin user (PostgreSQL, or PAM_DB=mysql, mariadb or sqlserver: see
# podman/database.sh). Run build.sh afterwards.
cd "$(dirname "$0")" || exit 1
source ./podman/database.sh
# Make sure all container are stopped
podman stop myguactest
podman stop myguacdtest
podman stop myguacdbtest
# Remove old DB
db_reset
# Start db and init db
db_start
db_wait
