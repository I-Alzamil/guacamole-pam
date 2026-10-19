#!/bin/bash
# Start a second Guacamole server sharing the database and guacd of build.sh,
# on port 8081, to test several servers running the extension at once
# (tests/suites/40-servers.sh). Run build.sh first.
podman run --rm -d \
--name myguactest2 \
--hostname myguactest2 \
--net myguacnet \
-e GUACD_HOSTNAME=myguacdtest \
-e POSTGRESQL_HOSTNAME=myguacdbtest \
-e POSTGRESQL_DATABASE=postgres \
-e POSTGRESQL_USER=postgres \
-e POSTGRESQL_PASSWORD=mysecretpassword \
-e WEBAPP_CONTEXT=ROOT \
-p 8081:8080 \
-v ./target/guacamole-pam-1.6.0.jar:/opt/guacamole/extensions/guacamole-pam-1.6.0.jar:Z \
-v ./podman/entrypoint.d/855-add-pam.sh:/opt/guacamole/entrypoint.d/855-add-pam.sh:Z \
docker.io/guacamole/guacamole:1.6.0
