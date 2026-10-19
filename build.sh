#!/bin/bash
# Stop previous containers
podman stop myguactest
podman stop myguacdtest
podman stop myguacdbtest
# Clean & build the project
mvn clean
mvn package
# Start db
podman run --rm -d \
--name myguacdbtest \
--hostname myguacdbtest \
--net myguacnet \
-e POSTGRES_PASSWORD=mysecretpassword \
-e PGDATA=/var/lib/postgresql/data/pgdata \
-v ./podman/db:/var/lib/postgresql/data:Z \
docker.io/postgres:18.4
# Start gaucd
podman run --rm -d \
--name myguacdtest \
--hostname myguacdtest \
--net myguacnet \
docker.io/guacamole/guacd:1.6.0
# Start guacamole
podman run --rm -d \
--name myguactest \
--hostname myguactest \
--net myguacnet \
-e GUACD_HOSTNAME=myguacdtest \
-e POSTGRESQL_HOSTNAME=myguacdbtest \
-e POSTGRESQL_DATABASE=postgres \
-e POSTGRESQL_USER=postgres \
-e POSTGRESQL_PASSWORD=mysecretpassword \
-e WEBAPP_CONTEXT=ROOT \
-p 8080:8080 \
-v ./target/guacamole-pam-1.6.0.jar:/opt/guacamole/extensions/guacamole-pam-1.6.0.jar:Z \
-v ./podman/entrypoint.d/855-add-pam.sh:/opt/guacamole/entrypoint.d/855-add-pam.sh:Z \
docker.io/guacamole/guacamole:1.6.0
