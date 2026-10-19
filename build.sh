#!/bin/bash
# Stop previous containers
podman stop myguactest
podman stop myguacdtest
podman stop myguacdbtest
# A second server (startguac2.sh) would keep the old jar
podman stop --ignore myguactest2
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
# Start guacamole. Stored secrets are encrypted with a fixed test key (for
# development only); run with PAM_ENCRYPTION_KEY= to store them unencrypted
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
-e PAM_ENCRYPTION_KEY="${PAM_ENCRYPTION_KEY-um/hqZa6cc89CtHmc9vYOuoDd8S1jY8IaASlz5S00iY=}" \
-p 8080:8080 \
-v ./target/guacamole-pam-1.6.0.jar:/opt/guacamole/extensions/guacamole-pam-1.6.0.jar:Z \
-v ./podman/entrypoint.d/855-add-pam.sh:/opt/guacamole/entrypoint.d/855-add-pam.sh:Z \
docker.io/guacamole/guacamole:1.6.0
