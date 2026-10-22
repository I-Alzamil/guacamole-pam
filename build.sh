#!/bin/bash
# Builds the extension and starts it in Guacamole on port 8080, with guacd
# and the test database (PostgreSQL, or PAM_DB=mysql, mariadb or sqlserver:
# see podman/database.sh).
cd "$(dirname "$0")" || exit 1
source ./podman/database.sh
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
db_start
db_wait || exit 1
# Start gaucd
podman run --rm -d \
--name myguacdtest \
--hostname myguacdtest \
--net myguacnet \
docker.io/guacamole/guacd:1.6.0
# Start guacamole. Stored secrets are encrypted with a fixed test key (for
# development only); run with PAM_ENCRYPTION_KEY= to store them unencrypted
mapfile -t DB_ENV < <(db_guacamole_env)
podman run --rm -d \
--name myguactest \
--hostname myguactest \
--net myguacnet \
-e GUACD_HOSTNAME=myguacdtest \
"${DB_ENV[@]}" \
-e WEBAPP_CONTEXT=ROOT \
-e PAM_ENCRYPTION_KEY="${PAM_ENCRYPTION_KEY-um/hqZa6cc89CtHmc9vYOuoDd8S1jY8IaASlz5S00iY=}" \
-p 8080:8080 \
-v "$(./podman/extension-jar.sh)":/opt/guacamole/extensions/guacamole-pam.jar:Z \
-v ./podman/entrypoint.d/855-add-pam.sh:/opt/guacamole/entrypoint.d/855-add-pam.sh:Z \
"$PAM_GUACAMOLE_IMAGE"
