#!/bin/bash
# Start a second Guacamole server sharing the database and guacd of build.sh,
# on port 8081, to test several servers running the extension at once
# (tests/suites/40-servers.sh). Run build.sh first.
cd "$(dirname "$0")" || exit 1
source ./podman/database.sh
mapfile -t DB_ENV < <(db_guacamole_env)
podman run --rm -d \
--name myguactest2 \
--hostname myguactest2 \
--net myguacnet \
-e GUACD_HOSTNAME=myguacdtest \
"${DB_ENV[@]}" \
-e WEBAPP_CONTEXT=ROOT \
-e PAM_ENCRYPTION_KEY="${PAM_ENCRYPTION_KEY-um/hqZa6cc89CtHmc9vYOuoDd8S1jY8IaASlz5S00iY=}" \
-p 8081:8080 \
-v "$(./podman/extension-jar.sh)":/opt/guacamole/extensions/guacamole-pam.jar:Z \
-v ./podman/entrypoint.d/855-add-pam.sh:/opt/guacamole/entrypoint.d/855-add-pam.sh:Z \
"$PAM_GUACAMOLE_IMAGE"
