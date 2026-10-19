#!/bin/bash
# Make sure all container are stopped
podman stop myguactest
podman stop myguacdtest
podman stop myguacdbtest
# Remove old DB
sudo rm -rf podman/db/*
# Start db and init db
podman run --rm -d \
--name myguacdbtest \
-e POSTGRES_PASSWORD=mysecretpassword \
-e PGDATA=/var/lib/postgresql/data/pgdata \
-v ./podman/db:/var/lib/postgresql/data:Z \
-v ./podman/init/initdb.sql:/docker-entrypoint-initdb.d/initdb.sql:Z \
docker.io/postgres:18.4
