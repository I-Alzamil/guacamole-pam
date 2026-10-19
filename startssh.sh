#!/bin/bash
# Start an SSH server to test password rotation against
# (hostname "mysshtest", port 22, user "mysshtest", password "P@ssw0rd")
# sshd runs as an unprivileged user in this image, so the container is
# allowed to bind ports below 1024 (this only affects the container's own
# network namespace)
podman run --rm -d \
--name mysshtest \
--hostname mysshtest \
--net myguacnet \
--sysctl net.ipv4.ip_unprivileged_port_start=0 \
-e PUID=1000 \
-e PGID=1000 \
-e PASSWORD_ACCESS=true \
-e LISTEN_PORT=22 \
-e USER_NAME=mysshtest \
-e USER_PASSWORD=P@ssw0rd \
docker.io/linuxserver/openssh-server:version-10.2_p1-r0
