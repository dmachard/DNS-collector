# Docker Deployment Guide

## Quick Start with Docker Compose (Recommended)

Create a directory of your choice (e.g. ./dnscollector) to hold the docker-compose.yml and .env files.

```bash
mkdir ./dnscollector
cd ./dnscollector
```

Download docker-compose.yml and docker-example.env, either by running the following commands:

```bash
wget https://github.com/dmachard/DNS-collector/releases/latest/download/docker-compose.yml
wget -O .env https://github.com/dmachard/DNS-collector/releases/latest/download/docker-example.env
```

Populate the .env file with custom values:

- Update DNSCOLLECTOR_DATA with your preferred location for storing DNS logs.

Start the containers using docker compose command

```bash
docker compose up -d
```


## Basic docker run

Docker run with a custom configuration:

```bash
docker run -d -v $(pwd)/config.yml:/etc/dnscollector/config.yml dmachard/dnscollector
```

## Running with Podman (Rootless)

The official container image runs as a non-root user (`UID 1000` / `GID 1000`).

### Volume Permissions

In rootless Podman, your host user is mapped to container `UID 0` by default, while container `UID 1000` maps to a subordinate UID (`subuid`). To ensure the container can read and write mounted volumes, use `--userns=keep-id`:

```bash
podman run -d \
  --userns=keep-id:uid=1000,gid=1000 \
  -v $(pwd)/config.yml:/etc/dnscollector/config.yml:ro,z \
  -v ./data:/var/dnscollector:z \
  dmachard/dnscollector
```

> **Note:** The `:z` flag configures SELinux volume relabeling when running on distributions like Fedora, RHEL, or Rocky Linux.

### User Namespaces Range (`--userns=auto`)

When using automatic user namespaces (`--userns=auto`), ensure that the allocated namespace size is at least **1024** so that `UID 1000` is mapped inside the container:

```bash
podman run -d --userns=auto:size=1024 dmachard/dnscollector
```

### Privileged Ports (< 1024)

In rootless environments, binding directly to privileged ports (such as DNS port `53`) requires kernel permission. You can either:

- Allow unprivileged binding on the host:
  ```bash
  sudo sysctl -w net.ipv4.ip_unprivileged_port_start=53
  ```
- Or map an unprivileged host port to the container port:
  ```bash
  podman run -d -p 5353:53/udp -p 5353:53/tcp dmachard/dnscollector
  ```

