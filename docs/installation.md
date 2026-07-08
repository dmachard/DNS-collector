# Installation Guide

You can run **DNS-collector** using precompiled binaries, Docker containers, or by building it from source.

## Download Precompiled Binaries

Precompiled binaries for Linux, macOS, and Windows are available on the GitHub Releases page:

👉 **[Download latest DNS-collector release](https://github.com/dmachard/DNS-collector/releases/latest)**

### Quick Run (Linux/macOS)

1. Download the binary for your architecture.
2. Make it executable:
   ```bash
   chmod +x dnscollector
   ```
3. Run it with your configuration:
   ```bash
   ./dnscollector -config config.yml
   ```

---

## Docker Containers

Docker images are automatically built and published to Docker Hub.

### Docker Run

To run the container with a custom configuration:
```bash
docker run -d -v $(pwd)/config.yml:/etc/dnscollector/config.yml dmachard/dnscollector
```

For more advanced setups, see the [Docker Deployment Guide](docker.md).

---

## Build from Source

To compile DNS-collector yourself, you need **Go 1.22+** installed.

### Clone the Repository
```bash
git clone https://github.com/dmachard/DNS-collector.git
cd DNS-collector
```

### Build Using Make
```bash
make build
```

This will produce the `dnscollector` executable in the root directory.
