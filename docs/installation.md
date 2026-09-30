# Installation Guide

You can run **DNS-collector** using precompiled binaries, Docker containers, or by building it from source.

## Download Precompiled Binaries

Precompiled binaries for Linux, macOS, and Windows are available on the GitHub Releases page:

👉 **[Download latest DNS-collector release](https://github.com/dmachard/DNS-collector/releases/latest)**

> **Important**: Official precompiled binaries only include stable and production-ready features. Experimental components (such as OpenTelemetry) are **not included** in official release binaries and must be compiled from source with the `experimental` tag.

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

To compile DNS-collector yourself, you need **Go 1.26+** installed.

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

> **Note**: Experimental components (such as the OpenTelemetry logger) are **not included by default** to keep the binary lightweight and stable.

### Build with Experimental Components
To build with all experimental components included:
```bash
make build-experimental
```

Or using `go build` directly:
```bash
go build -tags experimental dnscollector.go
```
