# DNS-collector - Configuration Guide

## Table of Contents

1. [Quick Start](#quick-start)
2. [Configuration Structure](#configuration-structure)
3. [Global Settings](#global-settings)
4. [Pipelines](#pipelines)
5. [Output Formats](#output-formats)
6. [Validation and Reloading](#validation-and-reloading)

## Quick Start

DNS-collector uses a YAML configuration file named `config.yml` located in the current working directory.

### Minimal Configuration

```yaml
global:
  server-identity: "my-dns-collector"
  trace:
    verbose: true

pipelines:
  - name: "dnstap-input"
    dnstap:
      listen-ip: "0.0.0.0"
      listen-port: 6000
    routing-policy:
      forward: ["console-output"]

  - name: "console-output"
    stdout:
      mode: "text"
```

### Configuration Validation

Always test your configuration before deploying:

```bash
./dnscollector -config config.yml -test-config
```

Expected output:
```
INFO: 2023/12/24 14:43:29.043730 main - config OK!
```

## Configuration Structure

DNS-collector configuration has two main sections:

```yaml
global:
  # Global settings apply to the entire application
  server-identity: "dns-collector"
  trace:
    verbose: true

pipelines:
  # List of processing pipelines
  - name: "input-pipeline"
    # collector configuration
    routing-policy:
      forward: ["output-pipeline"]
  
  - name: "output-pipeline"
    # logger configuration
```


## Global Settings

### Server Identity

Set a unique identifier for your DNS-collector instance:

```yaml
global:
  server-identity: "dns-collector-prod"
```

If empty, the hostname will be used.

### Logging Configuration

Control application logging behavior:

```yaml
global:
  trace:
    verbose: true           # Enable debug messages
    log-malformed: false   # Log malformed DNS packets
    filename: ""           # Log file path (empty = stdout)
    max-size: 10          # Max log file size in MB
    max-backups: 10       # Number of old log files to keep
```

### Worker Settings

Configure internal processing:

```yaml
global:
  worker:
    interval-monitor: 10    # Monitoring interval in seconds
    buffer-size: 8192      # Internal buffer size
```

**Important**: Increase `buffer-size` if you see "buffer is full, xxx packet(s) dropped" warnings.

### Process Management

```yaml
global:
  pid-file: "/var/run/dnscollector.pid"
```

