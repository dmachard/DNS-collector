# Configuration Guide


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

### Logging

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

Configure internal processing queue capacity:

```yaml
global:
  worker:
    interval-monitor: 10    # Monitoring interval in seconds
    buffer-size: 8192      # Global channel buffer capacity for all workers
```

> [!NOTE]
> **Channel Capacity (`buffer-size`)**: Channel queue sizes are centrally controlled via `global.worker.buffer-size`. Increase `buffer-size` if you see `"buffer is full, xxx packet(s) dropped"` warnings under burst traffic.
> *(Note: The legacy per-worker `chan-buffer-size` setting has been removed in favor of this global configuration).*

### Process Management

```yaml
global:
  pid-file: "/var/run/dnscollector.pid"
```


### Telemetry & Monitoring

Enable Prometheus metrics endpoint:

```yaml
global:
  telemetry:
    enabled: true
    web-path: "/metrics"
    web-listen: ":9165"
    prometheus-prefix: "dnscollector"

    # Optional: serve over a unix socket instead of web-listen.
    # Either/or - setting sock-path is a config error together with tls-support.
    sock-path: ""
    sock-mode: "0660"

    # Optional TLS configuration
    tls-support: false
    tls-cert-file: ""
    tls-key-file: ""
    
    # Optional authentication
    basic-auth-enable: false
    basic-auth-login: "admin"
    basic-auth-pwd: "changeme"
```

`sock-path` is an alternative to `web-listen`: when set, the endpoint serves
plain HTTP over the unix socket instead of TCP. `tls-support` must be `false`
(setting both is a startup error).

Access is governed by `sock-mode` and the socket's parent directory — keep the
socket in a dedicated directory owned by the daemon, not `/tmp`:

```yaml
global:
  telemetry:
    sock-path: "/run/dnscollector/telemetry.sock"  # dir mode 0750
    sock-mode: "0660"
```

`basic-auth-enable` still applies but travels in cleartext over the socket —
defense-in-depth, not a replacement for `sock-mode`.

### Default Output Format

Set default text format for all loggers:

```yaml
global:
  text-format: "timestamp-rfc3339ns identity operation rcode queryip queryport qname qtype"
  text-format-delimiter: " "
  text-format-boundary: "\""
```

### Framestream

Configure the Framestream protocol limits:

```yaml
global:
  framestream:
    control-frame-max-length: 4064     # Max length for control frames (default: 4064)
    data-frame-max-length: 65536      # Max length for data frames (default: 65536)
    handshake-timeout: 5              # Timeout in seconds for the handshake (default: 5)
    content-type: "protobuf:dnstap.Dnstap" # Content type for the stream (default: protobuf:dnstap.Dnstap)
```



## Validation and Reloading

### Configuration Validation

Always validate configuration before deployment:

```bash
# Test configuration
./dnscollector -config config.yml -test-config

# Run with specific config file
./dnscollector -config /path/to/config.yml
```

### Hot Configuration Reload

Reload configuration without restarting the service:

```bash
# Send SIGHUP signal
sudo pkill -HUP dnscollector

# Or if you know the PID
kill -HUP <pid>
```

Expected reload output:
```
WARNING: 2024/10/28 18:37:05.046321 main - SIGHUP received
INFO: 2024/10/28 18:37:05.049529 worker - [tap] dnstap - reload configuration...
INFO: 2024/10/28 18:37:05.050071 worker - [tofile] file - reload configuration...
```