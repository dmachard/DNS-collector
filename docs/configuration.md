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


### Telemetry & Monitoring

Enable Prometheus metrics endpoint:

```yaml
global:
  telemetry:
    enabled: true
    web-path: "/metrics"
    web-listen: ":9165"
    prometheus-prefix: "dnscollector"
    
    # Optional TLS configuration
    tls-support: false
    tls-cert-file: ""
    tls-key-file: ""
    
    # Optional authentication
    basic-auth-enable: false
    basic-auth-login: "admin"
    basic-auth-pwd: "changeme"
```

### Default Output Format

Set default text format for all loggers:

```yaml
global:
  text-format: "timestamp-rfc3339ns identity operation rcode queryip queryport qname qtype"
  text-format-delimiter: " "
  text-format-boundary: "\""
```



## Pipelines

Pipelines define the flow of DNS data from collectors to loggers. Each pipeline is a named processing stage.

### Basic Pipeline Structure

```yaml
pipelines:
  - name: "unique-pipeline-name"
    # Collector OR Logger configuration
    collector-type:
      # collector settings
    
    # Optional: data transformations
    transforms:
      - type: "transformer-name"
        # transformer settings
    
    # Required: routing policy
    routing-policy:
      forward: ["next-pipeline-name"]  # Success path
      dropped: ["error-pipeline-name"] # Error path (optional)
```


### Common Pipeline Examples

#### DNStap Input → Multiple Outputs

```yaml
pipelines:
  - name: "dnstap-collector"
    dnstap:
      listen-ip: "0.0.0.0"
      listen-port: 6000
    routing-policy:
      forward: ["json-file", "console-debug"]
      dropped: ["error-log"]

  - name: "json-file"
    logfile:
      file-path: "/var/log/dns/queries.json"
      mode: "json"

  - name: "console-debug"
    stdout:
      mode: "text"

  - name: "error-log"
    logfile:
      file-path: "/var/log/dns/errors.log"
      mode: "text"
```

#### Network Capture → Processing → Storage

```yaml
pipelines:
  - name: "network-capture"
    pcap:
      device: "eth0"
      port: 53
    transforms:
      - type: "geoip"
        mmdb-country-file: "/path/to/country.mmdb"
    routing-policy:
      forward: ["elasticsearch-output"]

  - name: "elasticsearch-output"
    elasticsearch:
      server: "http://localhost:9200"
      index: "dns-logs"
```


## Output Formats

DNS-collector supports multiple output formats for different use cases.

### Text Format

Highly customizable text output using field directives:

#### Available Directives

**Time & Identity**
- `timestamp-rfc3339ns` - RFC3339 timestamp with nanoseconds
- `timestamp-unixms` - Unix timestamp (milliseconds)
- `localtime` - Local time format
- `identity` - DNStap identity
- `peer-name` - Sender hostname/IP

**DNS Information**
- `operation` - DNStap operation (CLIENT_QUERY, etc.)
- `rcode` - DNS response code
- `qname` - Query domain name
- `qtype` - Query type (A, AAAA, etc.)
- `qclass` - Query class
- `opcode` - DNS opcode
- `id` - DNS transaction ID

**Network Details**
- `queryip` / `responseip` - IP addresses
- `queryport` / `responseport` - Port numbers
- `family` - IP version (IPv4/IPv6)
- `protocol` - Transport protocol (UDP/TCP)
- `length` / `length-unit` - Packet size

**DNS Flags**
- `qr` - Query/Response flag
- `aa` - Authoritative Answer
- `tc` - Truncated
- `rd` - Recursion Desired
- `ra` - Recursion Available
- `ad` - Authenticated Data

**Advanced Fields**
- `latency` - Query/response latency
- `answer` - First answer record
- `answer-ip` - First A/AAAA answer
- `answer-ips` - All A/AAAA answers (comma-separated)
- `ttl` - Answer TTL
- `edns-csubnet` - EDNS Client Subnet


#### Text Format Examples

**Standard Format**

```yaml
text-format: "timestamp-rfc3339ns identity operation rcode queryip qname qtype latency"
```

**CSV Format**

```yaml
text-format: "timestamp-rfc3339ns identity operation rcode queryip qname qtype"
text-format-delimiter: ";"
```

**Custom Format with Raw Text**

```yaml
text-format: "{TIME:} timestamp-rfc3339ns {CLIENT:} queryip {QUERY:} qname qtype"
```


### JSON Format

Structured JSON output with complete DNS message details:

```json
{
  "network": {
    "family": "IPv4",
    "protocol": "UDP",
    "query-ip": "192.168.1.100",
    "query-port": "54321",
    "response-ip": "8.8.8.8",
    "response-port": "53"
  },
  "dns": {
    "id": 12345,
    "qname": "example.com",
    "qtype": "A",
    "rcode": "NOERROR",
    "flags": {
      "qr": true,
      "aa": false,
      "tc": false,
      "rd": true,
      "ra": true,
      "ad": false
    },
    "resource-records": {
      "an": [
        {
          "name": "example.com",
          "rdatatype": "A",
          "ttl": 300,
          "rdata": "93.184.216.34"
        }
      ]
    }
  },
  "dnstap": {
    "operation": "CLIENT_RESPONSE",
    "identity": "dns-server-1",
    "timestamp-rfc3339ns": "2024-01-15T10:30:45.123456789Z",
    "latency": 0.025
  }
}
```

### Flat JSON Format

Single-level key-value pairs for easier processing:

```json
{
  "dns.qname": "example.com",
  "dns.qtype": "A",
  "dns.rcode": "NOERROR",
  "network.query-ip": "192.168.1.100",
  "network.protocol": "UDP",
  "dnstap.operation": "CLIENT_RESPONSE",
  "dnstap.timestamp-rfc3339ns": "2024-01-15T10:30:45.123456789Z"
}
```

### Jinja2 Templating

For maximum flexibility, use Jinja2 templates:

```yaml
text-jinja: |
  {{ dm.DNSTap.TimestampRFC3339 }} - {{ dm.NetworkInfo.QueryIP }} queried {{ dm.DNS.Qname }} ({{ dm.DNS.Qtype }})
  {% if dm.DNS.AnswerRRs %}Response: {{ dm.DNS.AnswerRRs[0].Rdata }}{% endif %}
```

**Note**: Jinja templating is powerful but slower than standard text format.

### PCAP Format

Save DNS traffic in PCAP format for network analysis tools:

```yaml
pipelines:
  - name: "pcap-logger"
    logfile:
      file-path: "/var/log/dns/capture.pcap"
      mode: "pcap"
```

Protocol mapping:
- DNS/UDP → DNS UDP/53
- DNS/TCP → DNS TCP/53  
- DoH/TCP/443 → DNS UDP/443 (unencrypted)
- DoT/TCP/853 → DNS UDP/853 (unencrypted)
- DoQ/UDP/443 → DNS UDP/443 (unencrypted)


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