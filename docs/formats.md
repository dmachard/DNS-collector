# Output Formats

DNS-collector supports multiple output formats for different use cases.


### Text Format

Highly customizable text output using field directives:

#### Available Directives

| Category | Directive | Description |
|---|---|---|
| **Time** | `timestamp-rfc3339ns` | RFC3339 timestamp with nanoseconds |
| | `timestamp-unixms` | Unix timestamp (milliseconds) |
| | `localtime` | Local time format |
| | `latency` | Query/response latency in second(s) |
| | `latency_ms` | Query/response latency in millisecond(s) |
| **Network Details** | `queryip` / `responseip` | Client / Resolver IP addresses |
| | `queryport` / `responseport` | Client / Resolver port numbers |
| | `family` | IP version (IPv4 or IPv6) |
| | `protocol` | Transport protocol (UDP or TCP) |
| | `length` / `length-unit` | Packet size in bytes |
| | `peer-name` | Sender hostname or IP |
| | `identity` | DNStap identity string |
| **DNS Flags** | `qr` | Query/Response flag |
| | `aa` | Authoritative Answer flag |
| | `tc` | Truncated flag |
| | `rd` | Recursion Desired flag |
| | `ra` | Recursion Available flag |
| | `ad` | Authenticated Data flag |
| **DNS Information** | `operation` | DNStap operation (e.g. `CLIENT_QUERY`, `CLIENT_RESPONSE`) |
| | `rcode` | DNS response code (e.g. `NOERROR`, `NXDOMAIN`) |
| | `rdatatype` | DNS response type (A, AAAA, TXT, etc.) |
| | `rdatatypes` | DNS response types (semicolon separated) |
| | `qname` | Query domain name |
| | `qtype` | Query type (A, AAAA, TXT, etc.) |
| | `qclass` | Query class (typically `IN`) |
| | `opcode` | DNS opcode (typically `QUERY`) |
| | `id` | DNS transaction ID |
| | `answer` | First answer record |
| | `answer-ip` | First A/AAAA answer |
| | `answer-ips` | All A/AAAA answers (comma-separated) |
| | `ttl` | Answer Time-To-Live (TTL) |
| | `edns-csubnet` | EDNS Client Subnet (ECS) |

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
    "latency": 0.025,
    "latency_ms": 25
  }
}
```


### Flat JSON Format

**Note:** In this format, all lists (for example, DNS answers or EDNS options) are converted into a single string, where each element is concatenated using the `|` (pipe) separator. This ensures a flat format compatible with most indexing and analytics tools. If a list is empty, the field value is set to `-`.

Single-level key-value pairs for easier processing:

```json
{
  "dns.flags.aa": false,
  "dns.flags.ad": false,
  "dns.flags.qr": false,
  "dns.flags.ra": false,
  "dns.flags.tc": false,
  "dns.flags.rd": false,
  "dns.flags.cd": false,
  "dns.length": 0,
  "dns.malformed-packet": false,
  "dns.id": 0,
  "dns.opcode": 0,
  "dns.qname": "-",
  "dns.qtype": "-",
  "dns.rcode": "-",
  "dns.qclass": "-",
  "dns.qdcount": 0,
  "dns.ancount": 0,
  "dns.arcount": 0,
  "dns.nscount": 0,
  "dns.resource-records.an.names": "google.nl",
  "dns.resource-records.an.rdatas": "142.251.39.99",
  "dns.resource-records.an.rdatatypes": "A",
  "dns.resource-records.an.ttls": "300",
  "dns.resource-records.an.classes": "IN",
  "dns.resource-records.ar.names": "-",
  "dns.resource-records.ar.rdatas": "-",
  "dns.resource-records.ar.rdatatypes": "-",
  "dns.resource-records.ar.ttls": "-",
  "dns.resource-records.ar.classes": "-",
  "dns.resource-records.ns.names": "-",
  "dns.resource-records.ns.rdatas": "-",
  "dns.resource-records.ns.rdatatypes": "-",
  "dns.resource-records.ns.ttls": "-",
  "dns.resource-records.ns.classes": "-",
  "dnstap.identity": "-",
  "dnstap.latency": 0,
  "dnstap.latency_ms": 0,
  "dnstap.operation": "-",
  "dnstap.timestamp-rfc3339ns": "-",
  "dnstap.version": "-",
  "dnstap.extra": "-",
  "dnstap.policy-rule": "-",
  "dnstap.policy-type": "-",
  "dnstap.policy-action": "-",
  "dnstap.policy-match": "-",
  "dnstap.policy-value": "-",
  "dnstap.peer-name": "-",
  "dnstap.query-zone": "-",
  "edns.dnssec-ok": 0,
  "edns.optionscount": 1,
  "edns.options.codes": "10",
  "edns.options.datas": "aaaabbbbcccc",
  "edns.options.names": "COOKIE",
  "edns.rcode": 0,
  "edns.udp-size": 0,
  "edns.version": 0,
  "network.family": "-",
  "network.ip-defragmented": false,
  "network.protocol": "-",
  "network.query-ip": "-",
  "network.query-port": "-",
  "network.response-ip": "-",
  "network.response-port": "-",
  "network.tcp-reassembled": false
}
```


### Jinja Templating

**Tip:** For a complete list of available field names and their structure, visit: https://pkg.go.dev/github.com/dmachard/go-dnscollector/v2/dnsutils#DNSMessage

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

| Protocol       | Mapped To                  |
|----------------|----------------------------|
| DNS/UDP        | DNS UDP/53                 |
| DNS/TCP        | DNS TCP/53                 |
| DoH/TCP/443    | DNS UDP/443 (unencrypted)  |
| DoT/TCP/853    | DNS UDP/853 (unencrypted)  |
| DoQ/UDP/443    | DNS UDP/443 (unencrypted)  |

## Which Output Format Should I Choose?

| Output Format | CPU Encoding Speed | Memory Impact | Human Readability | Best Use Cases / Target Systems |
|---|---|---|---|---|
| **DNStap (Protobuf)** | Ultra Fast | Minimal | Binary | High-speed forwarding, DNStap relays, remote collector pipelines |
| **Text (CSV / Custom)** | Very Fast | Minimal | Excellent | Console output, Syslog, local log files, Grep / AWK scripts |
| **JSON (Nested)** | Fast (~1µs) | Minimal | Good | Webhooks, REST APIs, Application storage with nested JSON support |
| **Flat JSON** | Fast (~3.4µs) | Low | Fair | Elasticsearch, OpenSearch, Loki, ClickHouse, Scalyr, Grafana |
| **Jinja Template** | Moderate | Moderate | Custom | Complex custom human-readable log formatting |
| **PCAP** | Fast | Minimal | Wireshark | Traffic analysis, Network forensics & troubleshooting |

> **Note on I/O Bottlenecks**: The table above reflects **CPU encoding speed in Go**. When writing to local disk files or remote network sinks, overall throughput is also constrained by disk I/O (HDD vs. NVMe SSD) and network latency. For high-throughput file logging, consider tuning `flush-interval`, `batch-size`, and `chan-buffer-size`.

### Comparison Guide: JSON vs. Flat JSON

- **Choose `json` (Nested)** if you want **maximum Go application throughput** (~3.4x faster generation in Go) and your consuming application natively supports nested JSON objects.
- **Choose `flat-json`** if you are streaming logs to indexing and analytics engines like **Elasticsearch, Loki, OpenSearch, ClickHouse, or Grafana**. Flat JSON converts all fields to a single 1-level key-value format (e.g. `"dns.flags.aa": false`), making indexing, aggregation, and dashboard querying significantly faster and easier downstream.

## Data Encoding and UTF-8

DNS-collector processes all textual fields (qname, rdata, etc.) as **UTF-8 strings**. 

If a DNS message contains non-UTF-8 characters (for example, Latin-1 characters or raw binary data in a TXT record), these characters will be replaced by the UTF-8 replacement character () during processing and when outputting in Text or JSON formats.

To preserve the original bytes of these fields, it is recommended to use the **Data Extractor** transformer with the `base64-fields` or `hex-fields` options enabled. This will provide the raw data in an encoded format that avoids any character loss.
