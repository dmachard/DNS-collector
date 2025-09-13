# DNS-collector - Output Formats

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
