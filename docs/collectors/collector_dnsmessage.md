# Collector: DNSMessage

The `dnsmessage` collector is a **virtual pipeline stage and content router**. 

Unlike network collectors (`dnstap`, `afpacket`) that capture raw traffic from external interfaces, the `dnsmessage` collector receives already-decoded DNS messages forwarded from upstream pipelines. It evaluates advanced matching rules on any DNS header or resource record field to selectively filter, route, or branch DNS traffic.

---

## 🎯 Key Use Cases & Benefits

1. **Conditional Traffic Routing & Forking**:
   - Split your global DNS traffic into dedicated processing paths (e.g., forward security anomalies and `NXDOMAIN`/`SERVFAIL` errors to a SIEM while sending general metrics to Prometheus).
   - Route traffic conditionally using `routing-policy.forward` (matched messages) and `routing-policy.dropped` (unmatched messages).

2. **Fine-Grained Record Inspection**:
   - Inspect deep DNS fields including `RDATA` values, `TTL` thresholds, query lengths, specific EDNS options, and DNS flags (`QR`, `AA`, `TC`, `RD`, `RA`).

3. **Threat Intelligence & Dynamic Blocklists**:
   - Dynamically load external domain or IP lists from local files (`file://`) or remote HTTP endpoints (`http://`) with support for plain string sets and precompiled regular expressions.

4. **Targeted Middleware Optimization**:
   - Avoid CPU overhead by applying heavy transformers (GeoIP lookups, BGP enrichment, Suspicious detectors) **only** to specific traffic matching your criteria rather than the entire ingestion stream.

---

## Configuration Options

* `enable` (boolean, default: `false`)
  > Enables the DNSMessage collector.

* `matching` (map)
    * `include` (map)
      > List of field criteria that **must match** for a message to be retained (supports exact values, regex, lists, and comparison operators).
    * `exclude` (map)
      > List of field criteria that will cause a message to be **dropped/routed to dropped policy** if matched.

---

## Matching Syntax & Operators

Field names correspond directly to the JSON structure of the `DNSMessage` payload:

| Operator / Directive | Type | Description | Example |
|---|---|---|---|
| **Exact Value** | `string` / `int` / `bool` | Matches exact field content | `dns.flags.qr: false` |
| **Wildcard Array** | `.*` | Matches any element in a list/array | `dns.resource-records.an.*.ttl` |
| **Indexed Array** | `.0`, `.1` | Matches a specific item by index | `dns.resource-records.an.0.rdata` |
| `greater-than` | `int` / `float` | Matches numbers strictly greater than limit | `greater-than: 300` |
| `lower-than` | `int` / `float` | Matches numbers strictly lower than limit | `lower-than: 10` |
| `match-source` | `string` | Path to local file (`file://`) or remote URL (`http://`) | `file:///etc/threat-domains.txt` |
| `source-kind` | `string` | Format of `match-source`: `string_list` or `regexp_list` | `source-kind: "regexp_list"` |

---

## Configuration Examples

### Example 1: Isolating Suspicious TXT Queries & Long Answers

Filter for incoming query messages (`dns.flags.qr: false`) requesting `TXT` records with payload size $> 512$ bytes:

```yaml
pipelines:
  - name: suspicious-txt-filter
    dnsmessage:
      enable: true
      matching:
        include:
          dns.flags.qr: false
          dns.qtype: "TXT"
          dns.length:
            greater-than: 512
    routing-policy:
      forward: [ "security-alerts" ]
      dropped: [ "standard-logger" ]
```

---

### Example 2: Filtering Answers by TTL and Response IP Pattern

Match responses where answer records have a TTL $> 300$ seconds and IP addresses matching specific subnets:

```yaml
pipelines:
  - name: filter-specific-ips
    dnsmessage:
      enable: true
      matching:
        include:
          dns.resource-records.an.*.ttl:
            greater-than: 300
          dns.resource-records.an.*.rdata:
            - "^142\\.250\\.185\\.(196|132)$"
            - "^143\\.251\\.185\\.(196|132)$"
    routing-policy:
      forward: [ "loki-output" ]
```

---

### Example 3: Threat Intelligence with Dynamic File Ingestion

```yaml
pipelines:
  - name: threat-intel-matcher
    dnsmessage:
      enable: true
      matching:
        include:
          dns.qname:
            match-source: "file:///etc/dnscollector/malicious_domains_regex.txt"
            source-kind: "regexp_list"
        exclude:
          dns.qtype: [ "TXT", "MX" ]
          dns.qname:
            - ".*\\.github\\.com$"
            - "^www\\.google\\.com$"
    transforms:
      atags:
        tags: [ "THREAT:MALICIOUS_DOMAIN" ]
    routing-policy:
      forward: [ "siem-syslog" ]
      dropped: [ "standard-archive" ]
```