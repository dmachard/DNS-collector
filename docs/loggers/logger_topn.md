# Logger: Top-N (Periodic Autonomous Summary Reports)

The `topn` logger collects DNS query and response statistics in memory and periodically generates an autonomous **Top-N summary report** (Top domains, Top client IPs, Top response codes, and Top TLDs).

It requires **zero external infrastructure** (no Prometheus, no Elasticsearch, no Grafana).

---

## Output Formats

### 1. Text Format (`mode: "text"`)
Outputs human-readable ASCII tables:

```text
=== [Top-N Summary Report (2026-08-27T19:48:00Z - 60s window - 154200 queries)] ===
-- Top Domains --
  #1  google.com                               42100
  #2  cloudflare.com                           18200
  #3  github.com                               9100
-- Top Clients --
  #1  192.168.1.50                             14200
  #2  192.168.1.12                             8900
-- Top Rcodes --
  #1  NOERROR                                  148000
  #2  NXDOMAIN                                 6200
==========================================================
```

### 2. JSON Digest Format (`mode: "json"`)
Outputs a single JSON object per report interval:

```json
{
  "timestamp": "2026-08-27T19:48:00Z",
  "interval": 60,
  "total_queries": 154200,
  "top_qnames": [
    {"rank": 1, "name": "google.com", "count": 42100},
    {"rank": 2, "name": "cloudflare.com", "count": 18200}
  ],
  "top_clients": [
    {"rank": 1, "name": "192.168.1.50", "count": 14200}
  ],
  "top_rcodes": [
    {"rank": 1, "name": "NOERROR", "count": 148000}
  ]
}
```

### 3. Flat JSON Format (`mode: "flat-json"`)
Outputs one JSON line per ranked item, ideal for streaming into file ingestors:

```json
{"timestamp":"2026-08-27T19:48:00Z","interval":60,"category":"qname","rank":1,"name":"google.com","count":42100}
{"timestamp":"2026-08-27T19:48:00Z","interval":60,"category":"client","rank":1,"name":"192.168.1.50","count":14200}
```

---

## Options

* `enable` (boolean, default: `false`)
  > Enables the Top-N logger.

* `interval` (integer, default: `60`)
  > Reporting interval in seconds. At each interval, a report is generated and counters are reset for the next window.

* `top-n` (integer, default: `10`)
  > Maximum number of top entries to include per category.

* `mode` (string, default: `"text"`)
  > Output format: `"text"`, `"json"`, or `"flat-json"`.

* `output` (string, default: `"stdout"`)
  > Output destination: `"stdout"` or `"file"`.

* `file-path` (string, default: `""`)
  > File destination path when `output: "file"`.

* `track-qnames` (boolean, default: `true`)
  > Track top queried domain names.

* `track-clients` (boolean, default: `true`)
  > Track top client IP addresses.

* `track-rcodes` (boolean, default: `true`)
  > Track top DNS response codes (e.g. `NOERROR`, `NXDOMAIN`, `SERVFAIL`).

* `track-tlds` (boolean, default: `false`)
  > Track top Public Suffix / TLDs (requires `normalize` transformer).

---

## Configuration Example

```yaml
pipelines:
  - name: edge-topn
    topn:
      enable: true
      interval: 60
      top-n: 10
      mode: "text"
      output: "stdout"
      track-qnames: true
      track-clients: true
      track-rcodes: true
```
