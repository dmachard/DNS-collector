# Logger: ClickHouse client

ClickHouse client to stream DNS logs directly to a remote ClickHouse server using the high-performance `JSONEachRow` batch insertion format.

## Options

* `url` (string)
  > ClickHouse HTTP server URL (e.g. `http://localhost:8123`)

* `user` (string)
  > ClickHouse database user (sent via `X-ClickHouse-User` header)

* `password` (string)
  > ClickHouse database user password (sent via `X-ClickHouse-Key` header)

* `database` (string)
  > ClickHouse database name (default: `dnscollector`)

* `table` (string)
  > ClickHouse table name (default: `records`)

* `buffer-size` (integer)
  > Number of DNS events to batch in memory before flushing an HTTP POST request (default: `100`)

* `flush-interval` (integer)
  > Interval in seconds to flush the buffer even if `buffer-size` is not reached (default: `10`)

* `timeout` (integer)
  > HTTP connection and request timeout in seconds (default: `5`)

* `tls-support` (bool)
  > Enable TLS/HTTPS communication with ClickHouse (default: `false`)

* `tls-insecure` (bool)
  > Disable TLS certificate verification (default: `false`)

* `tls-min-version` (string)
  > Minimum TLS version (`1.2` or `1.3`, default: `1.2`)

* `ca-file` (string)
  > Path to custom CA certificate file

* `cert-file` (string)
  > Path to client certificate file

* `key-file` (string)
  > Path to client private key file

---

## Configuration Example

```yaml
clickhouse:
  enable: true
  url: "http://localhost:8123"
  user: "default"
  password: "password"
  database: "dnscollector"
  table: "records"
  buffer-size: 1000
  flush-interval: 5
  timeout: 5
```

---

## ClickHouse Table Schema Example

You can create the corresponding table in ClickHouse:

```sql
CREATE DATABASE IF NOT EXISTS dnscollector;

CREATE TABLE IF NOT EXISTS dnscollector.records (
    timestamp DateTime64(3, 'UTC'),
    timensec UInt64,
    timestamp_rfc3339 String,
    identity LowCardinality(String),
    operation LowCardinality(String),
    family LowCardinality(String),
    protocol LowCardinality(String),
    queryip IPv4,
    queryport UInt16,
    responseip IPv4,
    responseport UInt16,
    qname String,
    qtype LowCardinality(String),
    rcode LowCardinality(String),
    length UInt16,
    id UInt16,
    opcode UInt8,
    latency Float64,
    qr Bool,
    tc Bool,
    aa Bool,
    ra Bool,
    ad Bool,
    rd Bool,
    cd Bool,
    malformed_packet Bool,
    tld LowCardinality(String),
    etld_plus_one LowCardinality(String),
    city LowCardinality(String),
    country LowCardinality(String),
    as_number UInt32,
    as_owner LowCardinality(String),
    suspicious_score Float64
) ENGINE = MergeTree()
PARTITION BY toYYYYMM(timestamp)
ORDER BY (timestamp, qname);
```
