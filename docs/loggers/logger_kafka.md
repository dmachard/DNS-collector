# Logger: Kafka Producer

Kafka producer, based on [kafka-go](https://github.com/segmentio/kafka-go) library.
It receives DNS messages and sends them to one or more Kafka topics, with support for TLS, SASL, compression, and partitioning.

Behavior
- Connection and Reconnection: The producer connects to the Kafka cluster via the high-level `kafka.Writer`. It automatically discovers partition leaders and handles reconnections and retries in the background.
- Buffering and Flush: DNS messages are buffered in memory and flushed to Kafka in batches either when the buffer reaches batch-size or after flush-interval seconds.
- Partitioning: If partition is set, all messages are sent to that partition. Otherwise, messages are distributed across partitions using the configured `balancer` (default: `round-robin`).

Options:

* `remote-address` (string)
  > Remote addresses.
  > Specifies the remote addresses to connect to, separated by commas (,). This parameter is used to provide the IP addresses of Kafka brokers for initial cluster communication.

* `remote-port` (integer)
  > Remote tcp port.
  > Specifies the remote TCP port to connect to.

* `client-id` (string)
  >Unique identifier for Kafka Client,Using Client IDs to manage client traffic on the Kafka server.

* `connect-timeout` (integer)
  > Specifies the maximum time to wait for a connection attempt to complete.

* `flush-interval` (integer)
  > Specifies the interval between buffer flushes.

* `tls-support` (boolean)
  > Enables or disables TLS (Transport Layer Security) support.
  > If set to true, TLS will be used for secure communication.

* `tls-insecure` (boolean)
  > If set to true, skip verification of server certificate.

* `tls-min-version` (string)
  > Specifies the minimum TLS version that the server will support.

* `ca-file` (string)
  > Specifies the path to the CA (Certificate Authority) file used to verify the server's certificate.

* `cert-file` (string)
  > Specifies the path to the certificate file to be used. This is a required parameter if TLS support is enabled.

* `key-file` (string)
  > Specifies the path to the key file corresponding to the certificate file. This is a required parameter if TLS support is enabled.

* `sasl-support` (boolean)
  > Enable or disable SASL (Simple Authentication and Security Layer) support for Kafka.

* `sasl-username` (string)
  > Specifies the SASL username for authentication with Kafka brokers.

* `sasl-password` (string)
  > Specifies the SASL password for authentication with Kafka brokers

* `sasl-mechanism` (string)
  > Specifies the SASL mechanism to use for authentication with Kafka brokers.
  > SASL mechanism: `PLAIN`, `SCRAM-SHA-512` or `SCRAM-SHA-256` .

* `mode` (string)
  > Specifies the output format for Kafka messages. Output format: `text`, `json`, or `flat-json`.

* `text-format` (string)
  > output text format, please refer to the default text format to see all available [text directives](../formats.md#available-directives), use this parameter if you want a specific format

* `batch-size` (integer)
  > Specifies the size of the batch for DNS messages before they are sent to Kafka.

* `topic` (string)
  > Specifies the Kafka topic to which messages will be forwarded.

* `partition` (integer)
  > Specifies the Kafka partition to which messages will be sent.
  > If partition parameter is null, then use the configured `balancer` (default behavior).

* `balancer` (string)
  > Specifies the balancing algorithm used to distribute messages across partitions when `partition` is null.
  > Supported balancers: `round-robin` (default), `least-bytes`, `hash`, `reference-hash`, `crc32`.
  > Note: `hash` and `reference-hash` use the DNS collector/resolver identity key to preserve message ordering per source.

* `compression` (string)
  > Specifies the compression algorithm to use for Kafka messages.
  > Compression for Kafka messages: `none`, `gzip`, `lz4`, `snappy`, `zstd`.

Defaults:

```yaml
kafkaproducer:
  remote-address: 127.0.0.1
  remote-port: 9092
  connect-timeout: 5
  flush-interval: 30
  tls-support: false
  tls-insecure: false
  sasl-support: false
  sasl-mechanism: PLAIN
  sasl-username: false
  sasl-password: false
  mode: flat-json
  text-format: ""
  batch-size: 100
  topic: "dnscollector"
  partition: null
  balancer: "round-robin"
  compression: none
```
