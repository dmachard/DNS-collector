# Loggers

Loggers handle the output, storage, and processing of collected DNS data. They provide various formats and destinations for your DNS logs and act as the output layer of your DNS-collector pipeline.

For a detailed explanation of how these components are configured and chained together, see [Pipeline Routing](pipelines.md).

---

## Logger Categories

### Console & Local Files
Simple and direct local output destinations for debugging or local archiving.

| Logger | Status | Capabilities |
|--------|--------|--------------|
| [Console](loggers/logger_stdout.md) | Production ready | • Outputs logs to standard output (stdout)<br/>• Supports Text, JSON, and raw binary formats |
| [File](loggers/logger_file.md) | Production ready | • Saves logs to local files<br/>• Supports Plain text, JSON, and binary formats<br/>• Rotates log files dynamically |

### Network Streaming & Forwarding
Forwarding raw or processed DNStap streams over standard network protocols.

| Logger | Status | Capabilities |
|--------|--------|--------------|
| [DNStap Client](loggers/logger_dnstap.md) | Production ready | • Forwards logs in DNStap format over TCP/Unix sockets<br/>• Frame stream (fstrm) protocol support |
| [TCP](loggers/logger_tcp.md) | Production ready | • Streams logs over custom TCP connections |
| [Syslog](loggers/logger_syslog.md) | Production ready | • Sends logs via standard syslog protocol (RFC3164/RFC5424)<br/>• Supports TLS encryption |

### Metrics & Monitoring
Exposing and pushing real-time DNS metrics for monitoring dashboards.

| Logger | Status | Capabilities |
|--------|--------|--------------|
| [Prometheus](loggers/logger_prometheus.md) | Production ready | • Exposes Prometheus metric endpoints for scraping<br/>• Real-time query, response, and performance counters |
| [Top-N](loggers/logger_topn.md) | Production ready | • Autonomous periodic Top-N summary reports (domains, clients, rcodes)<br/>• Text tables, JSON digest, and Flat JSON formats |
| [StatsD](loggers/logger_statsd.md) | Beta support | • Sends performance metrics in StatsD format to remote daemons |
| [REST API](loggers/logger_restapi.md) | Beta support | • Provides built-in webserver with REST API endpoints for real-time log searching |

### Time-Series & Analytic Databases
Ingesting DNS records into high-performance analytical databases.

| Logger | Status | Capabilities |
|--------|--------|--------------|
| [ClickHouse](loggers/logger_clickhouse.md) | Beta support | • High-performance columnar database ingestion for large-scale analytics |
| [InfluxDB](loggers/logger_influxdb.md) | Beta support | • Ingests DNS metrics and logs into InfluxDB v1.x/v2.x databases |

### Log Aggregation Platforms
Sending logs to centralized log management and aggregation ecosystems.

> For pre-configured Docker Compose stacks (Loki & Grafana, Elasticsearch & Kibana, Prometheus, Fluentd, Kafka, InfluxDB), see [Integrations & Stacks](platforms/sinks.md).

| Logger | Status | Capabilities |
|--------|--------|--------------|
| [Loki Client](loggers/logger_loki.md) | Production ready | • Streams logs directly to Grafana Loki using the HTTP API |
| [ElasticSearch](loggers/logger_elasticsearch.md) | Production ready | • Indexes logs directly into Elasticsearch cluster |
| [Fluentd](loggers/logger_fluentd.md) | Beta support | • Forwards logs to Fluentd collectors |
| [Scalyr](loggers/logger_scalyr.md) | Beta support | • Sends logs to DataSet/Scalyr log analysis platform |

### Message Queues & Streaming Brokers
Publishing DNS data to streaming platforms and message queues for downstream processing.

| Logger | Status | Capabilities |
|--------|--------|--------------|
| [Redis Publisher](loggers/logger_redis.md) | Production ready | • Publishes logs to Redis pub/sub channels |
| [Kafka Producer](loggers/logger_kafka.md) | Production ready | • Sends logs to Apache Kafka topics with partition key options |
| [NSQ](loggers/logger_nsq.md) | Beta support | • Publishes logs to NSQ topics |
| [MQTT Publisher](loggers/logger_mqtt.md) | Beta support | • Publishes DNS logs to MQTT brokers for IoT/messaging use cases |

### Specialized Loggers
Advanced outputs for security, tracing, or performance benchmarking.

| Logger | Status | Capabilities |
|--------|--------|--------------|
| [Falco](loggers/logger_falco.md) | Beta support | • Integrates with Falco security monitoring to flag anomalies |
| [OpenTelemetry](loggers/logger_opentelemetry.md) | Experimental | • Distributed tracing and metrics support using OpenTelemetry protocols |
| [DevNull](loggers/logger_devnull.md) | Production ready | • Discards all logs (useful for performance testing and benchmarking) |
