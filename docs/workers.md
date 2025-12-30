# DNS-collector - Workers

## Supported Collectors

Collectors are responsible for gathering DNS data from different sources. They act as the input layer of your DNS monitoring pipeline.

### Network-Based Collectors

| Collector | Status | Description |
|-----------|--------|-------------|
| [AF_PACKET Sniffer](collectors/collector_afpacket.md) | Production ready | Live packet capture using AF_PACKET sockets | 
| [XDP Sniffer](collectors/collector_xdp.md) | Experimental | High-performance live packet capture using XDP (eXpress Data Path) |

### Network Streaming Collectors

| Collector | Status | Description |
|-----------|--------|-------------|
| [DNStap Server](collectors/collector_dnstap.md)| Production ready  | Integration with DNS servers supporting DNStap (BIND, Unbound, PowerDNS) **Full support**  |
| [PowerDNS](collectors/collector_powerdns.md)| Production ready | Direct integration with PowerDNS authoritative and recursive servers **Full support** |
| [TZSP](collectors/collector_tzsp.md)| Beta support | TZSP network protocol |

### File-Based Collectors
| Collector | Status | Description |
|-----------|--------|-------------|
| [File Ingestor](collectors/collector_fileingestor.md)| Production ready | Processes stored network captures (PCAP or DNStap files) |
| [Tail](collectors/collector_tail.md)| Production ready | Monitors and parses plain text log files |

### Specialized Collectors
| Collector | Status | Description |
|-----------|--------|-------------|
| [DNS Message](collectors/collector_dnsmessage.md)| Production ready | Filters and matches specific DNS messages |
| [HTTP Webhook](collectors/collector_webhook.md)| Experimental | Adds custom data using HTTP webhooks |

## Supported Loggers

Loggers handle the output and processing of collected DNS data. They provide various formats and destinations for your DNS logs.

### Console & File Output
| Logger | Status | Description |
|--------|--------|-------------|
| [Console](loggers/logger_stdout.md) | Production ready | Outputs logs to standard output (Text, JSON, Binary) |
| [File](loggers/logger_file.md) | Production ready | Saves logs to local files (Plain text, Binary) |

### Network Streaming
| Logger | Status | Description |
|--------|--------|-------------|
| [DNStap Client](loggers/logger_dnstap.md) | Production ready | Forwards logs in DNStap format over TCP/Unix sockets |
| [TCP](loggers/logger_tcp.md) | Production ready | Streams logs over TCP connections |
| [Syslog](loggers/logger_syslog.md) | Production ready | Sends logs via syslog protocol (RFC3164/RFC5424) |

### Metrics & Monitoring
| Logger | Status | Description |
|--------|--------|-------------|
| [Prometheus](loggers/logger_prometheus.md) | Production ready | Exposes DNS metrics for Prometheus scraping |
| [Statsd](loggers/logger_statsd.md) | Beta support | Sends metrics in StatsD format |
| [Rest API](loggers/logger_restapi.md) | Beta support | Provides REST endpoints for log searching |

### Time-Series Databases
| Logger | Status | Description |
|--------|--------|-------------|
| [InfluxDB](loggers/logger_influxdb.md) | Beta support | Stores DNS metrics and logs in InfluxDB v1.x/v2.x |
| [ClickHouse](loggers/logger_clickhouse.md) | Beta support | High-performance analytics database|

### Log Aggregation Platforms
| Logger | Status | Description |
|--------|--------|-------------|
| [Fluentd](loggers/logger_fluentd.md) | Beta support | Forwards logs to Fluentd collectors |
| [Loki Client](loggers/logger_loki.md) | Production ready | Sends logs to Grafana Loki |
| [ElasticSearch](loggers/logger_elasticsearch.md) | Production ready | Indexes logs in Elasticsearch |
| [Scalyr](loggers/logger_scalyr.md) | Beta support | Sends logs to DataSet/Scalyr platform |

### Message Queues & Streaming
| Logger | Status | Description |
|--------|--------|-------------|
| [Redis Publisher](loggers/logger_redis.md) | Production ready | Publishes logs to Redis pub/sub channels |
| [Kafka Producer](loggers/logger_kafka.md) | Production ready | Sends logs to Apache Kafka topics |
| [NSQ](loggers/logger_nsq.md) | Beta support | Publishes logs to NSQ topics |
| [MQTT Publisher](loggers/logger_mqtt.md) | Beta support | Publishes DNS logs to MQTT brokers |

### Specialized Loggers
| Logger | Status | Description |
|--------|--------|-------------|
| [Falco](loggers/logger_falco.md) | Beta support | Integration with Falco security monitoring |
| [OpenTelemetry](loggers/logger_opentelemetry.md) | Experimental | Distributed tracing support |
| [DevNull](loggers/logger_devnull.md) | Production ready | Discards all logs (Performance testing) |
