# DNS-collector - Workers

## Supported Collectors

Collectors are responsible for gathering DNS data from different sources. They act as the input layer of your DNS monitoring pipeline.

### Network-Based Collectors

| Collector | Description |
|-----------|-------------|
| [AF_PACKET Sniffer](collectors/collector_afpacket.md) | Live packet capture using AF_PACKET sockets | 
| [XDP Sniffer](collectors/collector_xdp.md) | High-performance live packet capture using XDP (eXpress Data Path) |

### Network Streaming Collectors

| Collector | Description |
|-----------|-------------|
| [DNStap Server](collectors/collector_dnstap.md) | Integration with DNS servers supporting DNStap (BIND, Unbound, PowerDNS) **Full support**  |
| [PowerDNS](collectors/collector_powerdns.md) | Direct integration with PowerDNS authoritative and recursive servers **Full support** |
| [TZSP](collectors/collector_tzsp.md) | TZSP network protocol (Beta support) |

### File-Based Collectors
| Collector | Description |
|-----------|-------------|
| [File Ingestor](collectors/collector_fileingestor.md) | Processes stored network captures (PCAP or DNStap files) |
| [Tail](collectors/collector_tail.md) | Monitors and parses plain text log files |

### Specialized Collectors
| Collector | Description |
|-----------|-------------|
| [DNS Message](collectors/collector_dnsmessage.md) | Filters and matches specific DNS messages |

## Supported Loggers

Loggers handle the output and processing of collected DNS data. They provide various formats and destinations for your DNS logs.

### Console & File Output
| Logger | Description |
|--------|-------------|
| [Console](loggers/logger_stdout.md) | Outputs logs to standard output (Text, JSON, Binary) |
| [File](loggers/logger_file.md) | Saves logs to local files (Plain text, Binary) |

### Network Streaming
| Logger | Description |
|--------|-------------|
| [DNStap Client](loggers/logger_dnstap.md) | Forwards logs in DNStap format over TCP/Unix sockets |
| [TCP](loggers/logger_tcp.md) | Streams logs over TCP connections |
| [Syslog](loggers/logger_syslog.md) | Sends logs via syslog protocol (RFC3164/RFC5424) |

### Metrics & Monitoring
| Logger | Description |
|--------|-------------|
| [Prometheus](loggers/logger_prometheus.md) | Exposes DNS metrics for Prometheus scraping |
| [Statsd](loggers/logger_statsd.md) | Sends metrics in StatsD format **Not production ready** |
| [Rest API](loggers/logger_restapi.md) | Provides REST endpoints for log searching |

### Time-Series Databases
| Logger | Description |
|--------|-------------|
| [InfluxDB](loggers/logger_influxdb.md) | Stores DNS metrics and logs in InfluxDB v1.x/v2.x |
| [ClickHouse](loggers/logger_clickhouse.md) | High-performance analytics database **Not production ready** |

### Log Aggregation Platforms
| Logger | Description |
|--------|-------------|
| [Fluentd](loggers/logger_fluentd.md) | Forwards logs to Fluentd collectors |
| [Loki Client](loggers/logger_loki.md) | Sends logs to Grafana Loki |
| [ElasticSearch](loggers/logger_elasticsearch.md) | Indexes logs in Elasticsearch |
| [Scalyr](loggers/logger_scalyr.md) | Sends logs to DataSet/Scalyr platform |

### Message Queues & Streaming
| Logger | Description |
|--------|-------------|
| [Redis Publisher](loggers/logger_redis.md) | Publishes logs to Redis pub/sub channels |
| [Kafka Producer](loggers/logger_kafka.md) | Sends logs to Apache Kafka topics |

### Specialized Loggers
| Logger | Description |
|--------|-------------|
| [Falco](loggers/logger_falco.md) | Integration with Falco security monitoring |
| [OpenTelemetry](loggers/logger_opentelemetry.md) | Distributed tracing support **Experimental** |
| [DevNull](loggers/logger_devnull.md) | Discards all logs (Performance testing) |