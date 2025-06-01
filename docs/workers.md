# DNS-collector - Supported Collectors & Loggers

## Supported Collectors

Collectors are responsible for gathering DNS data from different sources. They act as the input layer of your DNS monitoring pipeline.

### Network-Based Collectors

| Collector | Description | Use Case |
|-----------|-------------|----------|
| [AF_PACKET Sniffer](collectors/collector_afpacket.md) | Live packet capture using AF_PACKET sockets | Cross-platform network monitoring with good performance |
| [XDP Sniffer](collectors/collector_xdp.md) | High-performance live packet capture using XDP (eXpress Data Path) | Real-time monitoring with minimal CPU overhead on modern Linux systems |

### Network Streaming

| [DNStap Server](collectors/collector_dnstap.md) | Receives DNStap protocol messages. **Full support** | Integration with DNS servers supporting DNStap (BIND, Unbound, PowerDNS) |
| [PowerDNS](collectors/collector_powerdns.md) | Receives protobuf messages from PowerDNS servers **Full support** | Direct integration with PowerDNS authoritative and recursive servers |
| [TZSP](collectors/collector_tzsp.md) | beta support |  |

### File-Based Collectors

| Collector | Description | Use Case |
|-----------|-------------|----------|
| [File Ingestor](collectors/collector_fileingestor.md) | Processes stored network captures (PCAP or DNStap files) | Offline analysis and batch processing of network captures |
| [Tail](collectors/collector_tail.md) | Monitors and parses plain text log files | Integration with existing DNS server logs |

### Specialized Collectors

| Collector | Description | Use Case |
|-----------|-------------|----------|
| [DNS Message](collectors/collector_dnsmessage.md) | Filters and matches specific DNS messages | Targeted monitoring and alerting based on DNS query patterns |


## Supported Loggers

Loggers handle the output and processing of collected DNS data. They provide various formats and destinations for your DNS logs.

### Console & File Output

| Logger | Description | Output Formats |
|--------|-------------|----------------|
| [Console](loggers/logger_stdout.md) | Outputs logs to standard output | Text, JSON, Binary |
| [File](loggers/logger_file.md) | Saves logs to local files | Plain text, Binary |


### Network Streaming

| Logger | Description | Protocol/Format |
|--------|-------------|-----------------|
| [DNStap Client](loggers/logger_dnstap.md) | Forwards logs in DNStap format | DNStap over TCP/Unix sockets |
| [TCP](loggers/logger_tcp.md) | Streams logs over TCP connections | Custom TCP streaming |
| [Syslog](loggers/logger_syslog.md) | Sends logs via syslog protocol | RFC3164/RFC5424 syslog |

### Metrics & Monitoring

| Logger | Description | Integration |
|--------|-------------|-------------|
| [Prometheus](loggers/logger_prometheus.md) | Exposes DNS metrics for Prometheus scraping | Prometheus monitoring stack |
| [Statsd](loggers/logger_statsd.md) | Sends metrics in StatsD format. **Not production ready** | StatsD/Graphite monitoring |
| [Rest API](loggers/logger_restapi.md) | Provides REST endpoints for log searching | Custom applications and dashboards |

### Time-Series Databases

| Logger | Description | Database |
|--------|-------------|----------|
| [InfluxDB](loggers/logger_influxdb.md) | Stores DNS metrics and logs in InfluxDB | InfluxDB v1.x/v2.x |
| [ClickHouse](loggers/logger_clickhouse.md) | High-performance analytics database. **Not production ready** | ClickHouse OLAP database |


### Log Aggregation Platforms

| Logger | Description | Platform |
|--------|-------------|----------|
| [Fluentd](loggers/logger_fluentd.md) | Forwards logs to Fluentd collectors | Fluentd/td-agent ecosystem |
| [Loki Client](loggers/logger_loki.md) | Sends logs to Grafana Loki | Grafana Loki log aggregation |
| [ElasticSearch](loggers/logger_elasticsearch.md) | Indexes logs in Elasticsearch | Elastic Stack (ELK) |
| [Scalyr](loggers/logger_scalyr.md) | Sends logs to DataSet/Scalyr platform | DataSet cloud logging |

### Message Queues & Streaming

| Logger | Description | Platform |
|--------|-------------|----------|
| [Redis Publisher](loggers/logger_redis.md) | Publishes logs to Redis pub/sub channels | Redis streaming |
| [Kafka Producer](loggers/logger_kafka.md) | Sends logs to Apache Kafka topics | Kafka streaming platform |

### Specialized Loggers

| Logger | Description | Use Case |
|--------|-------------|----------|
| [Falco](loggers/logger_falco.md) | Integration with Falco security monitoring | Cloud-native security monitoring |
| [OpenTelemetry](loggers/logger_opentelemetry.md) | Distributed tracing support **Experimental** | Observability and tracing |
| [DevNull](loggers/logger_devnull.md) | Discards all logs | Performance testing and benchmarking |
