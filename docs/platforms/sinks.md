# Sink & Observability Integrations

DNS-collector can route DNS events directly to various platforms and databases. This guide provides pre-configured Docker Compose stacks and configuration files to help you get started quickly.

All integration templates and docker-compose files can be found in the repository's `docs/_integration/` directory.

---

## 🚀 Quick Start Stacks

Select a platform below to view the detailed setup steps and configuration files:

* [Loki & Grafana](./sinks_loki.md) — Visualize and query DNS logs in real-time.
* [Elasticsearch & Kibana](./sinks_elasticsearch.md) — Route DNS events into Elasticsearch and visualize them with Kibana.
* [Prometheus](./sinks_prometheus.md) — Expose and collect DNS metrics with Prometheus.
* [Fluentd](./sinks_fluentd.md) — Forward DNS logs to Fluentd for parsing and storage.
* [Kafka](./sinks_kafka.md) — Stream DNS traffic into an Apache Kafka topic.
* [InfluxDB](./sinks_influxdb.md) — Log metrics and time-series data into InfluxDB.
