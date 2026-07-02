# Sink & Observability Integrations

DNS-collector can route DNS events directly to various platforms and databases. This guide provides pre-configured Docker Compose stacks and configuration files to help you get started quickly.

All integration templates and docker-compose files can be found in the repository's `docs/_integration/` directory.

---

## 🚀 Quick Start Stacks

Select a platform tab below to view the setup steps and configuration files.

=== "Loki & Grafana"

    Deploy Loki and Grafana to visualize and query DNS logs in real-time.

    1. Create a `data` folder for storage:
       ```bash
       mkdir -p ./data
       ```

    2. Download and start the Loki Docker Compose stack:
       - [Loki docker-compose.yml](https://github.com/dmachard/DNS-collector/blob/main/docs/_integration/loki/docker-compose.yml)
       ```bash
       docker compose up -d
       ```

    3. Run DNS-collector with the Loki integration configuration:
       - [Loki config.yml](https://github.com/dmachard/DNS-collector/blob/main/docs/_integration/loki/config.yml)
       ```bash
       ./dnscollector -config docs/_integration/loki/config.yml
       ```

    4. Access Grafana at `http://localhost:3000` (default login: `admin` / `badpassword`). Go to **Explore** and search with the query `{job="dnscollector"}`.

=== "Elasticsearch & Kibana"

    Route DNS events into Elasticsearch and visualize them with Kibana.

    1. Download and start the Elasticsearch Docker Compose stack:
       - [Elasticsearch docker-compose.yml](https://github.com/dmachard/DNS-collector/blob/main/docs/_integration/elasticsearch/docker-compose.yml)
       ```bash
       docker compose up -d
       ```

    2. Run DNS-collector with the Elasticsearch integration configuration:
       - [Elasticsearch config.yml](https://github.com/dmachard/DNS-collector/blob/main/docs/_integration/elasticsearch/config.yml)
       ```bash
       ./dnscollector -config docs/_integration/elasticsearch/config.yml
       ```

    3. Go to Kibana at `http://127.0.0.1:5601`. Click **Explore on my own** -> **Discover**, and create an index pattern named `dnscollector` using the time field `dnstap.timestamp-rfc3339ns`.

=== "Prometheus"

    Expose and collect DNS metrics with Prometheus.

    1. Create a `data` folder:
       ```bash
       mkdir -p ./data
       ```

    2. Configure targets in `prometheus.yml` and start the stack:
       - [Prometheus docker-compose.yml](https://github.com/dmachard/DNS-collector/blob/main/docs/_integration/prometheus/docker-compose.yml)
       ```bash
       docker compose up -d
       ```

    3. Run DNS-collector with the Prometheus integration configuration:
       - [Prometheus config.yml](https://github.com/dmachard/DNS-collector/blob/main/docs/_integration/prometheus/config.yml)
       ```bash
       ./dnscollector -config docs/_integration/prometheus/config.yml
       ```

=== "Fluentd"

    Forward DNS logs to Fluentd for parsing and storage.

    1. Download and start the Fluentd Docker Compose stack:
       - [Fluentd docker-compose.yml](https://github.com/dmachard/DNS-collector/blob/main/docs/_integration/fluentd/docker-compose.yml)
       ```bash
       docker compose up -d
       ```

    2. Run DNS-collector with the Fluentd integration configuration:
       - [Fluentd config.yml](https://github.com/dmachard/DNS-collector/blob/main/docs/_integration/fluentd/config.yml)
       ```bash
       ./dnscollector -config docs/_integration/fluentd/config.yml
       ```

    3. Log output will be written to files inside `./data/`.

=== "Kafka"

    Stream DNS traffic into an Apache Kafka topic.

    1. Download and start the Kafka Docker Compose stack:
       - [Kafka docker-compose.yml](https://github.com/dmachard/DNS-collector/blob/main/docs/_integration/kafka/docker-compose.yml)
       ```bash
       docker compose up -d
       ```

    2. Open the Kafka UI at `http://127.0.0.1:8080` to verify the `dnscollector` topic is active.

    3. Run DNS-collector with the Kafka integration configuration:
       - [Kafka config.yml](https://github.com/dmachard/DNS-collector/blob/main/docs/_integration/kafka/config.yml)
       ```bash
       ./dnscollector -config docs/_integration/kafka/config.yml
       ```

=== "InfluxDB"

    Log metrics and time-series data into InfluxDB.

    1. Create a `data` folder:
       ```bash
       mkdir -p ./data
       ```

    2. Start the InfluxDB Docker Compose stack:
       - [InfluxDB docker-compose.yml](https://github.com/dmachard/DNS-collector/blob/main/docs/_integration/influxdb/docker-compose.yml)
       ```bash
       docker compose up -d
       ```

    3. Navigate to `http://127.0.0.1:8086`, create an initial user (Org: `dnscollector`, Bucket: `db_dns`), copy the generated API token, and paste it into the DNS-collector configuration.

    4. Run DNS-collector with the InfluxDB integration configuration:
       - [InfluxDB config.yml](https://github.com/dmachard/DNS-collector/blob/main/docs/_integration/influxdb/config.yml)
       ```bash
       ./dnscollector -config docs/_integration/influxdb/config.yml
       ```
