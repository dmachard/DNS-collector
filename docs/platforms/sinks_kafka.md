# Kafka Integration

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
