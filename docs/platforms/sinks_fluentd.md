# Fluentd Integration

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
