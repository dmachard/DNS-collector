# Prometheus Integration

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
