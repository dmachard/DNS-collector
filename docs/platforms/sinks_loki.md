# Loki & Grafana Integration

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
