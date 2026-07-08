# InfluxDB Integration

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
