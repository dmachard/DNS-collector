# Elasticsearch & Kibana Integration

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
