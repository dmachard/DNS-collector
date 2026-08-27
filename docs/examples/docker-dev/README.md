# Local Docker Development & Testing Stack

This example demonstrates running **DNS-collector** alongside **dnsdist** and **Prometheus** using Docker Compose.

## Architecture

- **dnsdist**: Listens on port `53` (UDP/TCP), forwards DNS queries to `1.1.1.1`, and streams DNSTap frames to `dnscollector:6000`.
- **dnscollector**: Receives DNSTap frames, logs queries in `flat-json` on stdout, and exposes metrics on port `8080`.
- **prometheus**: Scrapes DNS-collector metrics on port `8080` every 5 seconds.

## Usage

Start the stack:

```bash
docker compose up -d
```

Send a test DNS query:

```bash
dig @127.0.0.1 -p 53 example.com
```

Inspect DNS-collector logs:

```bash
docker logs -f dnscollector-dev
```

Access Prometheus:

Open [http://localhost:9090](http://localhost:9090) in your browser.
