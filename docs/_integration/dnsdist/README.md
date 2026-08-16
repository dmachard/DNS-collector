# DNSdist + DNS-collector Local Development Environment

This folder provides a complete local development and testing environment using `docker-compose` to test `dnsdist` streaming DNSTap frames to `dnscollector`.

## Prerequisites

- [Docker](https://docs.docker.com/get-docker/)
- [Docker Compose](https://docs.docker.com/compose/)

## How to Run

1. Navigate to this directory:
   ```bash
   cd docs/_integration/dnsdist
   ```

2. Start the services:
   ```bash
   docker compose up
   ```

3. Test sending DNS queries to `dnsdist`:
   ```bash
   dig @127.0.0.1 -p 5300 example.com
   ```

4. Watch the `dnscollector` logs to see the incoming DNSTap messages printed in real time.
