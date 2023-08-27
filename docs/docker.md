# DNS-collector - Docker

## Docker run

Docker run with a custom configuration:

```bash
docker run -d dmachard/go-dnscollector -v $(pwd)/config.yml:/etc/dnscollector/config.yml
```

## Docker-compose

Example with docker-compose

```ini
version: "3.8"

services:
  dnscollector:
    image: dmachard/go-dnscollector:v0.25.0
    environment:
      - "TZ=Europe/Paris"
    volumes:
      - ${APP_CONFIG}/dnscollector/config.yml:/etc/dnscollector/config.yml
      - ${COLLECTOR_DATA}/:/var/dnscollector/
    ports:
      - "8080:8080/tcp"
      - "8081:8081/tcp"
      - "6000:6000/tcp"
```

DNS-collector configuration:

```ini
global:
  trace:
    verbose: true
    log-malformed: true

multiplexer:
  collectors:
    - name: tap
      powerdns:
        listen-ip: 0.0.0.0
        listen-port: 6000
      transforms:
        normalize:
          qname-lowercase: true
          add-tld: true
        suspicious:
          enable: true

  loggers:
    - name: console
      stdout:
        mode: text

    - name: json
      logfile:
        file-path:  /var/dnscollector/dnstap.log 
        mode: text

    - name: api
      restapi:
        listen-ip: 0.0.0.0
        listen-port: 8080

    - name: prom
      prometheus:
        listen-ip: 0.0.0.0
        listen-port: 8081
 
  routes:
    - from: [ tap ]
      to: [ console, json, api, prom ]
```
