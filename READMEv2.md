<p align="center">
  <img src="https://goreportcard.com/badge/github.com/dmachard/DNS-collector" alt="Go Report"/>
  <img src="https://img.shields.io/badge/go%20version-min%201.23-green" alt="Go version"/>
  <img src="https://img.shields.io/badge/go%20tests-534-green" alt="Go tests"/>
  <img src="https://img.shields.io/badge/go%20bench-21-green" alt="Go bench"/>
  <img src="https://img.shields.io/badge/go%20lines-33707-green" alt="Go lines"/>
</p>

<p align="center">
  <img src="https://img.shields.io/github/v/release/dmachard/DNS-collector?logo=github&sort=semver" alt="release"/>
  <img src="https://img.shields.io/docker/pulls/dmachard/go-dnscollector.svg" alt="docker"/>
</p>

<p align="center">
  <img src="docs/dns-collector_logo.png" alt="DNS-collector"/>
</p>

Grab your DNS logs, detect anomalies, and finally understand what's happening on your network.

# DNS-collector

`DNS-collector` is a high-performance DNS traffic processor written in Go. It ingests DNS logs from multiple sources (DNStap streams, network capture, log files), transforms them with security analysis and metadata enrichment, then outputs to your favorite monitoring tools.

## Why DNS-collector?

- **Multiple input sources**: DNStap streams, live network capture, log files
- **Smart filtering & transformation**: Traffic filtering, anomaly detection, user privacy
- **Flexible outputs**: Files, syslog, databases, monitoring tools
- **Production ready**: Used in real networks, tested with major DNS servers

## Quick Start

1. Download the [latest release](https://github.com/dmachard/DNS-collector/releases)
2. Run with default config:

```bash
# Download latest release
wget https://github.com/dmachard/DNS-collector/releases/latest

# Run with default config
./dnscollector -config config.yml
```

Default setup listens on tcp/6000 for DNStap streams and outputs to stdout.

![run](docs/_images/terminal.gif)

## Core Features

### 📥 Input Sources (Collectors)
- **DNStap streams**: TCP, TLS, Unix sockets with compression support
- **Network capture**: Live packet capture with IPv4/v6 defragmentation
- **Log files**: Plain text, PCAP files, directory watching
- and more ...

### 🔄 Transform & Filter
- **Traffic filtering**: Block/allow based on domains, IPs, query types
- **Security analysis**: Suspicious traffic detection, newly observed domains
- **Privacy**: User anonymization, data normalization  
- **Performance**: Traffic reduction, message reordering
- and more ...

### 📤 Output Destinations (Loggers)
- **Files & Syslog**: Text, JSON, PCAP, DNStap, local/remote syslog
- **Databases**: InfluxDB, ElasticSearch, Loki
- **Message queues**: Kafka, Redis
- **Monitoring**: Prometheus
- and more ...