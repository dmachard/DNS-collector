<p align="center">
  <img src="https://goreportcard.com/badge/github.com/dmachard/DNS-collector" alt="Go Report"/>
  <img src="https://img.shields.io/badge/go%20version-min%201.24-green" alt="Go version"/>
  <img src="https://img.shields.io/badge/go%20tests-520-green" alt="Go tests"/>
  <img src="https://img.shields.io/badge/go%20coverage-68%25-green" alt="Go coverage"/>
  <img src="https://img.shields.io/badge/go%20bench-21-green" alt="Go bench"/>
  <img src="https://img.shields.io/badge/go%20lines-15469-green" alt="Go lines"/>
</p>

<p align="center">
  <img src="https://img.shields.io/github/v/release/dmachard/DNS-collector?logo=github&sort=semver" alt="release"/>
  <img src="https://img.shields.io/docker/pulls/dmachard/go-dnscollector.svg" alt="docker"/>
</p>

<p align="center">
  <img src="docs/dns-collector_logo.png" alt="DNS-collector"/>
</p>

## What is DNS-collector?

**DNS-collector** is a lightweight tool that captures DNS queries and responses from your DNS servers, processes them intelligently, and sends clean data to your monitoring or analytics systems.

What it does:
- **Captures DNS data** from your DNS servers (BIND, PowerDNS, Unbound, etc.) via DNStap protocol or live network capture
- **Filters out noise** like health checks, internal queries, or spam before storage
- **Enriches data** with GeoIP, threat intelligence, or custom metadata  
- **Outputs clean data** to files, databases, SIEM tools, or monitoring dashboards

## Why DNS-collector?

The missing piece between DNS servers and your data stack.

- **DNS-native processing**: Understands DNS protocol, EDNS, query types natively
- **Process at the edge**: Clean, filter and enrich DNS data before storage - not after
- **Multiple input sources**: DNStap streams, live network capture, log files
- **DNS-aware transformations**: Filtering noise upstream, user privacy
- **Flexible outputs**: Files, syslog, databases, monitoring tools and more...
- **Production ready**: Used in real networks, tested with major DNS servers
- **Enhanced DNStap**: TLS encryption, compression, and more metadata capabilities

## 🚀 Quick Start

Download the [latest release](https://github.com/dmachard/DNS-collector/releases) and run with default config:
Default setup listens on tcp/6000 for DNStap streams and outputs to stdout.
To get started quickly, you can use this default [`config.yml`](config.yml).

```bash
./dnscollector -config config.yml
```

![run](docs/_images/terminal.gif)

## 📚 Documentation

| Topic | Description |
|-------|-------------|
| [📝 Formats](docs/formats.md) | Supported output formats (text, JSON, PCAP, Jinja2, etc.) |
| [🔧 Configuration](docs/configuration.md) | Complete config reference |
| [📤 Workers](docs/workers.md) | Input sources and output destinations setup |
| [🔄 Transformers](docs/transformers.md) | Data enrichment options |
| [🐳 Docker](docs/docker.md) | Container deployment |
| [🔍 Examples](docs/examples.md) | Ready-to-use configs |
| [🔗 Integrations](docs/integrations.md) | Integration with popular tools and DNS servers |
| [⭐ Extended DNStap](docs/extended_dnstap.md) | Extended DNSTap |
| [📊 Telemetry](docs/telemetry.md) | REST API and Prometheus metrics |
| [⚡ Performance](docs/performance.md) | Tuning guide |

## 👥 Contributions

Contributions are welcome!
Check out:
- [Contribution Guide](CONTRIBUTING.md)
- [Architecture Guide](docs/architecture.md)
- [Development Guide](docs/development.md)

## 🧰 Related Projects:

- [DNS-tester](https://github.com/dmachard/DNS-tester) - DNS testing toolkit
- [CoreDNS-GSLB](https://github.com/dmachard/coredns-gslb) - Global Server Load Balancing functionality in CoreDNS
