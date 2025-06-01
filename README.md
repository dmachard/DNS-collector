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
  Grab your DNS logs, detect anomalies, and finally understand what's happening on your network.
</p>
<p align="center">
  <img src="docs/dns-collector_logo.png" alt="DNS-collector"/>
</p>

## 🔧 Why DNS-collector?

The missing piece between DNS servers and your data stack

- **DNS-native processing**: Understands DNS protocol, EDNS, query types natively
- **Process at the edge**: Clean, filter and enrich DNS data before storage - not after
- **Multiple input sources**: DNStap streams, live network capture, log files
- **DNS-aware transformations**: Filtering noise upstream, user privacy
- **Flexible outputs**: Files, syslog, databases, monitoring tools and more...
- **Production ready**: Used in real networks, tested with major DNS servers

## 🚀 Quick Start

Download the [latest release](https://github.com/dmachard/DNS-collector/releases) and run with default config:
Default setup listens on tcp/6000 for DNStap streams and outputs to stdout.

```bash
./dnscollector -config config.yml
```

![run](docs/_images/terminal.gif)

## 📚 Documentation

| Topic | Description |
|-------|-------------|
| [🔍 Examples](docs/examples.md) | Ready-to-use configs |
| [🔧 Configuration](docs/configuration.md) | Complete config reference |
| [📤 Workers](docs/workers.md) | Input sources and output destinations setup |
| [🔄 Transformers](docs/transformers.md) | Data enrichment options |
| [🐳 Docker](docs/docker.md) | Container deployment |
| [🔗 Integrations](docs/integrations.md) | Popular tools setup |
| [📊 Telemetry](docs/telemetry.md) | REST API and Prometheus metrics |
| [⚡ Performance](docs/performance.md) | Tuning guide |

## 🤝 Contributing

Contributions are welcome! Check out:
- [Architecture](docs/architecture.md)
- [Development guide](docs/development.md)

## 🧰 Related Projects:

- [DNS-tester](https://github.com/dmachard/DNS-tester) - DNS testing toolkit