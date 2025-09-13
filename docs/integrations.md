# DNS-collector - Integration Guide

This guide covers compatibility, configuration, and integration examples.

## Tested DNS Server Compatibility

[Enabling DNStap logging on most popular DNS servers](https://dmachard.github.io/posts/0001-dnstap-testing/)

| DNS Server | Versions | Transport Modes |
|------------|----------|-----------------|
| ✅ **Unbound** | 1.22.x, 1.21.x | TCP |
| ✅ **CoreDNS** | 1.12.1, 1.11.1 | TCP, TLS |
| ✅ **PowerDNS DNSdist** | 2.0.x, 1.9.x, 1.8.x, 1.7.x | TCP, Unix |
| ✅ **Knot Resolver** | 6.0.11 | Unix |
| ✅ **BIND** | 9.18.33 | Unix |


## Sink Integration Ecosystem

DNS-collector supports seamless integration with popular observability and data processing platforms through pre-configured templates and Docker Compose examples. The [`_integration`](./_integration) folder contains preconfigured files and `docker compose` examples:

- [Fluentd](./_integration/fluentd/README.md)
- [Elasticsearch](./_integration/elasticsearch/README.md)
- [Kafka](./_integration/kafka/README.md)
- [InfluxDB](./_integration/influxdb/README.md)
- [Prometheus](./_integration/prometheus/README.md)
- [Loki](./_integration/loki/README.md)
