# DNS-collector - Performance tuning


## Overview

DNS-collector can handle high-volume DNS traffic with proper tuning. This guide helps you optimize performance for large-scale deployments and understand the performance implications of different configuration choices.

## Performance Monitoring

### Built-in Metrics

DNS-collector provides comprehensive performance metrics through Prometheus endpoints:

```yaml
global:
  telemetry:
    enabled: true
    web-listen: ":9165"
    web-path: "/metrics"
    prometheus-prefix: "dnscollector"
```

### Key Performance Metrics

**Throughput Metrics**
- `dnscollector_input_packets_total` - Total packets received by collectors
- `dnscollector_output_packets_total` - Total packets processed by loggers
- `dnscollector_forwarded_packets_total` - Packets successfully forwarded
- `dnscollector_dropped_packets_total` - Packets dropped due to errors

**Buffer Metrics**
- `dnscollector_buffer_usage` - Current buffer utilization
- `dnscollector_buffer_dropped_total` - Packets dropped due to full buffers

**System Metrics**
- `dnscollector_memory_usage_bytes` - Memory consumption
- `dnscollector_cpu_usage_percent` - CPU utilization
- `dnscollector_goroutines_total` - Active goroutines


### Grafana Dashboard

A pre-built Grafana dashboard is available for comprehensive monitoring:

```bash
# Import the dashboard JSON
curl -O https://raw.githubusercontent.com/dmachard/DNS-collector/main/docs/dashboards/grafana_exporter.json
```

![Performance Dashboard](docs/_images/dashboard_global.png)

## Buffer Optimization

### Understanding Buffers

All collectors and loggers use buffered channels for data flow. Buffer sizing is critical for high-throughput scenarios.

### Buffer Configuration

```yaml
global:
  worker:
    buffer-size: 8192    # Default size
    # For high traffic, consider: 16384, 32768, or 65536
```

### Buffer Full Warning

If you see this warning, increase your buffer size:

```bash
logger[elastic] buffer is full, 7855 packet(s) dropped
```