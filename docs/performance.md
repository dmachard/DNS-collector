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


### Throughput Metrics

- `dnscollector_worker_ingress_traffic_total`  
  Total number of DNS messages received by each worker. Reflects successful handoff to the next internal
  worker only, **not external delivery guarantees**. Message loss due to temporary output unavailability is tracked via `dnscollector_worker_discarded_traffic_total`.

- `dnscollector_worker_egress_traffic_total`  
  Total number of DNS messages successfully passed to the next stage by each worker.  
  This does **not** guarantee delivery to external systems.

- `dnscollector_worker_discarded_traffic_total`  
  Counts messages dropped when worker output channels are full or when messages
  are intentionally discarded to avoid blocking the pipeline or when external system are temporary unavailability of the output.

- `dnscollector_policy_forwarded_total`  
  Total number of DNS messages forwarded by policy rules.

- `dnscollector_policy_dropped_total`  
  Total number of DNS messages dropped by policy rules.

### Runtime & System Metrics (Go runtime)

The following metrics are **automatically exposed by the Prometheus Go client**
and are **not specific to dnscollector**:

- `go_goroutines`  
  Current number of active goroutines.

- `go_memstats_alloc_bytes`  
  Number of bytes allocated and still in use.

- `go_memstats_heap_alloc_bytes`  
  Heap memory currently allocated.

- `process_cpu_seconds_total`  
  Total user and system CPU time spent in seconds.

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