# Performance Monitoring

To understand and optimize the performance of DNS-collector, you should enable telemetry. Telemetry allows you to monitor the internal pipeline traffic, detect bottlenecks, and see if any packets are being discarded.

## Why Enable Telemetry?

By enabling the process telemetry, you gain real-time visibility into:
- Ingress and egress message rates per pipeline worker.
- Dropped and discarded message counts (crucial for buffer sizing).
- System resource usage (CPU, memory allocations, goroutines count).

## How to Enable Telemetry

Enable telemetry in the `global` section of your configuration:

```yaml
global:
  telemetry:
    enabled: true
    web-listen: ":9165"
    web-path: "/metrics"
    prometheus-prefix: "dnscollector"
```

For the complete guide on telemetry endpoints, Go runtime exporter dashboards, and the list of exposed performance metrics, please refer to the [Telemetry & Monitoring](../telemetry.md) page.
