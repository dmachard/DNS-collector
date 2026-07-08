# Performance Tuning

To handle high-volume DNS traffic, DNS-collector can be optimized with proper configuration and system tuning. This guide explains how to scale the pipeline and tune buffers.

## Buffer Optimization

### Understanding Channels & Buffers

All collectors (inputs) and loggers (outputs) in DNS-collector communicate via buffered Go channels. In high-throughput environments, if a destination logger (e.g., Elasticsearch, Loki, Kafka) experiences slow ingestion or network latency, its channel buffer can fill up.

Once a buffer is full, DNS-collector will drop subsequent packets to prevent blocking the entire processing pipeline.

### Adjusting Buffer Size

You can configure the channel buffer size globally under the `global.worker` section:

```yaml
global:
  worker:
    buffer-size: 8192    # Default size
    # For high traffic, consider: 16384, 32768, or 65536
```

### Detecting Buffer Exhaustion

If a buffer becomes full and packets are being dropped, you will see warnings in your logs similar to the following:

```log
logger[elastic] buffer is full, 7855 packet(s) dropped
```

If you see these warnings, you should:
1. Increase the buffer size (e.g., to `32768` or `65536`).
2. Optimize your target sink ingestion rate or scale your sinks.
