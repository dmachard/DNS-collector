# Pipeline Buffer & Batching Tuning

All workers (collectors, transformers, and loggers) in DNS-collector communicate via pooled message batches (`*dnsutils.DNSMessageBatch`) over buffered Go channels.

Batching significantly reduces channel lock contention, context switching, and memory allocations in high-throughput pipelines.

---

## Global Worker Configuration

Queue size and batching parameters are configured under the `global.worker` section:

```yaml
global:
  worker:
    interval-monitor: 10     # Monitoring interval in seconds
    buffer-size: 512         # Channel buffer capacity in batches (Default: 512)
    batch-size: 64           # Maximum messages per batch (Default: 64)
    flush-interval-ms: 10    # Maximum flush delay for partial batches (Default: 10ms)
```

---

## Key Tuning Guidelines

- **Retention Capacity**: Total messages buffered = `buffer-size * batch-size` (e.g., `512 * 64 = 32,768` messages).
- **Batch Size Sweet Spot (`batch-size: 64`)**: Provides maximum throughput (+40% speedup vs unbatched) while keeping packet transit latency under 10ms.
- **Buffer Size Tuning**:
  - `buffer-size: 256` or `512`: Recommended for low-memory environments (bounds buffer RSS to ~25-40 MB).
  - `buffer-size: 1024` or `2048`: Recommended for high-burst environments absorbing sudden spikes of 100k+ packets.

---

## Detecting Buffer Exhaustion

If a destination logger (e.g., Elasticsearch, ClickHouse, Kafka) experiences slow ingestion or downstream latency, its channel buffer may fill up:

```log
logger[elastic] buffer is full, 7855 packet(s) dropped
```

If you see these warnings in your logs:
1. Increase `buffer-size` (e.g., to `1024` or `2048`).
2. Scale downstream logger workers or optimize sink batch ingestion.
