# Performance & Memory Tuning

To handle high-volume DNS traffic with low latency and optimal resource consumption, DNS-collector can be tuned across its internal pipeline buffers, Go runtime parameters, and collector settings.

---

## 1. Pipeline Buffer & Batching Tuning

### Understanding Channel Batching
All workers (collectors, transformers, and loggers) communicate via pooled message batches (`*dnsutils.DNSMessageBatch`) over buffered Go channels. Batching reduces channel lock contention and memory allocations.

### Global Worker Configuration

Queue size and batching parameters are configured under `global.worker`:

```yaml
global:
  worker:
    interval-monitor: 10     # Monitoring interval in seconds
    buffer-size: 512         # Channel buffer capacity in batches (Default: 512)
    batch-size: 64           # Maximum messages per batch (Default: 64)
    flush-interval-ms: 10    # Maximum flush delay for partial batches (Default: 10ms)
```

- **Retention Capacity**: Total messages buffered = `buffer-size * batch-size` (e.g. `512 * 64 = 32,768` messages).
- **Sweet Spot (`batch-size: 64`)**: Provides maximum throughput (+40% speedup vs unbatched) while keeping packet transit latency under 10ms.
- **Buffer Size Tuning**:
  - `buffer-size: 256` or `512`: Recommended for low-memory environments (bounds buffer RSS to ~25-40 MB).
  - `buffer-size: 1024` or `2048`: Recommended for high-burst environments absorbing sudden spikes of 100k+ packets.

### Detecting Buffer Exhaustion
If a destination logger (e.g., Elasticsearch, ClickHouse, Kafka) experiences slow ingestion, its channel buffer may fill up:

```log
logger[elastic] buffer is full, 7855 packet(s) dropped
```

If you see these warnings:
1. Increase `buffer-size` (e.g., to `1024` or `2048`).
2. Scale downstream logger workers or optimize sink batch ingestion.

---

## 2. Memory & Garbage Collection Tuning (`GOMEMLIMIT` & `GOGC`)

Under massive burst workloads (> 1M packets/sec), the Go runtime memory consumption can be strictly bounded using environment variables.

### Setting a Hard Memory Limit (`GOMEMLIMIT`)
Go 1.19+ supports `GOMEMLIMIT`, which instructs the Go runtime to proactively run garbage collection to keep the total heap under a specified budget without risking Out-Of-Memory (OOM) kills:

```bash
# Set a soft memory ceiling of 50 MiB
GOMEMLIMIT=50MiB ./dnscollector -config config.yml
```

### Tuning Garbage Collection Frequency (`GOGC`)
`GOGC` sets the percentage of newly allocated memory relative to the live heap before the next GC cycle runs (default is `100`):

```bash
# More aggressive GC during traffic spikes (reduces peak RSS to ~30-40 MB)
GOGC=50 ./dnscollector -config config.yml
```

### Recommended Production Environments

#### Docker / Kubernetes Container
```yaml
env:
  - name: GOMEMLIMIT
    value: "60MiB"
  - name: GOGC
    value: "75"
resources:
  limits:
    memory: "100Mi"
  requests:
    memory: "50Mi"
```

#### Systemd Service (`/etc/systemd/system/dnscollector.service`)
```ini
[Service]
Environment="GOMEMLIMIT=60MiB"
Environment="GOGC=75"
ExecStart=/usr/local/bin/dnscollector -config /etc/dnscollector/config.yml
```

---

## 3. Collector Performance Tuning (DNSTap)

For collectors receiving massive stream rates (> 500k queries/sec):

### 1. Enable Fast Wire Decoder (Default: `true`)
Ensure `fast-decoder: true` is enabled in your `dnstap` collector configuration to use the zero-allocation Protobuf decoder:

```yaml
collectors:
  dnstap:
    enable: true
    fast-decoder: true   # Eliminates Protobuf reflection & heap allocations
```

### 2. Tune Socket Read Buffer Size
Under heavy single-connection throughput, increasing `sock-read-buffer-size` reduces system call overhead:

```yaml
collectors:
  dnstap:
    sock-read-buffer-size: 65536  # 64 KB read buffer
```

### 3. Parallel Processing (`num-workers`)
By default, each connection runs single-threaded to guarantee strict message ordering. For multi-core scaling under massive single-socket ingress:

```yaml
collectors:
  dnstap:
    num-workers: 4  # Distribute message decoding across 4 worker goroutines
```

### 4. Minimal DNS Payload Parsing (`disable-dnsparser`)
If your pipeline only requires transport and DNSTap metadata (IPs, ports, latency, timestamps, message types) and does not need parsed DNS payload fields (`qname`, `qtype`, `rcode`, resource records), disabling the DNS parser completely eliminates payload parsing overhead:

```yaml
collectors:
  dnstap:
    disable-dnsparser: true  # Skips DNS RFC 1035 payload decoding entirely
```



