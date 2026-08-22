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

---

## Collector Performance Tuning (DNSTap)

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


