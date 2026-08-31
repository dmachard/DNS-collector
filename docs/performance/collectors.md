# Collector Performance Tuning

For collectors receiving massive stream rates (> 500k queries/sec), several tuning knobs are available to maximize wire throughput.

---

## 1. Enable Fast Wire Decoder (Default: `true`)

Ensure `fast-decoder: true` is enabled in your `dnstap` collector configuration to use the zero-allocation Protobuf decoder:

```yaml
collectors:
  dnstap:
    enable: true
    fast-decoder: true   # Eliminates Protobuf reflection & heap allocations
```

---

## 2. Tune Socket Read Buffer Size

Under heavy single-connection throughput, increasing `sock-read-buffer-size` reduces system call overhead:

```yaml
collectors:
  dnstap:
    sock-read-buffer-size: 65536  # 64 KB read buffer
```

---

## 3. Parallel Processing (`num-workers`)

By default, each connection runs single-threaded to guarantee strict message ordering. For multi-core scaling under massive single-socket ingress:

```yaml
collectors:
  dnstap:
    num-workers: 4  # Distribute message decoding across 4 worker goroutines
```

---

## 4. Minimal DNS Payload Parsing (`disable-dnsparser`)

If your pipeline only requires transport and DNSTap metadata (IPs, ports, latency, timestamps, message types) and does not need parsed DNS payload fields (`qname`, `qtype`, `rcode`, resource records), disabling the DNS parser completely eliminates payload parsing overhead:

```yaml
collectors:
  dnstap:
    disable-dnsparser: true  # Skips DNS RFC 1035 payload decoding entirely
```

---

## 5. Upstream Batching (`upstream-batching`)

In ultra-high throughput environments (> 3M - 6M+ queries/sec) on multi-core servers, transmitting frames individually through Go channels introduces channel lock contention and cache-line bouncing between CPU cores.

Enabling `upstream-batching` groups frames into pooled `RawBatch` structures before dispatching them to decoder workers:

```yaml
collectors:
  dnstap:
    upstream-batching: true   # Eliminates channel contention at 3M+ QPS
```

* **When to enable**: Multi-core systems (8+ cores) processing multi-million QPS streams over a single connection where maximizing throughput (+15%) and reducing CPU time (-20%) is paramount.
* **When to keep disabled (default)**: Low-to-moderate traffic (< 2M QPS) or resource-constrained environments (1-2 vCPUs) where minimizing memory footprint (~60 MB RSS) is prioritized.

