# Transformer: Unique Response Tracker (UDR)

The **Unique Response Tracker** (Unique Domain Responses / UDR) transformer identifies DNS responses that contain new resource record associations `(QNAME, RRType, RDATA)` never seen before within a configurable time window.

While Newly Observed Domains (NOD) tracks newly seen domain queries on the request side, Unique Response Tracking (UDR) tracks changes on the **response side**. It is especially effective for detecting:

- **DNS Hijacking & Cache Poisoning** (a trusted domain suddenly resolving to an unexpected IP or rogue CNAME).
- **Fast-Flux DNS networks** and dynamic C2 infrastructure.
- **Unauthorized record changes** in authoritative zones.

---

## Features

- **Tuple-based Tracking**: Tracks the `(QNAME, RRType, RDATA)` triplet in the `Answer` section of DNS replies.
- **Configurable Time Window (TTL)**: Defines how long an answer tuple is remembered.
- **Dual Storage Engine**: Choose between LRU (optimized for speed) or Cuckoo Filter (optimized for memory).
- **Memory Management**: Fixed bounded memory with zero memory leaks.
- **Disk Persistence**: Optionally persist the observed answer cache to disk across restarts (LRU engine only).
- **Whitelist Support**: Exclude specific domains or regex patterns from detection.

---

## How It Works

1. When a DNS reply with answers is received, the transformer checks each `(QNAME, RRType, RDATA)` tuple against the cache.
2. If any answer record is observed for the first time (or expired from cache), the message is kept (`ReturnKeep`).
3. If all answer records in the reply have already been observed within the TTL, the message is dropped (`ReturnDrop`).
4. Whitelisted domains are ignored and never flagged as unique.

---

## Configuration

* `enable` (bool)
  > Enable the unique response tracker (default: `false`)

* `ttl` (integer)
  > Time window in seconds (default: `86400` / 24h)

* `cache-size` (integer)
  > Maximum number of unique response tuples to track in memory (default: `100000`)

* `storage-engine` (string)
  > Storage backend: `"lru"` or `"cuckoo"` (default: `"lru"`)
  > - **LRU**: Optimized for speed (~192 ns/op). Best for most deployments. Supports disk persistence.
  > - **Cuckoo**: Optimized for memory (~81% reduction). Use for memory-constrained environments (edge nodes, Kubernetes pods with strict limits).

* `cuckoo-fingerprint-bits` (integer)
  > Fingerprint bit width when using the `"cuckoo"` storage engine: `8`, `16`, or `32` (default: `16`)
  > - **16 bits** (default): ~5.8 MB for 100k items, ~0.01% false positive rate (recommended optimal balance).
  > - **8 bits**: ~2.9 MB for 100k items, ~2.3% false positive rate (ultra-low RAM environments).
  > - **32 bits**: ~11.6 MB for 100k items, $< 10^{-7}\%$ false positive rate (near zero false positive tolerance).

* `white-domains-file` (string)
  > Path to domain whitelist file with regex expressions

* `persistence-file` (string)
  > Path to a JSON persistence file to save and restore cache across restarts (LRU engine only)

```yaml
transforms:
  unique-response-tracker:
    enable: true
    ttl: 86400 
    cache-size: 100000
    storage-engine: "cuckoo"
    cuckoo-fingerprint-bits: 16
    white-domains-file: ""
    persistence-file: "/var/lib/dnscollector/udr_cache.json"
```

---

## Storage Engines

### LRU Cache (Default)

The default storage engine uses an **LRU (Least Recently Used) Cache** optimized for throughput and minimal latency.

**Performance Characteristics:**
- **Lookup Speed**: ~192 ns/op (measured with realistic mixed DNS workload: 80% lookups, 20% inserts)
- **Memory Footprint**: ~30.84 MB for 100,000 tuples
- **Allocations**: 1 per operation (minimal garbage collection pressure)
- **Persistence**: Supports disk caching across daemon restarts
- **Best For**: Standard deployments where latency and throughput matter most

**Cache Management:**
Once the cache reaches its `cache-size` limit, the least recently seen tuples are evicted automatically. The eviction policy ensures predictable memory usage.

### Cuckoo Filter (Optional)

The **Cuckoo Filter** is a probabilistic data structure optimized for extreme memory efficiency and zero allocations.

**Performance Characteristics:**
- **Lookup Speed**: ~38 ns/op (direct bucket probe, zero garbage collection pressure)
- **Memory Footprint**: ~5.80 MB for 100,000 tuples (81% reduction vs LRU)
- **Allocations**: 0 per operation (`0 B/op`)
- **Persistence**: Not currently supported (in-memory generational tables)
- **False Positive Rate**: < 0.01% with default 16-bit fingerprints
- **Best For**: Memory-constrained deployments (edge nodes, Kubernetes pods, embedded systems)

**Configurable Fingerprint Bit Widths (`cuckoo-fingerprint-bits`):**

| Fingerprint Width | Memory (100k items) | False Positive Rate | Trade-off / Best Use Case |
|---|---|---|---|
| **`16 bits` (Default)** | **~5.8 MB** | **~0.012%** ($\approx 1/10000$) | **Recommended**: Ideal balance of accuracy and memory. |
| **`8 bits`** | **~2.9 MB** | **~2.3%** ($\approx 1/40$) | Extreme memory-constrained edge/IoT nodes. |
| **`32 bits`** | **~11.6 MB** | **$< 10^{-7}\%$** | Ultra-high fidelity (near-zero collision tolerance). |

**Trade-offs & Anti-Saturation Mechanism:**
- **Generational Anti-Churning**: Unlike single-table filters that suffer from high eviction churn when nearly full, the UDR sliding window maintains `active` and `previous` generation tables. New entries are always inserted into a fresh `active` table ($O(1)$ with no kicks), while hot entries are seamlessly promoted from `previous` upon hit.
- **Zero Eviction Scan Cost**: Stale/cold entries naturally expire when the `previous` table is rotated at $TTL/2$, requiring zero background deletion loops or CPU sweeps.

---

## Cache & Persistence

### LRU Engine Cache

The LRU engine uses an **LRU Cache** to manage memory consumption with automatic eviction of least-used entries.

To preserve the learned cache across daemon restarts, specify `persistence-file`. On shutdown, the cache is saved as JSON and automatically reloaded on startup.

```bash
# Monitor LRU cache growth
du -h /var/lib/dnscollector/udr_cache.json
```

### Cuckoo Engine Cache

The Cuckoo Filter operates entirely in-memory with a dual sliding window (`active` and `previous` generation tables rotated every `TTL / 2`):
- **Hot Item Residency (LRU Promotion)**: Continuously queried domains ("hot items") observed in the previous generation are automatically promoted to the active window, ensuring active traffic never prematurely expires.
- **Automatic Stale Eviction**: Inactive tuples that receive no traffic across two rotation cycles are automatically forgotten.
- **Bounded Memory**: Memory footprint remains fixed and bounded by `cache-size` (~5.8 MB for 100k items).
- **Purely In-Memory**: No disk I/O, zero garbage collector allocations during lookups.

---

## Whitelist

You can specify a file with regular expressions to whitelist domains that change frequently (e.g. CDNs or dynamic load balancers) so they do not trigger false alerts.

Example content for `white-domains-file`:

```
.*\.cdn\.cloudflare\.net$
.*\.trafficmanager\.net$
```
