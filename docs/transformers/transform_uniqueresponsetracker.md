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
- **LRU-based Memory Management**: Ensures fixed bounded memory with zero memory leaks.
- **Disk Persistence**: Optionally persist the observed answer cache to disk across restarts.
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

* `white-domains-file` (string)
  > Path to domain whitelist file with regex expressions

* `persistence-file` (string)
  > Path to a JSON persistence file to save and restore cache across restarts

```yaml
transforms:
  unique-response-tracker:
    enable: true
    ttl: 86400 
    cache-size: 100000
    white-domains-file: ""
    persistence-file: "/var/lib/dnscollector/udr_cache.json"
```

---

## Cache & Persistence

The Unique Response Tracker uses an **LRU Cache** to manage memory consumption. Once the cache reaches its `cache-size` limit, the least recently seen tuples are evicted.

To preserve the learned cache across daemon restarts, specify `persistence-file`. On shutdown, the cache is saved as JSON and automatically reloaded on startup.

---

## Whitelist

You can specify a file with regular expressions to whitelist domains that change frequently (e.g. CDNs or dynamic load balancers) so they do not trigger false alerts.

Example content for `white-domains-file`:

```
.*\.cdn\.cloudflare\.net$
.*\.trafficmanager\.net$
```
