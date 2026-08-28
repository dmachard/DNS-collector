# Transformer: Frequency Filtering (Heavy Hitters & Adaptive Sampling)

The `frequency-filtering` transformer performs streaming frequency estimation using an ultra-low-memory **Counting Cuckoo Filter**. It enables real-time identification of top-talkers / heavy-hitters (such as high-volume domains or abusive client IPs) and applies adaptive downsampling, flood dropping, or security tagging.

## Use Cases

* **SIEM Cost Reduction / Log Downsampling**: High-frequency repetitive domains (e.g. `google.com`, `apple.com`) can be downsampled (e.g. keep only 1 in 100 queries) while ensuring **100% of rare and novel domains** (C2 beaconing, DGA malware) are preserved and sent to security sinks.
* **DDoS & Water Torture Mitigation**: Instantly identify domains or IPs undergoing flood attacks and drop them before reaching backend loggers.
* **Real-time Threat Tagging & Classification**: Classify DNS messages into frequency tiers (`"rare"`, `"frequent"`, `"heavy"`) for downstream routing.

## Options

* `enable` (boolean, default: `false`)
  > Enables the frequency-filtering transformer.

* `target` (string, default: `"qname"`)
  > The message attribute to track and count. Supported values:
  > - `"qname"`: Track the exact queried domain name.
  > - `"domain"`: Track the effective second-level domain (eTLD+1, requires `normalize` enabled).
  > - `"client-ip"`: Track the client resolver / source IP address.

* `threshold-heavy` (integer, default: `1000`)
  > Frequency threshold. When a key is seen more than `threshold-heavy` times within the sliding window, it is classified as a heavy hitter.

* `action-on-heavy` (string, default: `"drop"`)
  > Action to perform when a query is classified as a heavy hitter:
  > - `"drop"`: Drop 100% of heavy-hitter queries (flood mitigation).
  > - `"sample"`: Retain 1 query out of every `sample-rate` heavy-hitter queries.
  > - `"tag"`: Do not drop any queries; only enrich the message with `dm.Frequency`.

* `sample-rate` (integer, default: `100`)
  > Downsampling factor applied when `action-on-heavy: "sample"`. Only 1 out of every `sample-rate` heavy-hitter queries is kept (e.g., `100` drops 99%).

* `ttl` (integer, default: `300`)
  > Sliding window half-life in seconds. Every `ttl` seconds, all frequency counts in the filter are halved (`Decay(0.5)`), evicting cold entries and continuously adapting to changing traffic.

* `max-capacity` (integer, default: `500000`)
  > Maximum distinct entries tracked simultaneously by the Counting Cuckoo Filter.

## Default Configuration

```yaml
transforms:
  frequency-filtering:
    enable: false
    target: "qname"
    threshold-heavy: 1000
    action-on-heavy: "drop"
    sample-rate: 100
    ttl: 300
    max-capacity: 500000
```

## Example: SIEM Downsampling Pipeline

```yaml
pipelines:
  - name: siem-pipeline
    transforms:
      frequency-filtering:
        enable: true
        target: "qname"
        threshold-heavy: 500
        action-on-heavy: "sample"
        sample-rate: 100
        ttl: 60
    routing-policy:
      forward: [ "siem_logger" ]
```

In this configuration, rare and novel domains (under 500 requests per 60-second window) are 100% forwarded to the SIEM logger.
High-frequency domains exceeding the threshold are downsampled at 1:100 (99% dropped) to reduce SIEM ingestion and storage costs.
Every 60 seconds, frequency counters are halved to continuously adapt to changing traffic patterns.

## Output JSON Schema

When enabled, the `dm.Frequency` field is included in JSON output:

```json
{
  "frequency": {
    "count": 1542,
    "is_heavy_hitter": true,
    "tier": "heavy",
    "target": "example.com"
  }
}
```
