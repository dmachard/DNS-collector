# Transformer: Frequency Filtering (Heavy Hitters & Adaptive Sampling)

The `frequency-filtering` transformer performs streaming frequency estimation using an ultra-low-memory **Counting Cuckoo Filter**. It enables real-time identification of top-talkers / heavy-hitters (such as high-volume domains or abusive client IPs) and applies adaptive downsampling, flood dropping, or security tagging.

## Use Cases

* **SIEM Cost Reduction / Log Downsampling**: High-frequency repetitive domains (e.g. `google.com`, `apple.com`) can be downsampled (e.g. keep only 1 in 100 queries) while ensuring **100% of rare and novel domains** (C2 beaconing, DGA malware) are preserved and sent to security sinks.
* **DDoS & Water Torture Mitigation**: Instantly identify domains or IPs undergoing flood attacks and drop them before reaching backend loggers.
* **Real-time Threat Tagging**: Mark DNS messages with their observed frequency (`dm.Frequency.Count` and `dm.Frequency.IsHeavyHitter`) for downstream pipeline routing.

## Options

* `enable` (boolean, default: `false`)
  > Enables the frequency-filtering transformer.

* `track-by` (string, default: `"qname"`)
  > The message attribute to track and count. Supported values:
  > - `"qname"`: Track the exact queried domain name.
  > - `"domain"`: Track the effective second-level domain (eTLD+1, requires `normalize` enabled).
  > - `"query-ip"`: Track the client resolver / source IP address.

* `threshold` (integer, default: `1000`)
  > Frequency threshold. When a key is seen more than `threshold` times within the sliding window, it is classified as a heavy hitter.

* `window-seconds` (integer, default: `60`)
  > Sliding window half-life in seconds. Every `window-seconds`, all frequency counts in the filter are halved (`Decay(0.5)`), evicting cold entries and continuously adapting to changing traffic.

* `sample-rate` (integer, default: `100`)
  > Downsampling factor applied to heavy hitters:
  > - `sample-rate: 100`: Retain 1 query out of every 100 heavy-hitter queries (drops 99%).
  > - `sample-rate: 0`: Drop 100% of heavy-hitter queries (flood mitigation).
  > - Normal / rare queries (count <= `threshold`) are always 100% kept.

* `tag-only` (boolean, default: `false`)
  > When `true`, no queries are dropped or downsampled. Messages are only enriched with the `dm.Frequency` payload.

* `capacity` (integer, default: `100000`)
  > Maximum distinct entries tracked simultaneously by the Counting Cuckoo Filter.

## Default Configuration

```yaml
transforms:
  frequency-filtering:
    enable: false
    track-by: "qname"
    threshold: 1000
    window-seconds: 60
    sample-rate: 100
    tag-only: false
    capacity: 100000
```

## Example: SIEM Downsampling Pipeline

```yaml
pipelines:
  - name: siem-pipeline
    transforms:
      frequency-filtering:
        enable: true
        track-by: "qname"
        threshold: 500
        window-seconds: 60
        sample-rate: 100
        tag-only: false
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
    "tracked_key": "example.com"
  }
}
```
