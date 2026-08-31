# Logger: DevNull

The `devnull` logger acts as a sinkhole (`/dev/null`) that silently discards all incoming DNS messages without performing any disk I/O or network operations.

### Use Cases:
- **Benchmarking & Performance Testing**: Measure the raw maximum throughput of collectors and transformers in isolation, without I/O bottlenecks from disk or remote network sinks.
- **Dropping Filtered Traffic**: In multi-pipeline routing configurations, route unwanted or malicious queries (identified by filtering rules) to `devnull` so they are safely discarded.
- **Dry-Run & Debugging**: Verify network capture, parser decoding, or transformer rules without sending test logs to production databases (such as Elasticsearch or Kafka).

---

## Configuration Example

```yaml
pipelines:
  - name: benchmark-test
    dnstap:
      listen-ip: 0.0.0.0
      listen-port: 6000
    routing-policy:
      forward: [ "blackhole" ]

loggers:
  - name: blackhole
    devnull: {}
```