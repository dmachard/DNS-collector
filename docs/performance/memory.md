# Memory & Garbage Collection Tuning

Under massive burst workloads (> 1M packets/sec), Go runtime memory consumption can be strictly bounded using standard environment variables.

---

## Setting a Hard Memory Limit (`GOMEMLIMIT`)

Go 1.19+ supports `GOMEMLIMIT`, which instructs the Go runtime to proactively run garbage collection to keep the total heap under a specified budget without risking Out-Of-Memory (OOM) kills:

```bash
# Set a soft memory ceiling of 50 MiB
GOMEMLIMIT=50MiB ./dnscollector -config config.yml
```

---

## Tuning Garbage Collection Frequency (`GOGC`)

`GOGC` sets the percentage of newly allocated memory relative to the live heap before the next GC cycle runs (default is `100`):

```bash
# More aggressive GC during traffic spikes (reduces peak RSS to ~30-40 MB)
GOGC=50 ./dnscollector -config config.yml
```

---

## Recommended Production Configurations

### Docker / Kubernetes Container

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

### Systemd Service (`/etc/systemd/system/dnscollector.service`)

```ini
[Service]
Environment="GOMEMLIMIT=60MiB"
Environment="GOGC=75"
ExecStart=/usr/local/bin/dnscollector -config /etc/dnscollector/config.yml
```
