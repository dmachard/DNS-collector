# Performance & Memory Tuning Overview

To handle high-volume DNS traffic with low latency and optimal resource consumption, DNS-collector can be tuned across three key areas:

---

## Tuning Guides

- 🚀 **[Pipeline Buffers & Batching](buffers.md)**  
  Understand channel batching (`batch-size`, `buffer-size`), queue retention capacity, and detecting buffer exhaustion warnings.

- 🧠 **[Memory & Garbage Collection (GOMEMLIMIT)](memory.md)**  
  Control heap size and eliminate Out-Of-Memory (OOM) risk in containerized environments using `GOMEMLIMIT` and `GOGC`.

- ⚡ **[Collector Optimization](collectors.md)**  
  Maximize collector throughput via fast wire decoders, socket read buffer sizing, multi-core worker scaling, and selective payload parsing.
