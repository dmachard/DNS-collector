# Performance Benchmarks & Version Comparison

This guide documents the performance benchmarks and automated version comparison results in `DNS-collector`.

---

## 1. Automated Version Comparison Benchmark (`TestCompare_VersionN1`)

The integration test [`tests/compare_vN1_test.go`](../../tests/compare_vN1_test.go) automatically compares the performance (Throughput, Total CPU time, Peak RSS memory, and Execution Time) of the current version against any previous release tag under identical workloads.

### Comparative Results vs `v2.5.0` (Stable Baseline)

Measured on AMD Ryzen 9 9900X (Linux 64-bit) under continuous DNSTap TCP stream ingestion:

#### 1,000,000 Messages Workload:
```text
================================================================================
          PERFORMANCE COMPARISON: v2.5.0 vs Current (Refactored)
================================================================================
Metric                      v2.5.0               Current              Delta
--------------------------------------------------------------------------------
Total Messages Processed    1000000              1000000              -
Execution Time              908ms                737ms                -18.77%  ⏱️
Total CPU Time (User+Sys)   1.073s               641ms                -40.24%  💻
Peak Memory (Max RSS)       103592 KB (101.16 MB) 63828 KB (62.33 MB)  -38.39%  📉
Throughput                  1101524.46 msg/s     1355994.05 msg/s     +23.10%  🚀
================================================================================
```

#### 5,000,000 Messages Heavy Burst Workload:
```text
================================================================================
          PERFORMANCE COMPARISON: v2.5.0 vs Current (Refactored)
================================================================================
Metric                      v2.5.0               Current              Delta
--------------------------------------------------------------------------------
Total Messages Processed    5000000              5000000              -
Execution Time              2.450s               1.980s               -19.16%  ⏱️
Total CPU Time (User+Sys)   4.854s               4.410s               -9.14%   💻
Peak Memory (Max RSS)       105636 KB (103.16 MB) 71240 KB (69.57 MB)  -32.56%  📉
Throughput                  2040941.00 msg/s     2524714.00 msg/s     +23.70%  🚀
================================================================================
```

### Comparative Results vs `v2.6.0-beta6` (1,000,000 messages)
```text
================================================================================
          PERFORMANCE COMPARISON: v2.6.0-beta6 vs Current (Refactored)
================================================================================
Metric                      v2.6.0-beta6         Current              Delta
--------------------------------------------------------------------------------
Total Messages Processed    1000000              1000000              -
Execution Time              790ms                735ms                -6.98%   ⏱️
Total CPU Time (User+Sys)   824ms                629ms                -23.60%  💻
Throughput                  1265497.00 msg/s     1360397.00 msg/s     +7.50%   🚀
================================================================================
```

---

## 2. Channel Batching Microbenchmarks (`workers/worker_bench_test.go`)

Running `go test -bench="^Benchmark_Worker_BatchSize_Comparison" -benchmem ./workers/` highlights the impact of channel message batching:

| Batch Size | Latency per message | Allocation per op | Speedup vs no-batch |
| :--- | :--- | :--- | :--- |
| **1 (No batching)** | `323.1 ns/op` | 925 B/op (1 alloc) | Baseline |
| **16** | `209.3 ns/op` | 919 B/op (1 alloc) | **+35.2% faster** |
| **32** | `202.2 ns/op` | 919 B/op (1 alloc) | **+37.4% faster** |
| **64 (Sweet spot)** | **`194.9 ns/op`** | **918 B/op (1 alloc)** | **+39.7% faster** ⚡ |
| **128** | `205.6 ns/op` | 918 B/op (1 alloc) | **+36.4% faster** |
| **256** | `209.2 ns/op` | 918 B/op (1 alloc) | **+35.2% faster** |
| **512** | `199.9 ns/op` | 917 B/op (1 alloc) | **+38.1% faster** |
| **1024** | `200.4 ns/op` | 919 B/op (1 alloc) | **+38.0% faster** |

---

## 3. Running Comparison Tests Locally

### Default (Compares against the latest stable tag):
```bash
go test -v -run=TestCompare_VersionN1 ./tests
```

### Options & Environment Variables:
- `PREV_TAG`: Release tag to compare against (e.g. `v2.5.0` or `v2.6.0-beta6`).
- `NUM_FRAMES`: Number of DNSTap frames to send per benchmark run (e.g. `1000000` or `5000000`).

```bash
PREV_TAG=v2.5.0 NUM_FRAMES=1000000 go test -v -run=TestCompare_VersionN1 ./tests
```

---

## 4. DNSTap Fast Wire Decoder Microbenchmarks

DNS-collector provides an internal microbenchmark comparing the standard Google Protobuf decoding against the custom zero-allocation binary wire decoder:

```bash
go test -run=^$ -bench=BenchmarkDecodeDNSTap ./dnsutils -benchmem
```

### Benchmark Results (AMD Ryzen 9 9900X):

```text
BenchmarkDecodeDNSTapWire-24                13 955 434      87.5 ns/op      48 B/op     2 allocs/op
BenchmarkDecodeDNSTapStandardProtobuf-24     3 009 538     346.9 ns/op     488 B/op    21 allocs/op
```

- **Protobuf wire decoding**: **~4× faster** CPU time per packet (`87.5 ns` vs `346.9 ns`).
- **Heap allocations**: **-90% memory allocated** (from `488 B` down to `48 B` per decoded DNSMessage).
- **Allocations count**: **-90% allocations** (from `21` down to `2 allocs/op`).
- **Protobuf internal structs & IP strings**: **0 allocations** (nested structs eliminated, native binary IP representation with zero-alloc streaming formatters).


---

## 3. DNS Payload Parser Microbenchmarks (`Custom` vs `miekg/dns`)

DNS-collector embeds a minimalist DNS binary parser designed specifically for passive monitoring, extracting only required fields without the overhead of generic DNS libraries.

```bash
go test -run=^$ -bench="Benchmark.*DecodeDNS" ./dnsutils -benchmem
```

### Benchmark Results (AMD Ryzen 9 9900X):

```text
BenchmarkCustomDecodeDNS_Query-24           38 373 133        28.4 ns/op       16 B/op       1 allocs/op
BenchmarkCustomDecodeDNS-24                  7 799 892       154.8 ns/op      128 B/op       8 allocs/op
BenchmarkMiekgDecodeDNS-24                   2 942 716       407.6 ns/op      440 B/op      17 allocs/op
```

- **Query Parsing Speed**: **~28 ns/op** for standard queries.
- **Full Packet Parsing (Query+Answer)**: **~2.6× faster** than `miekg/dns` (`154.8 ns` vs `407.6 ns`).
- **Memory Allocations**: **-71% memory allocated** (`128 B` vs `440 B`) and **-53% allocations** (`8 allocs` vs `17 allocs`).

---

## 4. Other Go Microbenchmarks (`go test -bench`)

Internal Go benchmarks measure sub-nanosecond processing efficiency and memory allocations per operation (`B/op`, `allocs/op`).

### Running Worker Benchmarks:
```bash
go test -run=^$ -bench=Benchmark_DNSTapProcessor ./workers -benchmem
```

### Running Transformer Benchmarks:
```bash
go test -run=^$ -bench=. ./transformers -benchmem
```

### Running All DNSUtils Benchmarks:
```bash
go test -run=^$ -bench=. ./dnsutils -benchmem
```


