# Performance Benchmarks & Version Comparison

This guide explains how to run CPU/memory performance benchmarks and automated version comparison tests in `DNS-collector`.

---

## 1. Automated Version Comparison Benchmark (`TestCompare_VersionN1`)

The integration test [`tests/compare_vN1_test.go`](../../tests/compare_vN1_test.go) automatically compares the performance (CPU, Max RSS memory, throughput) of the current workspace against a previous release tag.

### How it works
1. Clones and builds a target release tag (e.g. `v2.5.0` or `v2.6.0-beta2`) in an isolated temporary directory.
2. Builds the current workspace binary.
3. Spawns both binaries under an identical workload, sending 150,000 real DNSTap frames over TCP.
4. Measures **Peak Memory (Max RSS)**, **User+System CPU time**, **Total Execution Time**, and **Throughput (msgs/sec)**.
5. Prints a side-by-side comparative table with percentage deltas.

### Running the Comparison Test

#### Default (Compares against the latest Git tag):
```bash
go test -v -run=TestCompare_VersionN1 ./tests
```

#### Options & Environment Variables:
- `PREV_TAG`: Release tag to compare against (default: latest git tag).
- `NUM_FRAMES`: Number of DNSTap frames to send per benchmark run (default: `1000000`).

#### Run benchmark with 5,000,000 frames against `v2.5.0`:
```bash
PREV_TAG=v2.5.0 NUM_FRAMES=5000000 go test -v -run=TestCompare_VersionN1 ./tests
```

#### Example Output (5,000,000 messages processed):
```text
================================================================================
          PERFORMANCE COMPARISON: v2.5.0 vs Current (Refactored)
================================================================================
Metric                      v2.5.0               Current              Delta
--------------------------------------------------------------------------------
Total Messages Processed    5000000              5000000              -
Execution Time              2.228s               2.237s               +0.39%
Total CPU Time (User+Sys)   4.283s               4.378s               +2.22%
Peak Memory (Max RSS)       105764 KB (103.29 MB) 61892 KB (60.44 MB)  -41.48%
Throughput                  2243831.68           2235081.59           -0.39%
================================================================================
```

---

## 2. DNSTap Fast Wire Decoder Microbenchmarks

DNS-collector provides an internal microbenchmark comparing the standard Google Protobuf decoding against the custom zero-allocation binary wire decoder:

```bash
go test -run=^$ -bench=BenchmarkDecodeDNSTap ./dnsutils -benchmem
```

### Benchmark Results (AMD Ryzen 9 9900X):

```text
BenchmarkDecodeDNSTapWire-24                11 268 451     105.6 ns/op      64 B/op     4 allocs/op
BenchmarkDecodeDNSTapStandardProtobuf-24     3 548 641     338.0 ns/op     488 B/op    21 allocs/op
```

- **Protobuf wire decoding**: **~3× faster** CPU time per packet.
- **Heap allocations**: **-81% memory allocated** (from `488 B` down to `64 B` per decoded DNSMessage).
- **Protobuf internal structs**: **0 allocations** (all nested structs and pointers eliminated).

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


