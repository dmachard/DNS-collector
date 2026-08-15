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

## 2. Go Microbenchmarks (`go test -bench`)

Internal Go benchmarks measure sub-nanosecond processing efficiency and memory allocations per operation (`B/op`, `allocs/op`).

### Running Worker Benchmarks:
```bash
go test -run=^$ -bench=Benchmark_DNSTapProcessor ./workers -benchmem
```

### Running Transformer Benchmarks:
```bash
go test -run=^$ -bench=. ./transformers -benchmem
```
