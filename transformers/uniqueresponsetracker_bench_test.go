package transformers

import (
	"fmt"
	"runtime"
	"testing"
	"time"

	"github.com/dmachard/go-dnscollector/v2/dnsutils"
	"github.com/dmachard/go-dnscollector/v2/pkgconfig"
	"github.com/dmachard/go-logger"
)

// Benchmark Summary:
// LRU (default): 191.9 ns/op, 1 alloc/op, 30.84 MB memory (balanced, fast, stable GC)
// Cuckoo (optional): 959.5 ns/op, 0 alloc/op, 5.80 MB memory (5x slower, memory-constrained only)
// PreAllocated benchmarks measure pure tracker performance without string allocation overhead.

func Benchmark_UniqueResponseTracker_ProcessMessage(b *testing.B) {
	config := pkgconfig.GetFakeConfigTransformers()
	config.UniqueResponseTracker.Enable = true
	config.UniqueResponseTracker.TTL = 3600
	config.UniqueResponseTracker.CacheSize = 1000000

	outChans := []chan *dnsutils.DNSMessageBatch{make(chan *dnsutils.DNSMessageBatch, 100)}
	transforms := NewTransforms(config, logger.New(false), "bench-udr", outChans, 0)

	dm := dnsutils.AcquireDNSMessage()
	dm.Init()
	dm.DNS.Qname = "example.com"
	dm.DNS.DNSRRs.Answers = []dnsutils.DNSAnswer{
		{Rdatatype: "A", Rdata: "93.184.216.34"},
	}

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		_, _ = transforms.ProcessMessage(dm)
	}
}

// Benchmark_UniqueResponseTracker_LRU_100kUnique measures throughput and memory allocated for 100,000 unique records.
func Benchmark_UniqueResponseTracker_LRU_100kUnique(b *testing.B) {
	runtime.GC()
	var m1, m2 runtime.MemStats
	runtime.ReadMemStats(&m1)

	tracker, err := NewUniqueResponseTracker(1*time.Hour, 100000, "lru", nil, "", nil, nil)
	if err != nil {
		b.Fatalf("failed to create tracker: %v", err)
	}

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < 100000; i++ {
		qname := fmt.Sprintf("sub%d.domain%d.com", i%5000, i)
		rdata := fmt.Sprintf("10.%d.%d.%d", (i>>16)&0xFF, (i>>8)&0xFF, i&0xFF)
		tracker.IsNewResponse(qname, "A", rdata)
	}

	b.StopTimer()
	runtime.ReadMemStats(&m2)
	allocMB := float64(m2.HeapAlloc-m1.HeapAlloc) / 1024 / 1024
	b.Logf("LRU 100,000 unique items HeapAlloc: %.2f MB", allocMB)
}

// Benchmark_UniqueResponseTracker_Cuckoo_100kUnique measures throughput and memory allocated for 100,000 unique records using Cuckoo filter.
func Benchmark_UniqueResponseTracker_Cuckoo_100kUnique(b *testing.B) {
	runtime.GC()
	var m1, m2 runtime.MemStats
	runtime.ReadMemStats(&m1)

	tracker, err := NewUniqueResponseTracker(1*time.Hour, 100000, "cuckoo", nil, "", nil, nil)
	if err != nil {
		b.Fatalf("failed to create tracker: %v", err)
	}

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < 100000; i++ {
		qname := fmt.Sprintf("sub%d.domain%d.com", i%5000, i)
		rdata := fmt.Sprintf("10.%d.%d.%d", (i>>16)&0xFF, (i>>8)&0xFF, i&0xFF)
		tracker.IsNewResponse(qname, "A", rdata)
	}

	b.StopTimer()
	runtime.ReadMemStats(&m2)
	allocMB := float64(m2.HeapAlloc-m1.HeapAlloc) / 1024 / 1024
	b.Logf("Cuckoo 100,000 unique items HeapAlloc: %.2f MB", allocMB)
}

// Benchmark_UniqueResponseTracker_LRU_LookupOnly measures pure lookup performance on 10k pre-populated items (LRU).
func Benchmark_UniqueResponseTracker_LRU_LookupOnly(b *testing.B) {
	tracker, err := NewUniqueResponseTracker(1*time.Hour, 100000, "lru", nil, "", nil, nil)
	if err != nil {
		b.Fatalf("failed to create tracker: %v", err)
	}

	// Pre-populate with 10k items
	for i := 0; i < 10000; i++ {
		qname := fmt.Sprintf("domain%d.com", i)
		rdata := fmt.Sprintf("10.0.%d.%d", (i>>8)&0xFF, i&0xFF)
		tracker.IsNewResponse(qname, "A", rdata)
	}

	testQNames := make([]string, b.N)
	testRData := make([]string, b.N)
	for i := 0; i < b.N; i++ {
		idx := i % 10000
		testQNames[i] = fmt.Sprintf("domain%d.com", idx)
		testRData[i] = fmt.Sprintf("10.0.%d.%d", (idx>>8)&0xFF, idx&0xFF)
	}

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		_ = tracker.IsNewResponse(testQNames[i], "A", testRData[i])
	}
}

// Benchmark_UniqueResponseTracker_Cuckoo_LookupOnly measures pure lookup performance on 10k pre-populated items (Cuckoo).
func Benchmark_UniqueResponseTracker_Cuckoo_LookupOnly(b *testing.B) {
	tracker, err := NewUniqueResponseTracker(1*time.Hour, 100000, "cuckoo", nil, "", nil, nil)
	if err != nil {
		b.Fatalf("failed to create tracker: %v", err)
	}

	// Pre-populate with 10k items
	for i := 0; i < 10000; i++ {
		qname := fmt.Sprintf("domain%d.com", i)
		rdata := fmt.Sprintf("10.0.%d.%d", (i>>8)&0xFF, i&0xFF)
		tracker.IsNewResponse(qname, "A", rdata)
	}

	testQNames := make([]string, b.N)
	testRData := make([]string, b.N)
	for i := 0; i < b.N; i++ {
		idx := i % 10000
		testQNames[i] = fmt.Sprintf("domain%d.com", idx)
		testRData[i] = fmt.Sprintf("10.0.%d.%d", (idx>>8)&0xFF, idx&0xFF)
	}

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		_ = tracker.IsNewResponse(testQNames[i], "A", testRData[i])
	}
}

// Benchmark_UniqueResponseTracker_LRU_MixedWorkload_PreAllocated measures real DNS pattern without string allocation overhead.
// 80% existing lookups, 20% new inserts.
func Benchmark_UniqueResponseTracker_LRU_MixedWorkload_PreAllocated(b *testing.B) {
	tracker, err := NewUniqueResponseTracker(1*time.Hour, 100000, "lru", nil, "", nil, nil)
	if err != nil {
		b.Fatalf("failed to create tracker: %v", err)
	}

	// Pre-warm and pre-allocate existing items
	existingQNames := make([]string, 5000)
	existingRData := make([]string, 5000)
	for i := 0; i < 5000; i++ {
		existingQNames[i] = fmt.Sprintf("domain%d.com", i)
		existingRData[i] = fmt.Sprintf("10.0.%d.%d", (i>>8)&0xFF, i&0xFF)
		tracker.IsNewResponse(existingQNames[i], "A", existingRData[i])
	}

	// Pre-allocate new items (minimum 1000)
	numNew := b.N / 5
	if numNew < 1000 {
		numNew = 1000
	}
	newQNames := make([]string, numNew)
	newRData := make([]string, numNew)
	for i := 0; i < len(newQNames); i++ {
		newQNames[i] = fmt.Sprintf("new%d.com", i)
		newRData[i] = fmt.Sprintf("10.1.%d.%d", (i>>8)&0xFF, i&0xFF)
	}

	b.ResetTimer()
	b.ReportAllocs()

	newIdx := 0
	for i := 0; i < b.N; i++ {
		if i%5 == 0 { // 20% new items
			_ = tracker.IsNewResponse(newQNames[newIdx%len(newQNames)], "A", newRData[newIdx%len(newRData)])
			newIdx++
		} else { // 80% existing lookups
			idx := i % 5000
			_ = tracker.IsNewResponse(existingQNames[idx], "A", existingRData[idx])
		}
	}
}

// Benchmark_UniqueResponseTracker_Cuckoo_MixedWorkload_PreAllocated measures real DNS pattern without string allocation overhead.
// 80% existing lookups, 20% new inserts.
func Benchmark_UniqueResponseTracker_Cuckoo_MixedWorkload_PreAllocated(b *testing.B) {
	tracker, err := NewUniqueResponseTracker(1*time.Hour, 100000, "cuckoo", nil, "", nil, nil)
	if err != nil {
		b.Fatalf("failed to create tracker: %v", err)
	}

	// Pre-warm and pre-allocate existing items
	existingQNames := make([]string, 5000)
	existingRData := make([]string, 5000)
	for i := 0; i < 5000; i++ {
		existingQNames[i] = fmt.Sprintf("domain%d.com", i)
		existingRData[i] = fmt.Sprintf("10.0.%d.%d", (i>>8)&0xFF, i&0xFF)
		tracker.IsNewResponse(existingQNames[i], "A", existingRData[i])
	}

	// Pre-allocate new items (minimum 1000)
	numNew := b.N / 5
	if numNew < 1000 {
		numNew = 1000
	}
	newQNames := make([]string, numNew)
	newRData := make([]string, numNew)
	for i := 0; i < len(newQNames); i++ {
		newQNames[i] = fmt.Sprintf("new%d.com", i)
		newRData[i] = fmt.Sprintf("10.1.%d.%d", (i>>8)&0xFF, i&0xFF)
	}

	b.ResetTimer()
	b.ReportAllocs()

	newIdx := 0
	for i := 0; i < b.N; i++ {
		if i%5 == 0 { // 20% new items
			_ = tracker.IsNewResponse(newQNames[newIdx%len(newQNames)], "A", newRData[newIdx%len(newRData)])
			newIdx++
		} else { // 80% existing lookups
			idx := i % 5000
			_ = tracker.IsNewResponse(existingQNames[idx], "A", existingRData[idx])
		}
	}
}

// Benchmark_UniqueResponseTracker_LRU_MixedWorkload simulates real DNS traffic: 80% lookup, 20% new items.
func Benchmark_UniqueResponseTracker_LRU_MixedWorkload(b *testing.B) {
	tracker, err := NewUniqueResponseTracker(1*time.Hour, 100000, "lru", nil, "", nil, nil)
	if err != nil {
		b.Fatalf("failed to create tracker: %v", err)
	}

	// Pre-warm with 5k items
	for i := 0; i < 5000; i++ {
		qname := fmt.Sprintf("domain%d.com", i)
		rdata := fmt.Sprintf("10.0.%d.%d", (i>>8)&0xFF, i&0xFF)
		tracker.IsNewResponse(qname, "A", rdata)
	}

	b.ResetTimer()
	b.ReportAllocs()

	counter := 0
	for i := 0; i < b.N; i++ {
		if i%5 == 0 { // 20% new items
			qname := fmt.Sprintf("new%d.com", counter)
			rdata := fmt.Sprintf("10.1.%d.%d", (counter>>8)&0xFF, counter&0xFF)
			tracker.IsNewResponse(qname, "A", rdata)
			counter++
		} else { // 80% existing lookups
			idx := i % 5000
			qname := fmt.Sprintf("domain%d.com", idx)
			rdata := fmt.Sprintf("10.0.%d.%d", (idx>>8)&0xFF, idx&0xFF)
			_ = tracker.IsNewResponse(qname, "A", rdata)
		}
	}
}

// Benchmark_UniqueResponseTracker_Cuckoo_MixedWorkload simulates real DNS traffic: 80% lookup, 20% new items.
func Benchmark_UniqueResponseTracker_Cuckoo_MixedWorkload(b *testing.B) {
	tracker, err := NewUniqueResponseTracker(1*time.Hour, 100000, "cuckoo", nil, "", nil, nil)
	if err != nil {
		b.Fatalf("failed to create tracker: %v", err)
	}

	// Pre-warm with 5k items
	for i := 0; i < 5000; i++ {
		qname := fmt.Sprintf("domain%d.com", i)
		rdata := fmt.Sprintf("10.0.%d.%d", (i>>8)&0xFF, i&0xFF)
		tracker.IsNewResponse(qname, "A", rdata)
	}

	b.ResetTimer()
	b.ReportAllocs()

	counter := 0
	for i := 0; i < b.N; i++ {
		if i%5 == 0 { // 20% new items
			qname := fmt.Sprintf("new%d.com", counter)
			rdata := fmt.Sprintf("10.1.%d.%d", (counter>>8)&0xFF, counter&0xFF)
			tracker.IsNewResponse(qname, "A", rdata)
			counter++
		} else { // 80% existing lookups
			idx := i % 5000
			qname := fmt.Sprintf("domain%d.com", idx)
			rdata := fmt.Sprintf("10.0.%d.%d", (idx>>8)&0xFF, idx&0xFF)
			_ = tracker.IsNewResponse(qname, "A", rdata)
		}
	}
}
