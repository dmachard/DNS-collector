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
