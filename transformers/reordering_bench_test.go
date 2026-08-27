package transformers

import (
	"cmp"
	"math/rand"
	"slices"
	"sort"
	"testing"
	"time"

	"github.com/dmachard/go-dnscollector/v2/dnsutils"
	"github.com/dmachard/go-dnscollector/v2/pkg/config"
	"github.com/dmachard/go-logger"
)

func generateMessages(n int, jitter int64) []*dnsutils.DNSMessage {
	baseTime := time.Now().UnixNano()
	msgs := make([]*dnsutils.DNSMessage, n)
	r := rand.New(rand.NewSource(42))
	for i := 0; i < n; i++ {
		dm := dnsutils.GetFakeDNSMessage()
		var offset int64
		if jitter > 0 {
			offset = int64(i)*1_000_000 + r.Int63n(jitter) - jitter/2
		} else {
			offset = r.Int63n(1_000_000_000)
		}
		dm.DNSTap.Timestamp = baseTime + offset
		msgs[i] = &dm
	}
	return msgs
}

// -------------------------------------------------------------
// Pure Algorithm Microbenchmarks (sort.SliceStable vs slices.SortFunc)
// -------------------------------------------------------------

func Benchmark_Sort_SliceStable_NearlySorted_1000(b *testing.B) {
	template := generateMessages(1000, 50_000_000)
	buf := make([]*dnsutils.DNSMessage, 1000)

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		copy(buf, template)
		sort.SliceStable(buf, func(x, y int) bool {
			return buf[x].DNSTap.Timestamp < buf[y].DNSTap.Timestamp
		})
	}
}

func Benchmark_Sort_SlicesSortFunc_NearlySorted_1000(b *testing.B) {
	template := generateMessages(1000, 50_000_000)
	buf := make([]*dnsutils.DNSMessage, 1000)

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		copy(buf, template)
		slices.SortFunc(buf, func(a, b *dnsutils.DNSMessage) int {
			return cmp.Compare(a.DNSTap.Timestamp, b.DNSTap.Timestamp)
		})
	}
}

func Benchmark_Sort_SliceStable_Random_1000(b *testing.B) {
	template := generateMessages(1000, 0)
	buf := make([]*dnsutils.DNSMessage, 1000)

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		copy(buf, template)
		sort.SliceStable(buf, func(x, y int) bool {
			return buf[x].DNSTap.Timestamp < buf[y].DNSTap.Timestamp
		})
	}
}

func Benchmark_Sort_SlicesSortFunc_Random_1000(b *testing.B) {
	template := generateMessages(1000, 0)
	buf := make([]*dnsutils.DNSMessage, 1000)

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		copy(buf, template)
		slices.SortFunc(buf, func(a, b *dnsutils.DNSMessage) int {
			return cmp.Compare(a.DNSTap.Timestamp, b.DNSTap.Timestamp)
		})
	}
}

// -------------------------------------------------------------
// Transformer FlushBuffer End-to-End Benchmarks
// -------------------------------------------------------------

func Benchmark_Reordering_FlushBuffer_1000(b *testing.B) {
	cfg := config.GetFakeConfigTransformers()
	cfg.Reordering.Enable = true
	cfg.Reordering.MaxBufferSize = 1000
	log := logger.New(false)
	outChans := []chan *dnsutils.DNSMessageBatch{make(chan *dnsutils.DNSMessageBatch, 2000)}
	reorder := NewReorderingTransform(cfg, log, "bench", 0, outChans)

	template := generateMessages(1000, 50_000_000) // nearly sorted

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		reorder.mutex.Lock()
		reorder.buffer = append(reorder.buffer[:0], template...)
		reorder.mutex.Unlock()

		reorder.flushBuffer()
		// drain channel
		for len(outChans[0]) > 0 {
			batch := <-outChans[0]
			batch.Release()
		}
	}
}
