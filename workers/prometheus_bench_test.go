package workers

import (
	"testing"

	"github.com/dmachard/go-dnscollector/v2/dnsutils"
	"github.com/dmachard/go-dnscollector/v2/pkg/config"
	"github.com/dmachard/go-logger"
)

func Benchmark_Prometheus_Record_Direct(b *testing.B) {
	cfg := config.GetDefaultConfig()
	p := NewPrometheus(cfg, logger.New(false), "bench")

	dm := dnsutils.GetFakeDNSMessage()
	dm.NetworkInfo.SetQueryIPBytes([]byte{192, 168, 1, 100})
	dm.DNS.Qname = "dnscollector.dev"
	dm.DNS.Rcode = "NOERROR"
	dm.DNS.Qtype = "A"

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		p.Record(&dm)
	}
}

func Benchmark_Prometheus_Record_Batch(b *testing.B) {
	cfg := config.GetDefaultConfig()
	p := NewPrometheus(cfg, logger.New(false), "bench")

	dm := dnsutils.GetFakeDNSMessage()
	dm.NetworkInfo.SetQueryIPBytes([]byte{192, 168, 1, 100})
	dm.DNS.Qname = "dnscollector.dev"
	dm.DNS.Rcode = "NOERROR"
	dm.DNS.Qtype = "A"

	batchSize := 64
	msgs := make([]*dnsutils.DNSMessage, batchSize)
	for j := 0; j < batchSize; j++ {
		msgs[j] = &dm
	}

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i += batchSize {
		batch := dnsutils.AcquireDNSMessageBatch(batchSize)
		batch.Messages = append(batch.Messages, msgs...)
		p.RecordBatch(batch)
		batch.Release()
	}
}

func Benchmark_Prometheus_E2E_Batch64(b *testing.B) {
	cfg := config.GetDefaultConfig()
	cfg.Loggers.Prometheus.ListenPort = 0
	p := NewPrometheus(cfg, logger.New(false), "bench-e2e")
	go p.StartCollect()
	defer p.Stop()

	dm := dnsutils.GetFakeDNSMessage()
	dm.NetworkInfo.SetQueryIPBytes([]byte{192, 168, 1, 100})
	dm.DNS.Qname = "dnscollector.dev"
	dm.DNS.Rcode = "NOERROR"
	dm.DNS.Qtype = "A"

	batchSize := 64
	msgs := make([]*dnsutils.DNSMessage, batchSize)
	for j := 0; j < batchSize; j++ {
		msgs[j] = &dm
	}

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i += batchSize {
		batch := dnsutils.AcquireDNSMessageBatch(batchSize)
		batch.Messages = append(batch.Messages, msgs...)
		p.GetInputChannel() <- batch
	}
}
