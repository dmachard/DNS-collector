package transformers

import (
	"testing"

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
