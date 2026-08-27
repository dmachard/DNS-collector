package workers

import (
	"testing"

	"github.com/dmachard/go-dnscollector/v2/dnsutils"
	"github.com/dmachard/go-dnscollector/v2/pkg/config"
	"github.com/dmachard/go-logger"
)

func Benchmark_RestAPI_Record(b *testing.B) {
	cfg := config.GetDefaultConfig()
	g := NewRestAPI(cfg, logger.New(false), "bench_restapi")

	dm := dnsutils.GetFakeDNSMessage()
	dm.DNS.Qname = "dnscollector.dev"

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		g.RecordDNSMessage(&dm)
	}
}
