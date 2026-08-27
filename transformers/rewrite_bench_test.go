package transformers

import (
	"testing"

	"github.com/dmachard/go-dnscollector/v3/dnsutils"
	"github.com/dmachard/go-dnscollector/v3/pkg/config"
	"github.com/dmachard/go-logger"
)

func BenchmarkRewrite_UpdateValues(b *testing.B) {
	cfg := config.GetFakeConfigTransformers()
	cfg.Rewrite.Enable = true
	cfg.Rewrite.Identifiers = make(map[string]interface{})
	cfg.Rewrite.Identifiers["dns.qname"] = "rewritten.qname.com"
	cfg.Rewrite.Identifiers["network.query-ip"] = "1.1.1.1"

	outChans := []chan *dnsutils.DNSMessageBatch{}
	rewrite := NewRewriteTransform(cfg, logger.New(false), "test", 0, outChans)
	rewrite.GetTransforms()

	dm := dnsutils.GetFakeDNSMessage()

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = rewrite.UpdateValues(&dm)
	}
}
