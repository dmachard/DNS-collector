package transformers

import (
	"testing"

	"github.com/dmachard/go-dnscollector/v2/dnsutils"
	"github.com/dmachard/go-dnscollector/v2/pkgconfig"
	"github.com/dmachard/go-logger"
)

func BenchmarkRewrite_UpdateValues(b *testing.B) {
	config := pkgconfig.GetFakeConfigTransformers()
	config.Rewrite.Enable = true
	config.Rewrite.Identifiers = make(map[string]interface{})
	config.Rewrite.Identifiers["dns.qname"] = "rewritten.qname.com"
	config.Rewrite.Identifiers["network.query-ip"] = "1.1.1.1"

	outChans := []chan *dnsutils.DNSMessageBatch{}
	rewrite := NewRewriteTransform(config, logger.New(false), "test", 0, outChans)
	rewrite.GetTransforms()

	dm := dnsutils.GetFakeDNSMessage()

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = rewrite.UpdateValues(&dm)
	}
}
