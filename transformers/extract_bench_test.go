package transformers

import (
	"testing"

	"github.com/dmachard/go-dnscollector/v2/dnsutils"
	"github.com/dmachard/go-dnscollector/v2/pkgconfig"
	"github.com/dmachard/go-logger"
)

func BenchmarkExtract_AddBase64AndHexFields(b *testing.B) {
	config := pkgconfig.GetFakeConfigTransformers()
	config.Extract.Enable = true
	config.Extract.Base64Fields = []string{"dns.qname", "network.query-ip"}
	config.Extract.HexFields = []string{"dns.qname", "network.query-ip"}

	outChans := []chan *dnsutils.DNSMessageBatch{}
	extract := NewExtractTransform(config, logger.New(false), "test", 0, outChans)
	extract.GetTransforms()

	dm := dnsutils.GetFakeDNSMessage()
	dm.DNS.Qname = "test-request-abcd.com"
	dm.NetworkInfo.QueryIP = "192.168.1.2"

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = extract.addBase64Fields(&dm)
		_, _ = extract.addHexFields(&dm)
	}
}
