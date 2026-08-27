package transformers

import (
	"testing"

	"github.com/dmachard/go-dnscollector/v3/dnsutils"
	"github.com/dmachard/go-dnscollector/v3/pkg/config"
	"github.com/dmachard/go-logger"
)

func BenchmarkExtract_AddBase64AndHexFields(b *testing.B) {
	cfg := &config.TransformExtract{
		Enable:       true,
		Base64Fields: []string{"dns.qname", "network.query-ip"},
		HexFields:    []string{"dns.qname", "network.query-ip"},
	}

	outChans := []chan *dnsutils.DNSMessageBatch{}
	extract := NewExtractTransform(cfg, logger.New(false), "test", 0, outChans)
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

func BenchmarkExtract_AddBase64Payload(b *testing.B) {
	cfg := &config.TransformExtract{
		Enable:     true,
		AddPayload: true,
	}

	outChans := []chan *dnsutils.DNSMessageBatch{}
	extract := NewExtractTransform(cfg, logger.New(false), "test", 0, outChans)
	extract.GetTransforms()

	dm := dnsutils.GetFakeDNSMessageWithPayload()

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = extract.addBase64Payload(&dm)
	}
}
