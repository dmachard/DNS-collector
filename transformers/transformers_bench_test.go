package transformers

import (
	"testing"

	"github.com/dmachard/go-dnscollector/v2/dnsutils"
	"github.com/dmachard/go-dnscollector/v2/pkg/config"
	"github.com/dmachard/go-logger"
)

func BenchmarkTransforms_InitAndProcess(b *testing.B) {
	cfg := config.GetFakeConfigTransformers()
	cfg.Suspicious.Enable = true
	cfg.GeoIP.Enable = true
	cfg.GeoIP.DBCountryFile = ".././tests/testsdata/GeoLite2-Country.mmdb"
	cfg.GeoIP.DBASNFile = ".././tests/testsdata/GeoLite2-ASN.mmdb"
	cfg.UserPrivacy.Enable = true
	cfg.UserPrivacy.MinimizeQname = true
	cfg.UserPrivacy.AnonymizeIP = true
	cfg.Normalize.Enable = true
	cfg.Normalize.QnameLowerCase = true
	cfg.Filtering.Enable = true
	cfg.Filtering.KeepDomainFile = ".././tests/testsdata/filtering_keep_domains.txt"

	channels := []chan *dnsutils.DNSMessageBatch{}
	transformers := NewTransforms(cfg, logger.New(false), "test", channels, 0)

	dm := dnsutils.GetFakeDNSMessage()

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		transformers.ProcessMessage(&dm)
	}
}
