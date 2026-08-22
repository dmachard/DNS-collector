package transformers

import (
	"testing"

	"github.com/dmachard/go-dnscollector/v2/dnsutils"
	"github.com/dmachard/go-dnscollector/v2/pkgconfig"
	"github.com/dmachard/go-logger"
)

func BenchmarkTransforms_InitAndProcess(b *testing.B) {
	config := pkgconfig.GetFakeConfigTransformers()
	config.Suspicious.Enable = true
	config.GeoIP.Enable = true
	config.GeoIP.DBCountryFile = ".././tests/testsdata/GeoLite2-Country.mmdb"
	config.GeoIP.DBASNFile = ".././tests/testsdata/GeoLite2-ASN.mmdb"
	config.UserPrivacy.Enable = true
	config.UserPrivacy.MinimizeQname = true
	config.UserPrivacy.AnonymizeIP = true
	config.Normalize.Enable = true
	config.Normalize.QnameLowerCase = true
	config.Filtering.Enable = true
	config.Filtering.KeepDomainFile = ".././tests/testsdata/filtering_keep_domains.txt"

	channels := []chan *dnsutils.DNSMessageBatch{}
	transformers := NewTransforms(config, logger.New(false), "test", channels, 0)

	dm := dnsutils.GetFakeDNSMessage()

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		transformers.ProcessMessage(&dm)
	}
}
