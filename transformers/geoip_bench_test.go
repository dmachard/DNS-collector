package transformers

import (
	"testing"

	"github.com/dmachard/go-dnscollector/v3/dnsutils"
	"github.com/dmachard/go-dnscollector/v3/pkg/config"
	"github.com/dmachard/go-logger"
)

func BenchmarkGeoIP_Lookup(b *testing.B) {
	cfg := config.GetFakeConfigTransformers()
	cfg.GeoIP.Enable = true
	cfg.GeoIP.DBCountryFile = "../tests/testsdata/GeoLite2-Country.mmdb"
	cfg.GeoIP.DBASNFile = "../tests/testsdata/GeoLite2-ASN.mmdb"

	outChans := []chan *dnsutils.DNSMessageBatch{}
	geoip := NewDNSGeoIPTransform(cfg, logger.New(false), "test", 0, outChans)
	if err := geoip.Open(); err != nil {
		b.Fatalf("geoip init failed: %v", err)
	}
	defer geoip.Close()

	ip := "83.112.146.176"

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = geoip.Lookup(ip)
	}
}

func BenchmarkGeoIP_Lookup_ECS(b *testing.B) {
	cfg := config.GetFakeConfigTransformers()
	cfg.GeoIP.Enable = true
	cfg.GeoIP.DBCountryFile = "../tests/testsdata/GeoLite2-Country.mmdb"
	cfg.GeoIP.LookupECS = true

	outChans := []chan *dnsutils.DNSMessageBatch{}
	geoip := NewDNSGeoIPTransform(cfg, logger.New(false), "test", 0, outChans)
	if err := geoip.Open(); err != nil {
		b.Fatalf("geoip init failed: %v", err)
	}
	defer geoip.Close()

	dm := dnsutils.GetFakeDNSMessage()
	dm.NetworkInfo.QueryIP = "1.1.1.1"
	dm.EDNS.Options = append(dm.EDNS.Options, dnsutils.DNSOption{Code: 8, Name: "CSUBNET", Data: "83.112.146.176/32"})

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = geoip.geoipTransform(&dm)
	}
}
