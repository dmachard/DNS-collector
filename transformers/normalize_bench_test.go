package transformers

import (
	"testing"

	"github.com/dmachard/go-dnscollector/v2/dnsutils"
	"github.com/dmachard/go-dnscollector/v2/pkgconfig"
	"github.com/dmachard/go-logger"
)

func BenchmarkNormalize_GetEffectiveTld(b *testing.B) {
	config := pkgconfig.GetFakeConfigTransformers()
	channels := []chan *dnsutils.DNSMessage{}

	subprocessor := NewNormalizeTransform(config, logger.New(false), "test", 0, channels)
	dm := dnsutils.GetFakeDNSMessage()
	dm.DNS.Qname = "en.wikipedia.org"

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		subprocessor.GetEffectiveTld(&dm)
	}
}

func BenchmarkNormalize_GetEffectiveTldPlusOne(b *testing.B) {
	config := pkgconfig.GetFakeConfigTransformers()
	channels := []chan *dnsutils.DNSMessage{}

	subprocessor := NewNormalizeTransform(config, logger.New(false), "test", 0, channels)
	dm := dnsutils.GetFakeDNSMessage()
	dm.DNS.Qname = "en.wikipedia.org"

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		subprocessor.GetEffectiveTldPlusOne(&dm)
	}
}

func BenchmarkNormalize_QnameLowercase(b *testing.B) {
	config := pkgconfig.GetFakeConfigTransformers()
	channels := []chan *dnsutils.DNSMessage{}

	subprocessor := NewNormalizeTransform(config, logger.New(false), "test", 0, channels)
	dm := dnsutils.GetFakeDNSMessage()
	dm.DNS.Qname = "EN.Wikipedia.Org"

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		subprocessor.QnameLowercase(&dm)
	}
}

func BenchmarkNormalize_QnameLowercase_AlreadyLower(b *testing.B) {
	config := pkgconfig.GetFakeConfigTransformers()
	channels := []chan *dnsutils.DNSMessage{}

	subprocessor := NewNormalizeTransform(config, logger.New(false), "test", 0, channels)
	dm := dnsutils.GetFakeDNSMessage()

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		dm.DNS.Qname = "subdomain.example.google.com"
		subprocessor.QnameLowercase(&dm)
	}
}

func BenchmarkNormalize_RRLowercase(b *testing.B) {
	config := pkgconfig.GetFakeConfigTransformers()
	channels := []chan *dnsutils.DNSMessage{}

	transform := NewNormalizeTransform(config, logger.New(false), "test", 0, channels)

	name := "En.Tikipedia.Org"
	dm := dnsutils.GetFakeDNSMessage()
	dm.DNS.Qname = name
	dm.DNS.DNSRRs.Answers = append(dm.DNS.DNSRRs.Answers, dnsutils.DNSAnswer{Name: name})
	dm.DNS.DNSRRs.Nameservers = append(dm.DNS.DNSRRs.Nameservers, dnsutils.DNSAnswer{Name: name})
	dm.DNS.DNSRRs.Records = append(dm.DNS.DNSRRs.Records, dnsutils.DNSAnswer{Name: name})

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		transform.RRLowercase(&dm)
	}
}

func BenchmarkNormalize_QuietText(b *testing.B) {
	config := pkgconfig.GetFakeConfigTransformers()
	channels := []chan *dnsutils.DNSMessage{}

	subprocessor := NewNormalizeTransform(config, logger.New(false), "test", 0, channels)
	dm := dnsutils.GetFakeDNSMessage()
	dm.DNS.Qname = "EN.Wikipedia.Org"

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		subprocessor.QuietText(&dm)
	}
}

func BenchmarkNormalize_ReplaceNonprintable_Printable(b *testing.B) {
	config := pkgconfig.GetFakeConfigTransformers()
	channels := []chan *dnsutils.DNSMessage{}

	subprocessor := NewNormalizeTransform(config, logger.New(false), "test", 0, channels)
	dm := dnsutils.GetFakeDNSMessage()

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		dm.DNS.Qname = "subdomain.example.google.com"
		subprocessor.ReplaceNonprintable(&dm)
	}
}

func BenchmarkNormalize_ReplaceNonprintable_WithSpecial(b *testing.B) {
	config := pkgconfig.GetFakeConfigTransformers()
	channels := []chan *dnsutils.DNSMessage{}

	subprocessor := NewNormalizeTransform(config, logger.New(false), "test", 0, channels)
	dm := dnsutils.GetFakeDNSMessage()

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		dm.DNS.Qname = "sub domain\x00.example\n.com"
		subprocessor.ReplaceNonprintable(&dm)
	}
}
