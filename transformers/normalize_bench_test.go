package transformers

import (
	"testing"

	"github.com/dmachard/go-dnscollector/v2/dnsutils"
	"github.com/dmachard/go-dnscollector/v2/pkgconfig"
	"github.com/dmachard/go-logger"
)

func BenchmarkNormalize_GetEffectiveTld(b *testing.B) {
	config := pkgconfig.GetFakeConfigTransformers()
	channels := []chan *dnsutils.DNSMessageBatch{}

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
	channels := []chan *dnsutils.DNSMessageBatch{}

	subprocessor := NewNormalizeTransform(config, logger.New(false), "test", 0, channels)
	dm := dnsutils.GetFakeDNSMessage()
	dm.DNS.Qname = "en.wikipedia.org"

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		subprocessor.GetEffectiveTldPlusOne(&dm)
	}
}

func BenchmarkNormalize_QnameLowercase_MixedCase(b *testing.B) {
	config := pkgconfig.GetFakeConfigTransformers()
	channels := []chan *dnsutils.DNSMessageBatch{}

	subprocessor := NewNormalizeTransform(config, logger.New(false), "test", 0, channels)
	dm := dnsutils.GetFakeDNSMessage()

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		dm.DNS.Qname = "EN.Wikipedia.Org"
		subprocessor.QnameLowercase(&dm)
	}
}

func BenchmarkNormalize_QnameLowercase_AlreadyLower(b *testing.B) {
	config := pkgconfig.GetFakeConfigTransformers()
	channels := []chan *dnsutils.DNSMessageBatch{}

	subprocessor := NewNormalizeTransform(config, logger.New(false), "test", 0, channels)
	dm := dnsutils.GetFakeDNSMessage()

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		dm.DNS.Qname = "subdomain.example.google.com"
		subprocessor.QnameLowercase(&dm)
	}
}

func BenchmarkNormalize_RRLowercase_MixedCase(b *testing.B) {
	config := pkgconfig.GetFakeConfigTransformers()
	channels := []chan *dnsutils.DNSMessageBatch{}

	transform := NewNormalizeTransform(config, logger.New(false), "test", 0, channels)
	dm := dnsutils.GetFakeDNSMessage()
	dm.DNS.DNSRRs.Answers = []dnsutils.DNSAnswer{{Name: "En.Wikipedia.Org", Rdatatype: "CNAME", Rdata: "Target.Domain.Com"}}
	dm.DNS.DNSRRs.Nameservers = []dnsutils.DNSAnswer{{Name: "Ns1.Domain.Org", Rdatatype: "NS", Rdata: "Ns1.Other.Com"}}
	dm.DNS.DNSRRs.Records = []dnsutils.DNSAnswer{{Name: "Extra.Domain.Org"}}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		dm.DNS.DNSRRs.Answers[0].Name = "En.Wikipedia.Org"
		dm.DNS.DNSRRs.Answers[0].Rdata = "Target.Domain.Com"
		dm.DNS.DNSRRs.Nameservers[0].Name = "Ns1.Domain.Org"
		dm.DNS.DNSRRs.Nameservers[0].Rdata = "Ns1.Other.Com"
		dm.DNS.DNSRRs.Records[0].Name = "Extra.Domain.Org"
		transform.RRLowercase(&dm)
	}
}

func BenchmarkNormalize_RRLowercase_AlreadyLower(b *testing.B) {
	config := pkgconfig.GetFakeConfigTransformers()
	channels := []chan *dnsutils.DNSMessageBatch{}

	transform := NewNormalizeTransform(config, logger.New(false), "test", 0, channels)
	dm := dnsutils.GetFakeDNSMessage()
	dm.DNS.DNSRRs.Answers = []dnsutils.DNSAnswer{{Name: "en.wikipedia.org", Rdatatype: "CNAME", Rdata: "target.domain.com"}}
	dm.DNS.DNSRRs.Nameservers = []dnsutils.DNSAnswer{{Name: "ns1.domain.org", Rdatatype: "NS", Rdata: "ns1.other.com"}}
	dm.DNS.DNSRRs.Records = []dnsutils.DNSAnswer{{Name: "extra.domain.org"}}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		transform.RRLowercase(&dm)
	}
}

func BenchmarkNormalize_QuietText(b *testing.B) {
	config := pkgconfig.GetFakeConfigTransformers()
	channels := []chan *dnsutils.DNSMessageBatch{}

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
	channels := []chan *dnsutils.DNSMessageBatch{}

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
	channels := []chan *dnsutils.DNSMessageBatch{}

	subprocessor := NewNormalizeTransform(config, logger.New(false), "test", 0, channels)
	dm := dnsutils.GetFakeDNSMessage()

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		dm.DNS.Qname = "sub domain\x00.example\n.com"
		subprocessor.ReplaceNonprintable(&dm)
	}
}
