package transformers

import (
	"testing"

	"github.com/dmachard/go-dnscollector/v2/dnsutils"
	"github.com/dmachard/go-dnscollector/v2/pkgconfig"
	"github.com/dmachard/go-logger"
)

func BenchmarkUserPrivacy_ReduceQname(b *testing.B) {
	config := pkgconfig.GetFakeConfigTransformers()
	config.UserPrivacy.Enable = true
	config.UserPrivacy.MinimizeQname = true

	channels := []chan *dnsutils.DNSMessage{}

	userprivacy := NewUserPrivacyTransform(config, logger.New(false), "test", 0, channels)
	userprivacy.GetTransforms()

	dm := dnsutils.GetFakeDNSMessage()
	dm.DNS.Qname = "localhost.domain.local.home"

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		userprivacy.minimizeQname(&dm)
	}
}

func BenchmarkUserPrivacy_HashIP(b *testing.B) {
	config := pkgconfig.GetFakeConfigTransformers()
	config.UserPrivacy.Enable = true
	config.UserPrivacy.HashQueryIP = true

	channels := []chan *dnsutils.DNSMessage{}

	userprivacy := NewUserPrivacyTransform(config, logger.New(false), "test", 0, channels)
	userprivacy.GetTransforms()

	dm := dnsutils.GetFakeDNSMessage()

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		userprivacy.hashQueryIP(&dm)
	}
}

func BenchmarkUserPrivacy_HashIPSha512(b *testing.B) {
	config := pkgconfig.GetFakeConfigTransformers()
	config.UserPrivacy.Enable = true
	config.UserPrivacy.HashQueryIP = true
	config.UserPrivacy.HashIPAlgo = "sha512"

	channels := []chan *dnsutils.DNSMessage{}

	userprivacy := NewUserPrivacyTransform(config, logger.New(false), "test", 0, channels)
	userprivacy.GetTransforms()

	dm := dnsutils.GetFakeDNSMessage()

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		userprivacy.hashQueryIP(&dm)
	}
}

func BenchmarkUserPrivacy_AnonymizeIP(b *testing.B) {
	config := pkgconfig.GetFakeConfigTransformers()
	config.UserPrivacy.Enable = true
	config.UserPrivacy.AnonymizeIP = true

	channels := []chan *dnsutils.DNSMessage{}

	userprivacy := NewUserPrivacyTransform(config, logger.New(false), "test", 0, channels)
	userprivacy.GetTransforms()

	dm := dnsutils.GetFakeDNSMessage()

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		userprivacy.anonymizeQueryIP(&dm)
	}
}

func BenchmarkHashIP_Sha1(b *testing.B) {
	ip := "192.168.1.2"
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = HashIP(ip, "sha1")
	}
}

func BenchmarkHashIP_Sha256(b *testing.B) {
	ip := "192.168.1.2"
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = HashIP(ip, "sha256")
	}
}

func BenchmarkHashIP_Sha512(b *testing.B) {
	ip := "192.168.1.2"
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = HashIP(ip, "sha512")
	}
}
