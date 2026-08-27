package transformers

import (
	"testing"

	"github.com/dmachard/go-dnscollector/v3/dnsutils"
	"github.com/dmachard/go-dnscollector/v3/pkg/config"
	"github.com/dmachard/go-logger"
)

func Benchmark_UserPrivacy_AnonymizeIPv4_Binary(b *testing.B) {
	cfg := config.GetFakeConfigTransformers()
	cfg.UserPrivacy.Enable = true
	cfg.UserPrivacy.AnonymizeIP = true
	userPrivacy := NewUserPrivacyTransform(cfg, logger.New(false), "test", 0, nil)
	userPrivacy.GetTransforms()

	dm := dnsutils.GetFakeDNSMessage()
	ipBytes := []byte{192, 168, 1, 2}

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		dm.NetworkInfo.SetQueryIPBytes(ipBytes)
		userPrivacy.anonymizeQueryIP(&dm)
	}
}

func Benchmark_UserPrivacy_AnonymizeIPv4_String(b *testing.B) {
	cfg := config.GetFakeConfigTransformers()
	cfg.UserPrivacy.Enable = true
	cfg.UserPrivacy.AnonymizeIP = true
	userPrivacy := NewUserPrivacyTransform(cfg, logger.New(false), "test", 0, nil)
	userPrivacy.GetTransforms()

	dm := dnsutils.GetFakeDNSMessage()

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		dm.NetworkInfo.QueryIP = "192.168.1.2"
		dm.NetworkInfo.QueryIPLen = 0
		userPrivacy.anonymizeQueryIP(&dm)
	}
}

func Benchmark_UserPrivacy_AnonymizeIPv6_String(b *testing.B) {
	cfg := config.GetFakeConfigTransformers()
	cfg.UserPrivacy.Enable = true
	cfg.UserPrivacy.AnonymizeIP = true
	userPrivacy := NewUserPrivacyTransform(cfg, logger.New(false), "test", 0, nil)
	userPrivacy.GetTransforms()

	dm := dnsutils.GetFakeDNSMessage()

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		dm.NetworkInfo.QueryIP = "fe80::6111:626:c1b2:2353"
		dm.NetworkInfo.QueryIPLen = 0
		userPrivacy.anonymizeQueryIP(&dm)
	}
}

func Benchmark_UserPrivacy_AnonymizeIPv6_Binary(b *testing.B) {
	cfg := config.GetFakeConfigTransformers()
	cfg.UserPrivacy.Enable = true
	cfg.UserPrivacy.AnonymizeIP = true
	userPrivacy := NewUserPrivacyTransform(cfg, logger.New(false), "test", 0, nil)
	userPrivacy.GetTransforms()

	dm := dnsutils.GetFakeDNSMessage()
	ipBytes := []byte{0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0x61, 0x11, 0x06, 0x26, 0xc1, 0xb2, 0x23, 0x53}

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		dm.NetworkInfo.SetQueryIPBytes(ipBytes)
		userPrivacy.anonymizeQueryIP(&dm)
	}
}
