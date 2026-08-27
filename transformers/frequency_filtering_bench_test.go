package transformers

import (
	"fmt"
	"testing"

	"github.com/dmachard/go-dnscollector/v3/dnsutils"
	"github.com/dmachard/go-dnscollector/v3/pkg/config"
	"github.com/dmachard/go-logger"
)

func BenchmarkFrequencyFiltering_Process(b *testing.B) {
	cfg := &config.TransformFrequencyFiltering{
		Enable:        true,
		TrackBy:       "qname",
		Threshold:     1000,
		WindowSeconds: 60,
		SampleRate:    100,
		TagOnly:       false,
		Capacity:      100000,
	}

	log := logger.New(true)
	tf := NewFrequencyFilteringTransform(cfg, log, "test", 0, nil)
	defer tf.Stop()

	subtransforms, _ := tf.GetTransforms()
	filter := subtransforms[0].processFunc

	messages := make([]dnsutils.DNSMessage, 1000)
	for i := range messages {
		messages[i] = dnsutils.GetFakeDNSMessage()
		messages[i].DNS.Qname = fmt.Sprintf("domain-%d.com", i%200)
	}

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_, _ = filter(&messages[i%len(messages)])
	}
}
