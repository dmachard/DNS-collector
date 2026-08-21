package transformers

import (
	"testing"

	"github.com/dmachard/go-dnscollector/v2/dnsutils"
	"github.com/dmachard/go-dnscollector/v2/pkgconfig"
	"github.com/dmachard/go-logger"
)

func BenchmarkReducer_RepetitiveTrafficDetector(b *testing.B) {
	config := pkgconfig.GetFakeConfigTransformers()
	config.Reducer.Enable = true
	config.Reducer.RepetitiveTrafficDetector = true
	config.Reducer.WatchInterval = 10
	config.Reducer.UniqueFields = []string{"dns.qname", "dns.qtype", "network.query-ip"}

	outChan := make(chan *dnsutils.DNSMessage, 100000)
	reducer := NewReducerTransform(config, logger.New(false), "test", 0, []chan *dnsutils.DNSMessage{outChan})

	dm := dnsutils.DNSMessage{
		DNSTap:      dnsutils.DNSTap{Operation: "CLIENT_QUERY"},
		DNS:         dnsutils.DNS{Qname: "hello.world", Qtype: "A", Length: 64},
		NetworkInfo: dnsutils.DNSNetInfo{QueryIP: "127.0.0.1"},
	}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = reducer.repetitiveTrafficDetector(&dm)
	}
}

func BenchmarkReducer_RepetitiveTrafficDetectorParallel(b *testing.B) {
	config := pkgconfig.GetFakeConfigTransformers()
	config.Reducer.Enable = true
	config.Reducer.RepetitiveTrafficDetector = true
	config.Reducer.WatchInterval = 10
	config.Reducer.UniqueFields = []string{"dns.qname", "dns.qtype", "network.query-ip"}

	outChan := make(chan *dnsutils.DNSMessage, 1000000)
	reducer := NewReducerTransform(config, logger.New(false), "test", 0, []chan *dnsutils.DNSMessage{outChan})

	dm := dnsutils.DNSMessage{
		DNSTap:      dnsutils.DNSTap{Operation: "CLIENT_QUERY"},
		DNS:         dnsutils.DNS{Qname: "hello.world", Qtype: "A", Length: 64},
		NetworkInfo: dnsutils.DNSNetInfo{QueryIP: "127.0.0.1"},
	}

	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			localDm := dm
			_, _ = reducer.repetitiveTrafficDetector(&localDm)
		}
	})
}
