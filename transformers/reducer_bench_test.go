package transformers

import (
	"sync"
	"testing"
	"time"

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

	outChan := make(chan *dnsutils.DNSMessageBatch, 100000)
	reducer := NewReducerTransform(config, logger.New(false), "test", 0, []chan *dnsutils.DNSMessageBatch{outChan})

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

	outChan := make(chan *dnsutils.DNSMessageBatch, 1000000)
	reducer := NewReducerTransform(config, logger.New(false), "test", 0, []chan *dnsutils.DNSMessageBatch{outChan})

	dm := dnsutils.DNSMessage{
		DNSTap:      dnsutils.DNSTap{Operation: "CLIENT_QUERY"},
		DNS:         dnsutils.DNS{Qname: "hello.world", Qtype: "A", Length: 64},
		NetworkInfo: dnsutils.DNSNetInfo{QueryIP: "127.0.0.1"},
	}
	dm.InitTransforms()

	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			localDm := dm
			_, _ = reducer.repetitiveTrafficDetector(&localDm)
		}
	})
}

type singleLockMapTraffic struct {
	sync.Mutex
	kv map[string]*dnsutils.DNSMessage
}

func Benchmark_MapTraffic_MultiThread_SingleLock_vs_Sharded(b *testing.B) {
	names := []string{
		"google.com", "cloudflare.com", "github.com", "amazon.com",
		"netflix.com", "microsoft.com", "apple.com", "facebook.com",
		"twitter.com", "wikipedia.org", "yahoo.com", "reddit.com",
		"bing.com", "ebay.com", "linkedin.com", "twitch.tv",
		"domain1.org", "domain2.org", "domain3.org", "domain4.org",
		"domain5.org", "domain6.org", "domain7.org", "domain8.org",
		"domain9.org", "domain10.org", "domain11.org", "domain12.org",
		"domain13.org", "domain14.org", "domain15.org", "domain16.org",
	}

	b.Run("SingleLock_1Mutex_24Threads", func(b *testing.B) {
		m := &singleLockMapTraffic{kv: make(map[string]*dnsutils.DNSMessage)}
		dm := dnsutils.GetFakeDNSMessage()
		dm.InitTransforms()

		b.ReportAllocs()
		b.ResetTimer()
		b.RunParallel(func(pb *testing.PB) {
			i := 0
			for pb.Next() {
				key := names[i%len(names)]
				i++

				m.Lock()
				if v, ok := m.kv[key]; ok {
					v.Reducer.Occurrences++
				} else {
					m.kv[key] = &dm
				}
				m.Unlock()
			}
		})
	})

	b.Run("Sharded_32Mutexes_24Threads", func(b *testing.B) {
		mp := NewMapTraffic(10*time.Second, nil, nil, nil)
		dm := dnsutils.GetFakeDNSMessage()
		dm.InitTransforms()

		b.ReportAllocs()
		b.ResetTimer()
		b.RunParallel(func(pb *testing.PB) {
			i := 0
			for pb.Next() {
				key := names[i%len(names)]
				i++
				mp.Set([]byte(key), &dm)
			}
		})
	})
}
