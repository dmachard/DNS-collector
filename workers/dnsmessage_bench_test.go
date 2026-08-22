package workers

import (
	"testing"

	"github.com/dmachard/go-dnscollector/v2/dnsutils"
	"github.com/dmachard/go-dnscollector/v2/pkgconfig"
	"github.com/dmachard/go-logger"
)

func Benchmark_DNSMessageWorker_Passthrough(b *testing.B) {
	config := pkgconfig.GetDefaultConfig()
	config.Global.Worker.ChannelBufferSize = 65536

	devNull := NewDevNull(config, logger.New(false), "devnull")
	go devNull.StartCollect()
	defer devNull.Stop()

	c := NewDNSMessage(nil, config, logger.New(false), "bench-dnsmessage")
	c.SetDefaultRoutes([]Worker{devNull})
	go c.StartCollect()
	defer c.Stop()

	dm := dnsutils.GetFakeDNSMessage()
	inChan := c.GetInputChannel()

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		msg := dm
		inChan <- &msg
	}
}

func Benchmark_DNSMessageWorker_MatchingInclude(b *testing.B) {
	config := pkgconfig.GetDefaultConfig()
	config.Global.Worker.ChannelBufferSize = 65536
	config.Collectors.DNSMessage.Matching.Include = map[string]interface{}{
		"dns.qname": "dns.collector",
	}

	devNull := NewDevNull(config, logger.New(false), "devnull")
	go devNull.StartCollect()
	defer devNull.Stop()

	c := NewDNSMessage(nil, config, logger.New(false), "bench-dnsmessage")
	c.SetDefaultRoutes([]Worker{devNull})
	go c.StartCollect()
	defer c.Stop()

	dm := dnsutils.GetFakeDNSMessage()
	dm.DNS.Qname = "dns.collector"
	inChan := c.GetInputChannel()

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		msg := dm
		inChan <- &msg
	}
}

func Benchmark_DNSMessageWorker_MatchingExclude(b *testing.B) {
	config := pkgconfig.GetDefaultConfig()
	config.Global.Worker.ChannelBufferSize = 65536
	config.Collectors.DNSMessage.Matching.Exclude = map[string]interface{}{
		"dns.qname": "drop.me",
	}

	devNull := NewDevNull(config, logger.New(false), "devnull")
	go devNull.StartCollect()
	defer devNull.Stop()

	c := NewDNSMessage(nil, config, logger.New(false), "bench-dnsmessage")
	c.SetDefaultRoutes([]Worker{devNull})
	c.SetDefaultDropped([]Worker{devNull})
	go c.StartCollect()
	defer c.Stop()

	dm := dnsutils.GetFakeDNSMessage()
	dm.DNS.Qname = "drop.me"
	inChan := c.GetInputChannel()

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		msg := dm
		inChan <- &msg
	}
}
