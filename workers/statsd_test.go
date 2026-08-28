package workers

import (
	"net"
	"testing"
	"time"

	"github.com/dmachard/go-dnscollector/v3/dnsutils"
	"github.com/dmachard/go-dnscollector/v3/pkg/config"
	"github.com/dmachard/go-logger"
	"github.com/dmachard/go-netutils"
)

func TestStatsdRun(t *testing.T) {
	// init logger
	cfg := config.GetDefaultConfig()
	cfg.Loggers.Statsd.FlushInterval = 1

	g := NewStatsdClient(cfg, logger.New(false), "test")

	// fake msgpack receiver
	fakeRcvr, err := net.ListenPacket(netutils.SocketUDP, "127.0.0.1:8125")
	if err != nil {
		t.Fatal(err)
	}
	defer fakeRcvr.Close()

	// start the logger
	go g.StartCollect()

	// send fake dns message to logger
	dm := dnsutils.GetFakeDNSMessage()
	g.GetInputChannel() <- dnsutils.NewDNSMessageBatch(&dm)

	// read data on fake server side
	buf := make([]byte, 4096)
	n, _, err := fakeRcvr.ReadFrom(buf)
	if err != nil {
		t.Errorf("error to read data: %s", err)
	}

	if n == 0 {
		t.Errorf("no data received")
	}

	g.Stop()
}

func TestStatsd_MemoryPurgeAndRace(t *testing.T) {
	cfg := config.GetDefaultConfig()
	cfg.Loggers.Statsd.FlushInterval = 1

	g := NewStatsdClient(cfg, logger.New(false), "test-purge")

	fakeRcvr, err := net.ListenPacket(netutils.SocketUDP, "127.0.0.1:8125")
	if err != nil {
		t.Fatal(err)
	}
	defer fakeRcvr.Close()

	go g.StartCollect()

	// Feed multiple distinct domains and clients
	for i := 0; i < 50; i++ {
		dm := dnsutils.GetFakeDNSMessage()
		dm.DNS.Qname = "domain-" + string(rune('a'+(i%26))) + ".com"
		dm.NetworkInfo.QueryIP = "10.0.0." + string(rune('1'+(i%9)))
		if i%2 == 0 {
			dm.DNS.Rcode = dnsutils.DNSRcodeNXDomain
		}
		g.GetInputChannel() <- dnsutils.NewDNSMessageBatch(&dm)
	}

	// Read emitted statsd packet
	buf := make([]byte, 8192)
	_ = fakeRcvr.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, _, err := fakeRcvr.ReadFrom(buf)
	if err != nil {
		t.Fatalf("error reading statsd packet: %s", err)
	}
	if n == 0 {
		t.Fatalf("no statsd data received")
	}

	// Verify that unbounded maps were purged after the flush
	g.Lock()
	for _, stream := range g.Stats.Streams {
		if len(stream.Domains) > 0 {
			t.Errorf("expected stream.Domains to be purged after flush, got %d entries", len(stream.Domains))
		}
		if len(stream.Clients) > 0 {
			t.Errorf("expected stream.Clients to be purged after flush, got %d entries", len(stream.Clients))
		}
		if len(stream.Nxdomains) > 0 {
			t.Errorf("expected stream.Nxdomains to be purged after flush, got %d entries", len(stream.Nxdomains))
		}
	}
	g.Unlock()

	g.Stop()
}
