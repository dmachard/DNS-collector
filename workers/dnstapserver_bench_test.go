package workers

import (
	"sync"
	"testing"
	"time"

	"github.com/dmachard/go-dnscollector/v2/dnsutils"
	"github.com/dmachard/go-dnscollector/v2/pkgconfig"
	"github.com/dmachard/go-logger"
	"google.golang.org/protobuf/proto"
)

func Benchmark_DNSTapProcessor(b *testing.B) {
	config := pkgconfig.GetDefaultConfig()
	config.Collectors.Dnstap.DisableDNSParser = false
	config.Collectors.Dnstap.ChannelBufferSize = 65536

	devNull := NewDevNull(config, logger.New(false), "devnull")
	go devNull.StartCollect()
	defer devNull.Stop()

	// Get fake DNS query and construct marshaled dnstap payload
	dnsquery, err := dnsutils.GetFakeDNS()
	if err != nil {
		b.Fatalf("dns question pack error: %v", err)
	}

	dtQuery := GetFakeDNSTap(dnsquery)
	data, err := proto.Marshal(dtQuery)
	if err != nil {
		b.Fatalf("dnstap proto marshal error: %v", err)
	}

	proc := NewDNSTapProcessor(1, "bench-peer", config, logger.New(false), "bench-proc", config.Collectors.Dnstap.ChannelBufferSize)
	proc.SetDefaultRoutes([]Worker{devNull})
	go proc.StartCollect()
	defer proc.Stop()

	dataChan := proc.GetDataChannel()

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		dataChan <- data
	}
}

// Test_DNSTapProcessor_FramestreamBehavior simulates actual go-framestream behavior
// where a fresh buffer slice (make([]byte, total)) is allocated for each incoming frame.
func Test_DNSTapProcessor_FramestreamBehavior(t *testing.T) {
	config := pkgconfig.GetDefaultConfig()
	config.Collectors.Dnstap.DisableDNSParser = false
	config.Collectors.Dnstap.ChannelBufferSize = 1000

	devNull := NewDevNull(config, logger.New(false), "devnull")
	go devNull.StartCollect()
	defer devNull.Stop()

	dnsquery, err := dnsutils.GetFakeDNS()
	if err != nil {
		t.Fatalf("dns question pack error: %v", err)
	}

	dtQuery := GetFakeDNSTap(dnsquery)
	data, err := proto.Marshal(dtQuery)
	if err != nil {
		t.Fatalf("dnstap proto marshal error: %v", err)
	}

	proc := NewDNSTapProcessor(1, "test-peer", config, logger.New(false), "test-proc", 1000)
	proc.SetDefaultRoutes([]Worker{devNull})
	go proc.StartCollect()
	defer proc.Stop()

	dataChan := proc.GetDataChannel()

	var wg sync.WaitGroup
	wg.Add(1)

	// Single reader thread simulating HandleConn with go-framestream semantics
	go func() {
		defer wg.Done()

		for i := 0; i < 500; i++ {
			// go-framestream allocates a new byte slice per frame: make([]byte, total)
			buf := make([]byte, len(data))
			copy(buf, data)
			dataChan <- buf
			time.Sleep(10 * time.Microsecond)
		}
	}()

	wg.Wait()
}
