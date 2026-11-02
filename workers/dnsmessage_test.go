package workers

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"testing"
	"time"

	"github.com/dmachard/go-dnscollector/v3/dnsutils"
	"github.com/dmachard/go-dnscollector/v3/pkg/config"
	"github.com/dmachard/go-logger"
)

func TestDnsMessage_MatchSourceFromStringKeyMap(t *testing.T) {
	matchListPath := filepath.Join(t.TempDir(), "ip_addr_per_line.conf")
	if err := os.WriteFile(matchListPath, []byte("192.0.2.10\n"), 0600); err != nil {
		t.Fatalf("failed to write match source file: %v", err)
	}

	cfg := config.GetDefaultConfig()
	cfg.Collectors.DNSMessage.Matching.Include = map[string]interface{}{
		"network.query-ip": map[string]interface{}{
			"match-source": "file://" + matchListPath,
			"source-kind":  "string_list",
		},
	}

	c := NewDNSMessage(nil, cfg, logger.New(false), "test")

	matchingMessage := dnsutils.GetFakeDNSMessage()
	matchingMessage.NetworkInfo.QueryIP = "192.0.2.10"
	if !c.matcherInclude.Match(&matchingMessage) {
		t.Fatal("expected query IP from match source to be included")
	}

	nonMatchingMessage := dnsutils.GetFakeDNSMessage()
	nonMatchingMessage.NetworkInfo.QueryIP = "192.0.2.11"
	if c.matcherInclude.Match(&nonMatchingMessage) {
		t.Fatal("expected query IP absent from match source to be excluded")
	}
}

func TestDnsMessage_RoutingPolicy(t *testing.T) {
	// simulate next workers
	kept := GetWorkerForTest(config.DefaultBufferSize)
	dropped := GetWorkerForTest(config.DefaultBufferSize)

	// config for the collector
	cfg := config.GetDefaultConfig()
	cfg.Collectors.DNSMessage.Enable = true
	cfg.Collectors.DNSMessage.Matching.Include = map[string]interface{}{
		"dns.qname": "dns.collector",
	}

	// init the collector
	c := NewDNSMessage(nil, cfg, logger.New(false), "test")
	c.SetDefaultRoutes([]Worker{kept})
	c.SetDefaultDropped([]Worker{dropped})

	// start to collect and send DNS messages on it
	go c.StartCollect()
	defer c.Stop()

	// this message should be kept by the collector
	dm1 := dnsutils.GetFakeDNSMessage()
	c.GetInputChannel() <- dnsutils.NewDNSMessageBatch(&dm1)

	// this message should dropped by the collector
	dm2 := dnsutils.GetFakeDNSMessage()
	dm2.DNS.Qname = "dropped.collector"
	c.GetInputChannel() <- dnsutils.NewDNSMessageBatch(&dm2)

	// the 1er message should be in th k worker
	batchKept := <-kept.GetInputChannel()
	if len(batchKept.Messages) == 0 || batchKept.Messages[0].DNS.Qname != "dns.collector" {
		t.Errorf("invalid dns message with default routing policy")
	}

	// the 2nd message should be in the d worker
	batchDropped := <-dropped.GetInputChannel()
	if len(batchDropped.Messages) == 0 || batchDropped.Messages[0].DNS.Qname != "dropped.collector" {
		t.Errorf("invalid dns message with dropped routing policy")
	}

}

func waitForLogMatch(ch <-chan logger.LogEntry, pattern *regexp.Regexp, timeout time.Duration) bool {
	deadline := time.After(timeout)
	for {
		select {
		case entry, ok := <-ch:
			if !ok {
				return false
			}
			fmt.Println(entry)
			if pattern.MatchString(entry.Message) {
				return true
			}
		case <-deadline:
			return false
		}
	}
}

func TestDnsMessage_BufferLoggerIsFull(t *testing.T) {
	// redirect stdout output to bytes buffer
	logsChan := make(chan logger.LogEntry, 512)
	lg := logger.New(true)
	lg.SetOutputChannel((logsChan))

	// init the collector and run-it
	cfg := config.GetDefaultConfig()
	cfg.Global.Worker.InternalMonitor = 1
	c := NewDNSMessage(nil, cfg, lg, "test")

	// init next logger with a buffer of one element
	nxt := GetWorkerForTest(1)
	c.AddDefaultRoute(nxt)

	// run collector
	go c.StartCollect()

	// add a shot of dnsmessages to collector
	for i := 0; i < 512; i++ {
		dmIn := dnsutils.GetFakeDNSMessage()
		c.GetInputChannel() <- dnsutils.NewDNSMessageBatch(&dmIn)
	}

	// waiting monitor to run in consumer
	time.Sleep(2 * time.Second)

	if !waitForLogMatch(logsChan, regexp.MustCompile(config.ExpectedBufferMsg511), 3*time.Second) {
		t.Fatal("did not receive 511 dropped message log")
	}

	// read dnsmessage from next logger
	batchOut := <-nxt.GetInputChannel()
	if len(batchOut.Messages) == 0 || batchOut.Messages[0].DNS.Qname != config.ExpectedQname2 {
		t.Errorf("invalid qname in dns message: %v", batchOut.Messages)
	}

	// send second shot of packets to consumer
	for i := 0; i < 1024; i++ {
		dmIn := dnsutils.GetFakeDNSMessage()
		c.GetInputChannel() <- dnsutils.NewDNSMessageBatch(&dmIn)
	}

	// waiting monitor to run in consumer
	time.Sleep(2 * time.Second)

	if !waitForLogMatch(logsChan, regexp.MustCompile(config.ExpectedBufferMsg1023), 3*time.Second) {
		t.Fatal("did not receive 1023 dropped message log")
	}
	// read dnsmessage from next logger
	batch2 := <-nxt.GetInputChannel()
	if len(batch2.Messages) == 0 || batch2.Messages[0].DNS.Qname != config.ExpectedQname2 {
		t.Errorf("invalid qname in dns message: %v", batch2.Messages)
	}

	// stop all
	c.Stop()
}

func TestDnsMessage_BatchPreserved(t *testing.T) {
	kept := GetWorkerForTest(10)
	cfg := config.GetDefaultConfig()
	cfg.Collectors.DNSMessage.Enable = true

	c := NewDNSMessage(nil, cfg, logger.New(false), "test")
	c.SetDefaultRoutes([]Worker{kept})

	go c.StartCollect()
	defer c.Stop()

	// send a batch of 10 messages
	const count = 10
	inBatch := dnsutils.AcquireDNSMessageBatch(count)
	for i := 0; i < count; i++ {
		dm := dnsutils.GetFakeDNSMessage()
		dm.DNS.Qname = fmt.Sprintf("dns%d.collector", i)
		inBatch.Messages = append(inBatch.Messages, &dm)
	}
	c.GetInputChannel() <- inBatch

	// read from kept worker
	select {
	case outBatch := <-kept.GetInputChannel():
		if len(outBatch.Messages) != count {
			t.Fatalf("expected batch of %d messages, got batch of %d messages (batching was shattered into single messages)", count, len(outBatch.Messages))
		}
	case <-time.After(time.Second):
		t.Fatal("timeout waiting for batch")
	}
}

func TestDnsMessage_BatchPreserved_WithFiltering(t *testing.T) {
	kept := GetWorkerForTest(10)
	dropped := GetWorkerForTest(10)
	cfg := config.GetDefaultConfig()
	cfg.Collectors.DNSMessage.Enable = true
	cfg.Collectors.DNSMessage.Matching.Include = map[string]interface{}{
		"dns.qname": "keep.*",
	}

	c := NewDNSMessage(nil, cfg, logger.New(false), "test-filtering")
	c.SetDefaultRoutes([]Worker{kept})
	c.SetDefaultDropped([]Worker{dropped})

	go c.StartCollect()
	defer c.Stop()

	// send batch with 6 kept and 4 dropped messages
	inBatch := dnsutils.AcquireDNSMessageBatch(10)
	for i := 0; i < 6; i++ {
		dm := dnsutils.GetFakeDNSMessage()
		dm.DNS.Qname = fmt.Sprintf("keep.%d.example.com", i)
		inBatch.Messages = append(inBatch.Messages, &dm)
	}
	for i := 0; i < 4; i++ {
		dm := dnsutils.GetFakeDNSMessage()
		dm.DNS.Qname = fmt.Sprintf("drop.%d.example.com", i)
		inBatch.Messages = append(inBatch.Messages, &dm)
	}
	c.GetInputChannel() <- inBatch

	// kept route should receive 1 batch of 6
	select {
	case outBatch := <-kept.GetInputChannel():
		if len(outBatch.Messages) != 6 {
			t.Fatalf("expected kept batch of 6 messages, got %d", len(outBatch.Messages))
		}
	case <-time.After(time.Second):
		t.Fatal("timeout waiting for kept batch")
	}

	// dropped route should receive 1 batch of 4
	select {
	case outBatch := <-dropped.GetInputChannel():
		if len(outBatch.Messages) != 4 {
			t.Fatalf("expected dropped batch of 4 messages, got %d", len(outBatch.Messages))
		}
	case <-time.After(time.Second):
		t.Fatal("timeout waiting for dropped batch")
	}
}
