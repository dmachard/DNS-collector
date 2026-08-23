package workers

import (
	"fmt"
	"regexp"
	"testing"
	"time"

	"github.com/dmachard/go-dnscollector/v2/dnsutils"
	"github.com/dmachard/go-dnscollector/v2/pkgconfig"
	"github.com/dmachard/go-logger"
)

func TestDnsMessage_RoutingPolicy(t *testing.T) {
	// simulate next workers
	kept := GetWorkerForTest(pkgconfig.DefaultBufferSize)
	dropped := GetWorkerForTest(pkgconfig.DefaultBufferSize)

	// config for the collector
	config := pkgconfig.GetDefaultConfig()
	config.Collectors.DNSMessage.Enable = true
	config.Collectors.DNSMessage.Matching.Include = map[string]interface{}{
		"dns.qname": "dns.collector",
	}

	// init the collector
	c := NewDNSMessage(nil, config, logger.New(false), "test")
	c.SetDefaultRoutes([]Worker{kept})
	c.SetDefaultDropped([]Worker{dropped})

	// start to collect and send DNS messages on it
	go c.StartCollect()

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

func TestDnsMessage_BufferLoggerIsFull(t *testing.T) {
	// redirect stdout output to bytes buffer
	logsChan := make(chan logger.LogEntry, 512)
	lg := logger.New(true)
	lg.SetOutputChannel((logsChan))

	// init the collector and run-it
	config := pkgconfig.GetDefaultConfig()
	c := NewDNSMessage(nil, config, lg, "test")

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
	time.Sleep(12 * time.Second)

	for entry := range logsChan {
		fmt.Println(entry)
		pattern := regexp.MustCompile(pkgconfig.ExpectedBufferMsg511)
		if pattern.MatchString(entry.Message) {
			break
		}
	}

	// read dnsmessage from next logger
	batchOut := <-nxt.GetInputChannel()
	if len(batchOut.Messages) == 0 || batchOut.Messages[0].DNS.Qname != pkgconfig.ExpectedQname2 {
		t.Errorf("invalid qname in dns message: %v", batchOut.Messages)
	}

	// send second shot of packets to consumer
	for i := 0; i < 1024; i++ {
		dmIn := dnsutils.GetFakeDNSMessage()
		c.GetInputChannel() <- dnsutils.NewDNSMessageBatch(&dmIn)
	}

	// waiting monitor to run in consumer
	time.Sleep(12 * time.Second)

	for entry := range logsChan {
		fmt.Println(entry)
		pattern := regexp.MustCompile(pkgconfig.ExpectedBufferMsg1023)
		if pattern.MatchString(entry.Message) {
			break
		}
	}
	// read dnsmessage from next logger
	batch2 := <-nxt.GetInputChannel()
	if len(batch2.Messages) == 0 || batch2.Messages[0].DNS.Qname != pkgconfig.ExpectedQname2 {
		t.Errorf("invalid qname in dns message: %v", batch2.Messages)
	}

	// stop all
	c.Stop()
}
