package workers

import (
	"bytes"
	"fmt"
	"regexp"
	"testing"
	"time"

	"github.com/dmachard/go-dnscollector/v2/dnsutils"
	"github.com/dmachard/go-dnscollector/v2/pkgconfig"
	"github.com/dmachard/go-logger"
)

func Test_DnsProcessor(t *testing.T) {
	logger := logger.New(true)
	var o bytes.Buffer
	logger.SetOutput(&o)

	// init and run the dns processor
	fl := GetWorkerForTest(pkgconfig.DefaultBufferSize)

	consumer := NewDNSProcessor(pkgconfig.GetDefaultConfig(), logger, "test", 512)
	consumer.AddDefaultRoute(fl)
	consumer.AddDroppedRoute(fl)
	go consumer.StartCollect()

	dm := dnsutils.GetFakeDNSMessageWithPayload()
	consumer.GetInputChannel() <- dnsutils.NewDNSMessageBatch(&dm)

	// read dns message from dnstap consumer
	batchOut := <-fl.GetInputChannel()
	if len(batchOut.Messages) == 0 || batchOut.Messages[0].DNS.Qname != pkgconfig.ExpectedQname {
		t.Errorf("invalid qname in dns message: %v", batchOut.Messages)
	}
}

func Test_DnsProcessor_DecodeCounters(t *testing.T) {
	logger := logger.New(true)
	var o bytes.Buffer
	logger.SetOutput(&o)

	// init and run the dns processor
	fl := GetWorkerForTest(pkgconfig.DefaultBufferSize)

	consumer := NewDNSProcessor(pkgconfig.GetDefaultConfig(), logger, "test", 512)
	consumer.AddDefaultRoute(fl)
	consumer.AddDroppedRoute(fl)
	go consumer.StartCollect()

	// get dns packet
	responsePacket, _ := dnsutils.GetDNSResponsePacket()

	// prepare dns message
	dm := dnsutils.GetFakeDNSMessage()
	dm.DNS.Payload = responsePacket
	dm.DNS.Length = len(responsePacket)

	// send dm to consumer
	consumer.GetInputChannel() <- dnsutils.NewDNSMessageBatch(&dm)

	// read dns message from dnstap consumer
	batchOut := <-fl.GetInputChannel()
	if len(batchOut.Messages) == 0 {
		t.Fatalf("expected message in batch")
	}
	dmOut := batchOut.Messages[0]
	if dmOut.DNS.QdCount != 1 {
		t.Errorf("invalid number of questions in dns message: got %d expect 1", dmOut.DNS.QdCount)
	}
	if dmOut.DNS.NsCount != 1 {
		t.Errorf("invalid number of nscount in dns message: got %d expect 1", dmOut.DNS.NsCount)
	}
	if dmOut.DNS.AnCount != 1 {
		t.Errorf("invalid number of ancount in dns message: got %d expect 1", dmOut.DNS.AnCount)
	}
	if dmOut.DNS.ArCount != 1 {
		t.Errorf("invalid number of arcount in dns message: got %d expect 1", dmOut.DNS.ArCount)
	}
}

func Test_DnsProcessor_BufferLoggerIsFull(t *testing.T) {
	// redirect stdout output to bytes buffer
	logsChan := make(chan logger.LogEntry, 512)
	lg := logger.New(true)
	lg.SetOutputChannel((logsChan))

	// init and run the dns processor
	fl := GetWorkerForTest(pkgconfig.DefaultBufferOne)
	consumer := NewDNSProcessor(pkgconfig.GetDefaultConfig(), lg, "test", 512)
	consumer.AddDefaultRoute(fl)
	consumer.AddDroppedRoute(fl)
	go consumer.StartCollect()

	// add packets to consumer
	for i := 0; i < 512; i++ {
		dm := dnsutils.GetFakeDNSMessageWithPayload()
		consumer.GetInputChannel() <- dnsutils.NewDNSMessageBatch(&dm)
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

	// read dnsmessage from dnstap consumer
	batchOut := <-fl.GetInputChannel()
	if len(batchOut.Messages) == 0 || batchOut.Messages[0].DNS.Qname != pkgconfig.ExpectedQname {
		t.Errorf("invalid qname in dns message: %v", batchOut.Messages)
	}

	// send second shot of packets to consumer
	for i := 0; i < 1024; i++ {
		dm := dnsutils.GetFakeDNSMessageWithPayload()
		consumer.GetInputChannel() <- dnsutils.NewDNSMessageBatch(&dm)
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

	// read dnsmessage from dnstap consumer
	batch2 := <-fl.GetInputChannel()
	if len(batch2.Messages) == 0 || batch2.Messages[0].DNS.Qname != pkgconfig.ExpectedQname {
		t.Errorf("invalid qname in second dns message: %v", batch2.Messages)
	}
}
