package workers

import (
	"bytes"
	"fmt"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/dmachard/go-dnscollector/v3/dnsutils"
	"github.com/dmachard/go-dnscollector/v3/pkg/config"
	"github.com/dmachard/go-logger"
	"github.com/google/gopacket/pcapgo"
)

func Test_StdoutTextMode(t *testing.T) {

	cfg := config.GetDefaultConfig()

	testcases := []struct {
		name      string
		delimiter string
		boundary  string
		qname     string
		expected  string
	}{
		{
			name:      "default_delimiter",
			delimiter: cfg.Global.TextFormatDelimiter,
			boundary:  cfg.Global.TextFormatBoundary,
			qname:     config.ProgQname,
			expected:  "- collector CLIENT_QUERY NOERROR 1.2.3.4 1234 IPv4 UDP 0b dns.collector A -\n",
		},
		{
			name:      "custom_delimiter",
			delimiter: ";",
			boundary:  cfg.Global.TextFormatBoundary,
			qname:     config.ProgQname,
			expected:  "-;collector;CLIENT_QUERY;NOERROR;1.2.3.4;1234;IPv4;UDP;0b;dns.collector;A;-\n",
		},
		{
			name:      "default_boundary",
			delimiter: cfg.Global.TextFormatDelimiter,
			boundary:  cfg.Global.TextFormatBoundary,
			qname:     "dns. collector",
			expected:  "- collector CLIENT_QUERY NOERROR 1.2.3.4 1234 IPv4 UDP 0b \"dns. collector\" A -\n",
		},
		{
			name:      "custom_boundary",
			delimiter: cfg.Global.TextFormatDelimiter,
			boundary:  "!",
			qname:     "dns. collector",
			expected:  "- collector CLIENT_QUERY NOERROR 1.2.3.4 1234 IPv4 UDP 0b !dns. collector! A -\n",
		},
		{
			name:      "boundary_in_qname",
			delimiter: cfg.Global.TextFormatDelimiter,
			boundary:  cfg.Global.TextFormatBoundary,
			qname:     "d ns.\"collector\"",
			expected:  "- collector CLIENT_QUERY NOERROR 1.2.3.4 1234 IPv4 UDP 0b \"d ns.\\\"collector\\\"\" A -\n",
		},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			// init logger and redirect stdout output to bytes buffer
			var stdout bytes.Buffer

			cfg := config.GetDefaultConfig()
			cfg.Global.TextFormatDelimiter = tc.delimiter
			cfg.Global.TextFormatBoundary = tc.boundary

			g := NewStdOut(cfg, logger.New(false), "test")
			g.SetTextWriter(&stdout)

			go g.StartCollect()

			// print dns message to stdout buffer
			dm := dnsutils.GetFakeDNSMessage()
			dm.DNS.Qname = tc.qname
			g.GetInputChannel() <- dnsutils.NewDNSMessageBatch(&dm)

			// stop logger
			time.Sleep(time.Second)
			g.Stop()

			// check buffer
			if stdout.String() != tc.expected {
				t.Errorf("invalid stdout output: %s", stdout.String())
			}
		})
	}
}

func Test_StdoutJsonMode(t *testing.T) {
	testcases := []struct {
		mode    string
		pattern string
	}{
		{
			mode:    config.ModeJSON,
			pattern: "\"qname\":\"dns.collector\"",
		},
		{
			mode:    config.ModeFlatJSON,
			pattern: "\"dns.qname\":\"dns.collector\"",
		},
	}

	for _, tc := range testcases {
		t.Run(tc.mode, func(t *testing.T) {
			// init logger and redirect stdout output to bytes buffer
			var stdout bytes.Buffer

			cfg := config.GetDefaultConfig()
			cfg.Loggers.Stdout.Mode = tc.mode
			g := NewStdOut(cfg, logger.New(false), "test")
			g.SetTextWriter(&stdout)

			go g.StartCollect()

			// print dns message to stdout buffer
			dm := dnsutils.GetFakeDNSMessage()
			g.GetInputChannel() <- dnsutils.NewDNSMessageBatch(&dm)

			// stop logger
			time.Sleep(time.Second)
			g.Stop()

			// check buffer
			pattern := regexp.MustCompile(tc.pattern)
			ret := stdout.String()
			if !pattern.MatchString(ret) {
				t.Errorf("stdout error want %s, got: %s", tc.pattern, ret)
			}
		})
	}
}

func Test_StdoutPcapMode(t *testing.T) {
	// redirect stdout output to bytes buffer
	var pcap bytes.Buffer

	// init logger and run
	cfg := config.GetDefaultConfig()
	cfg.Loggers.Stdout.Mode = "pcap"

	g := NewStdOut(cfg, logger.New(false), "test")
	g.SetPcapWriter(&pcap)

	go g.StartCollect()

	// send DNSMessage to channel
	dm := dnsutils.GetFakeDNSMessageWithPayload()
	g.GetInputChannel() <- dnsutils.NewDNSMessageBatch(&dm)

	// stop logger
	time.Sleep(time.Second)
	g.Stop()

	// check pcap output
	pcapReader, err := pcapgo.NewReader(bytes.NewReader(pcap.Bytes()))
	if err != nil {
		t.Errorf("unable to read pcap: %s", err)
		return
	}
	data, _, err := pcapReader.ReadPacketData()
	if err != nil {
		t.Errorf("unable to read packet: %s", err)
		return
	}
	if len(data) < dm.DNS.Length {
		t.Errorf("incorrect packet size: %d", len(data))
	}
}

func Test_StdoutPcapMode_NoDNSPayload(t *testing.T) {
	// redirect stdout output to bytes buffer
	logger := logger.New(false)
	var logs bytes.Buffer
	logger.SetOutput(&logs)

	var pcap bytes.Buffer

	// init logger and run
	cfg := config.GetDefaultConfig()
	cfg.Loggers.Stdout.Mode = "pcap"

	g := NewStdOut(cfg, logger, "test")
	g.SetPcapWriter(&pcap)

	go g.StartCollect()

	// send DNSMessage to channel
	dm := dnsutils.GetFakeDNSMessage()
	g.GetInputChannel() <- dnsutils.NewDNSMessageBatch(&dm)

	// stop logger
	time.Sleep(time.Second)
	g.Stop()

	// check output
	regxp := "ERROR:.*process: no dns payload to encode, drop it.*"
	pattern := regexp.MustCompile(regxp)
	ret := logs.String()
	if !pattern.MatchString(ret) {
		t.Errorf("stdout error want %s, got: %s", regxp, ret)
	}
}

// test for issue https://github.com/dmachard/go-dnscollector/v3/issues/568
func Test_StdoutBufferLoggerIsFull(t *testing.T) {
	// redirect stdout output to bytes buffer
	logsChan := make(chan logger.LogEntry, 512)
	lg := logger.New(true)
	lg.SetOutputChannel((logsChan))

	// init logger and redirect stdout output to bytes buffer
	var stdout bytes.Buffer
	cfg := config.GetDefaultConfig()
	cfg.Global.Worker.InternalMonitor = 1
	g := NewStdOut(cfg, lg, "test")
	g.SetTextWriter(&stdout)

	// init next logger with a buffer of one element
	nxt := GetWorkerForTest(config.DefaultBufferOne)
	g.AddDefaultRoute(nxt)

	// run collector
	go g.StartCollect()
	defer g.Stop()

	// add a shot of dnsmessages to collector
	for range 512 {
		dmIn := dnsutils.GetFakeDNSMessage()
		g.GetInputChannel() <- dnsutils.NewDNSMessageBatch(&dmIn)
	}

	// waiting monitor to run in consumer
	time.Sleep(2 * time.Second)

	for entry := range logsChan {
		fmt.Println(entry)
		pattern := regexp.MustCompile(config.ExpectedBufferMsg511)
		if pattern.MatchString(entry.Message) {
			break
		}
	}

	// read dns message from dnstap consumer
	batchOut := <-nxt.GetInputChannel()
	if len(batchOut.Messages) == 0 || batchOut.Messages[0].DNS.Qname != config.ExpectedQname2 {
		t.Errorf("invalid qname in dns message: %v", batchOut.Messages)
	}

	// send second shot of packets to consumer
	for range 1024 {
		dmIn := dnsutils.GetFakeDNSMessage()
		g.GetInputChannel() <- dnsutils.NewDNSMessageBatch(&dmIn)
	}

	// waiting monitor to run in consumer
	time.Sleep(2 * time.Second)
	for entry := range logsChan {
		fmt.Println(entry)
		pattern := regexp.MustCompile(config.ExpectedBufferMsg1023)
		if pattern.MatchString(entry.Message) {
			break
		}
	}

	// read dns message from dnstap consumer
	batchOut2 := <-nxt.GetInputChannel()
	if len(batchOut2.Messages) == 0 || batchOut2.Messages[0].DNS.Qname != config.ExpectedQname2 {
		t.Errorf("invalid qname in second dns message: %v", batchOut2.Messages)
	}
}

func Test_StdoutTextMode_Batching(t *testing.T) {
	var stdout bytes.Buffer

	cfg := config.GetDefaultConfig()
	cfg.Loggers.Stdout.Mode = config.ModeText
	cfg.Loggers.Stdout.FlushInterval = 1

	g := NewStdOut(cfg, logger.New(false), "test")
	g.SetTextWriter(&stdout)

	go g.StartCollect()

	for range 5 {
		dm := dnsutils.GetFakeDNSMessage()
		g.GetInputChannel() <- dnsutils.NewDNSMessageBatch(&dm)
	}

	// wait for flush 2s > to the default 1s flush interval
	time.Sleep(2 * time.Second)
	g.Stop()

	output := stdout.String()
	lines := strings.Split(strings.TrimSpace(output), "\n")
	if len(lines) != 5 {
		t.Fatalf("expected 5 output lines, got %d\noutput:\n%s", len(lines), output)
	}
}
