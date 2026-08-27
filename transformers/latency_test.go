package transformers

import (
	"testing"
	"time"

	"github.com/dmachard/go-dnscollector/v3/dnsutils"
	"github.com/dmachard/go-dnscollector/v3/pkg/config"
	"github.com/dmachard/go-logger"
)

func TestLatency_MeasureLatencyAndMs(t *testing.T) {
	// enable feature
	cfg := config.GetFakeConfigTransformers()
	outChannels := []chan *dnsutils.DNSMessageBatch{}

	// init transformer
	latency := NewLatencyTransform(&cfg.Latency, logger.New(true), "test", 0, outChannels)
	latency.GetTransforms()

	testcases := []struct {
		name string
		cq   string
		cr   string
	}{
		{
			name: "standard_mode",
			cq:   dnsutils.DNSQuery,
			cr:   dnsutils.DNSReply,
		},
		{
			name: "quiet_mode",
			cq:   dnsutils.DNSQueryQuiet,
			cr:   dnsutils.DNSReplyQuiet,
		},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			// Register Query
			CQ := dnsutils.GetFakeDNSMessage()
			CQ.DNS.Type = tc.cq
			CQ.DNSTap.Timestamp = int64(1704486841216166066) // example nanoseconds timestamp

			latency.measureLatency(&CQ)

			// Register Response
			CR := dnsutils.GetFakeDNSMessage()
			CR.DNS.Type = tc.cr
			CR.DNSTap.Timestamp = int64(1704486841227961611)

			latency.measureLatency(&CR)

			// Check Latency in seconds
			if CR.DNSTap.Latency <= 0.0 {
				t.Errorf("incorrect latency, got %f", CR.DNSTap.Latency)
			}

			// Check Latency in milliseconds
			expectedMs := CR.DNSTap.Latency * 1000
			if CR.DNSTap.LatencyMs != int(expectedMs) {
				t.Errorf("incorrect latencyMs, got %d, expected %d", CR.DNSTap.LatencyMs, int(expectedMs))
			}
		})
	}
}

func TestLatency_DetectEvictedTimeout(t *testing.T) {
	// enable feature
	cfg := config.GetFakeConfigTransformers()
	cfg.Latency.Enable = true
	cfg.Latency.QueriesTimeout = 1

	outChannels := []chan *dnsutils.DNSMessageBatch{}
	outChannels = append(outChannels, make(chan *dnsutils.DNSMessageBatch, 1))

	// init transformer
	latency := NewLatencyTransform(&cfg.Latency, logger.New(true), "test", 0, outChannels)
	latency.GetTransforms()

	testcases := []struct {
		name string
		cq   string
		cr   string
	}{
		{
			name: "standard_mode",
			cq:   dnsutils.DNSQuery,
			cr:   dnsutils.DNSReply,
		},
		{
			name: "quiet_mode",
			cq:   dnsutils.DNSQueryQuiet,
			cr:   dnsutils.DNSReplyQuiet,
		},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			// Register Query
			CQ := dnsutils.GetFakeDNSMessage()
			CQ.DNS.Type = tc.cq
			CQ.DNSTap.Timestamp = 1704486841216166066

			// Measure latency
			latency.detectEvictedTimeout(&CQ)

			time.Sleep(2 * time.Second)

			batchTimeout := <-outChannels[0]
			if len(batchTimeout.Messages) == 0 || batchTimeout.Messages[0].DNS.Rcode != "TIMEOUT" {
				t.Errorf("incorrect rcode, expected=TIMEOUT, got=%s", batchTimeout.Messages[0].DNS.Rcode)
			}
		})
	}
}

func Test_HashQueries(t *testing.T) {
	// init map
	mapttl := NewHashQueries(2 * time.Second)

	// Set a new key/value
	mapttl.Set(uint64(1), int64(0))

	// Get value according to the key
	_, ok := mapttl.Get(uint64(1))
	if !ok {
		t.Errorf("key does not exist in the map")
	}
}

func Test_HashQueries_Expire(t *testing.T) {
	// ini map
	mapttl := NewHashQueries(1 * time.Second)

	// Set a new key/value
	mapttl.Set(uint64(1), int64(0))

	// sleep during 2 seconds
	time.Sleep(2 * time.Second)

	// Get value according to the key
	_, ok := mapttl.Get(uint64(1))
	if ok {
		t.Errorf("key/value always in map!")
	}
}
