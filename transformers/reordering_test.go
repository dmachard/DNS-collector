package transformers

import (
	"sort"
	"testing"
	"time"

	"github.com/dmachard/go-dnscollector/v2/dnsutils"
	"github.com/dmachard/go-dnscollector/v2/pkgconfig"
	"github.com/dmachard/go-logger"
)

func TestReorderingTransform_SortByTimestamp(t *testing.T) {
	// enable feature
	config := pkgconfig.GetFakeConfigTransformers()
	config.Reordering.Enable = true

	// initialize logger
	log := logger.New(false)

	// create output channels
	outChans := []chan dnsutils.DNSMessage{
		make(chan dnsutils.DNSMessage, 10),
	}

	// initialize transformer
	reorder := NewReorderingTransform(config, log, "test", 0, outChans)

	dm1 := dnsutils.GetFakeDNSMessage()
	dm1.DNSTap.TimestampRFC3339 = "2024-12-20T21:12:14.786109Z"

	dm2 := dnsutils.GetFakeDNSMessage()
	dm2.DNSTap.TimestampRFC3339 = "2024-12-20T21:12:14.766361Z"

	dm3 := dnsutils.GetFakeDNSMessage()
	dm3.DNSTap.TimestampRFC3339 = "2024-12-20T21:12:14.803447Z"

	reorder.ReorderLogs(&dm1)
	reorder.ReorderLogs(&dm2)
	reorder.ReorderLogs(&dm3)

	// manually trigger a buffer flush
	reorder.flushBuffer()

	// collect results from the output channel
	var results []dnsutils.DNSMessage
	done := false
	for !done {
		select {
		case msg := <-outChans[0]:
			results = append(results, msg)
		default:
			done = true
		}
	}

	// validate order
	if len(results) != 3 {
		t.Fatalf("Expected 3 messages, got %d", len(results))
	}

	timestamps := []string{
		results[0].DNSTap.TimestampRFC3339,
		results[1].DNSTap.TimestampRFC3339,
		results[2].DNSTap.TimestampRFC3339,
	}

	if !sort.StringsAreSorted(timestamps) {
		t.Errorf("Timestamps are not sorted: %v", timestamps)
	}
}

func BenchmarkReordering_ReorderAndFlush(b *testing.B) {
	config := pkgconfig.GetFakeConfigTransformers()
	config.Reordering.Enable = true
	config.Reordering.MaxBufferSize = 1000

	log := logger.New(false)
	outChans := []chan dnsutils.DNSMessage{
		make(chan dnsutils.DNSMessage, 2000),
	}

	reorder := NewReorderingTransform(config, log, "test", 0, outChans)

	// Create 1000 fake messages with different timestamps
	messages := make([]dnsutils.DNSMessage, 1000)
	for i := 0; i < 1000; i++ {
		messages[i] = dnsutils.GetFakeDNSMessage()
		ts := time.Now().Add(time.Duration(i%2-i%3+i%5) * time.Millisecond)
		messages[i].DNSTap.Timestamp = ts.UnixNano()
		messages[i].DNSTap.TimestampRFC3339 = ts.Format(time.RFC3339Nano)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		// Fill buffer
		for j := 0; j < 1000; j++ {
			reorder.buffer = append(reorder.buffer, messages[j])
		}
		// Flush buffer
		reorder.flushBuffer()

		// Drain output channel
		for len(outChans[0]) > 0 {
			<-outChans[0]
		}
	}
}
