package transformers

import (
	"testing"
	"time"

	"github.com/dmachard/go-dnscollector/v2/dnsutils"
	"github.com/dmachard/go-dnscollector/v2/pkgconfig"
	"github.com/dmachard/go-logger"
)

func BenchmarkReordering_ReorderAndFlush(b *testing.B) {
	config := pkgconfig.GetFakeConfigTransformers()
	config.Reordering.Enable = true
	config.Reordering.MaxBufferSize = 1000

	log := logger.New(false)
	outChans := []chan *dnsutils.DNSMessageBatch{
		make(chan *dnsutils.DNSMessageBatch, 2000),
	}

	reorder := NewReorderingTransform(config, log, "test", 0, outChans)

	// Create 1000 fake messages with different timestamps
	messages := make([]*dnsutils.DNSMessage, 1000)
	for i := 0; i < 1000; i++ {
		msg := dnsutils.GetFakeDNSMessage()
		ts := time.Now().Add(time.Duration(i%2-i%3+i%5) * time.Millisecond)
		msg.DNSTap.Timestamp = ts.UnixNano()
		msg.DNSTap.TimestampRFC3339 = ts.Format(time.RFC3339Nano)
		messages[i] = &msg
	}

	b.ReportAllocs()
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
