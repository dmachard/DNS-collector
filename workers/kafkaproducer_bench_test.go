package workers

import (
	"testing"

	"github.com/dmachard/go-dnscollector/v3/dnsutils"
	"github.com/dmachard/go-logger"
)

func Benchmark_KafkaProducer_FlushBuffer(b *testing.B) {
	listener, broker := createMockBroker(nil, 1, testAddress+":"+testPort, testTopic)
	defer listener.Close()
	defer broker.Close()

	cfg := setupKafkaProducerConfig(testAddress, testPort, testTopic, "none")
	producer := NewKafkaProducer(cfg, logger.New(false), "bench")
	defer producer.Disconnect()

	dm := dnsutils.GetFakeDNSMessage()
	batchSize := 100

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		b.StopTimer()
		buf := make([]*dnsutils.DNSMessage, batchSize)
		for j := 0; j < batchSize; j++ {
			msg := dm
			buf[j] = &msg
		}
		b.StartTimer()

		producer.FlushBuffer(&buf)
	}
}
