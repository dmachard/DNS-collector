package workers

import (
	"io"
	"testing"

	"github.com/dmachard/go-dnscollector/v2/dnsutils"
	"github.com/dmachard/go-dnscollector/v2/pkg/config"
	"github.com/dmachard/go-logger"
)

func Benchmark_DNSProcessor_Query(b *testing.B) {
	cfg := config.GetDefaultConfig()
	log := logger.New(false)
	log.SetOutput(io.Discard)

	devNull := NewDevNull(cfg, log, "devnull")
	go devNull.StartCollect()
	defer devNull.Stop()

	consumer := NewDNSProcessor(cfg, log, "bench-dnsprocessor", 65536)
	consumer.AddDefaultRoute(devNull)
	go consumer.StartCollect()
	defer consumer.Stop()

	dm := dnsutils.GetFakeDNSMessageWithPayload()
	inChan := consumer.GetInputChannel()

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		msg := dm
		inChan <- dnsutils.NewDNSMessageBatch(&msg)
	}
}

func Benchmark_DNSProcessor_Response(b *testing.B) {
	cfg := config.GetDefaultConfig()
	log := logger.New(false)
	log.SetOutput(io.Discard)

	devNull := NewDevNull(cfg, log, "devnull")
	go devNull.StartCollect()
	defer devNull.Stop()

	consumer := NewDNSProcessor(cfg, log, "bench-dnsprocessor", 65536)
	consumer.AddDefaultRoute(devNull)
	go consumer.StartCollect()
	defer consumer.Stop()

	responsePacket, _ := dnsutils.GetDNSResponsePacket()
	dm := dnsutils.GetFakeDNSMessage()
	dm.DNS.Payload = responsePacket
	dm.DNS.Length = len(responsePacket)
	inChan := consumer.GetInputChannel()

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		msg := dm
		inChan <- dnsutils.NewDNSMessageBatch(&msg)
	}
}

func Benchmark_DNSProcessor_Malformed(b *testing.B) {
	cfg := config.GetDefaultConfig()
	log := logger.New(false)
	log.SetOutput(io.Discard)

	devNull := NewDevNull(cfg, log, "devnull")
	go devNull.StartCollect()
	defer devNull.Stop()

	consumer := NewDNSProcessor(cfg, log, "bench-dnsprocessor", 65536)
	consumer.AddDefaultRoute(devNull)
	go consumer.StartCollect()
	defer consumer.Stop()

	dm := dnsutils.GetFakeDNSMessage()
	dm.DNS.Payload = []byte{0x00, 0x01, 0x01}
	dm.DNS.Length = len(dm.DNS.Payload)
	inChan := consumer.GetInputChannel()

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		msg := dm
		inChan <- dnsutils.NewDNSMessageBatch(&msg)
	}
}
