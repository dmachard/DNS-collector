package workers

import (
	"strconv"
	"testing"

	"github.com/dmachard/go-dnscollector/v2/dnsutils"
	"github.com/dmachard/go-dnscollector/v2/pkg/config"
	"github.com/dmachard/go-logger"
)

func Benchmark_Worker_CountIngressTraffic_TelemetryOn(b *testing.B) {
	cfg := config.GetDefaultConfig()
	cfg.Global.Telemetry.Enabled = true

	devNull := NewDevNull(cfg, logger.New(false), "bench-devnull")
	go devNull.StartCollect()
	defer devNull.Stop()

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		devNull.CountIngressTraffic()
	}
}

func Benchmark_Worker_CountIngressTraffic_TelemetryOff(b *testing.B) {
	cfg := config.GetDefaultConfig()
	cfg.Global.Telemetry.Enabled = false

	devNull := NewDevNull(cfg, logger.New(false), "bench-devnull")
	go devNull.StartCollect()
	defer devNull.Stop()

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		devNull.CountIngressTraffic()
	}
}

func Benchmark_Worker_SendForwardedTo_TelemetryOn(b *testing.B) {
	cfg := config.GetDefaultConfig()
	cfg.Global.Telemetry.Enabled = true

	devNull := NewDevNull(cfg, logger.New(false), "bench-devnull")
	go devNull.StartCollect()
	defer devNull.Stop()

	target := NewDevNull(cfg, logger.New(false), "target-devnull")
	go target.StartCollect()
	defer target.Stop()

	routes := []chan *dnsutils.DNSMessageBatch{target.GetInputChannel()}
	routesName := []string{"target-devnull"}
	dm := dnsutils.GetFakeDNSMessage()

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		msg := dm
		devNull.SendForwardedTo(routes, routesName, &msg)
	}
}

func Benchmark_Worker_SendForwardedBatchTo_TelemetryOn(b *testing.B) {
	cfg := config.GetDefaultConfig()
	cfg.Global.Telemetry.Enabled = true

	devNull := NewDevNull(cfg, logger.New(false), "bench-devnull")
	go devNull.StartCollect()
	defer devNull.Stop()

	target := NewDevNull(cfg, logger.New(false), "target-devnull")
	go target.StartCollect()
	defer target.Stop()

	routes := []chan *dnsutils.DNSMessageBatch{target.GetInputChannel()}
	routesName := []string{"target-devnull"}
	dm := dnsutils.GetFakeDNSMessage()

	batchSize := 64

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i += batchSize {
		batch := dnsutils.AcquireDNSMessageBatch(batchSize)
		for j := 0; j < batchSize; j++ {
			msg := dm
			batch.Messages = append(batch.Messages, &msg)
		}
		devNull.SendForwardedBatchTo(routes, routesName, batch)
	}
}

// Benchmark_Worker_E2E_RunBatchLoop measures end-to-end throughput when a producer
// goroutine feeds messages in batches into the GenericWorker channel and RunBatchLoop
// processes them in the consumer (DevNull).
func Benchmark_Worker_E2E_RunBatchLoop(b *testing.B) {
	cfg := config.GetDefaultConfig()
	cfg.Global.Telemetry.Enabled = true
	cfg.Global.Worker.ChannelBufferSize = 65536

	sink := NewDevNull(cfg, logger.New(false), "sink-devnull")
	go sink.StartCollect()
	defer sink.Stop()

	dm := dnsutils.GetFakeDNSMessage()
	batchSize := 64

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i += batchSize {
		batch := dnsutils.AcquireDNSMessageBatch(batchSize)
		for j := 0; j < batchSize; j++ {
			msg := dm
			batch.Messages = append(batch.Messages, &msg)
		}
		sink.GetInputChannel() <- batch
	}
}

// Benchmark_Worker_E2E_SingleMessage measures single message wrapped in batch per channel send.
func Benchmark_Worker_E2E_SingleMessage(b *testing.B) {
	cfg := config.GetDefaultConfig()
	cfg.Global.Telemetry.Enabled = true
	cfg.Global.Worker.ChannelBufferSize = 65536

	sink := NewDevNull(cfg, logger.New(false), "sink-devnull")
	go sink.StartCollect()
	defer sink.Stop()

	dm := dnsutils.GetFakeDNSMessage()

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		batch := dnsutils.AcquireDNSMessageBatch(1)
		msg := dm
		batch.Messages = append(batch.Messages, &msg)
		sink.GetInputChannel() <- batch
	}
}

func Benchmark_Worker_BatchSize_Comparison(b *testing.B) {
	sizes := []int{1, 16, 32, 64, 128, 256, 512, 1024}
	dm := dnsutils.GetFakeDNSMessage()

	for _, sz := range sizes {
		sz := sz
		b.Run("BatchSize_"+strconv.Itoa(sz), func(subB *testing.B) {
			cfg := config.GetDefaultConfig()
			cfg.Global.Telemetry.Enabled = true
			cfg.Global.Worker.ChannelBufferSize = 65536

			sink := NewDevNull(cfg, logger.New(false), "sink-devnull")
			go sink.StartCollect()
			defer sink.Stop()

			subB.ReportAllocs()
			subB.ResetTimer()

			for i := 0; i < subB.N; i += sz {
				batch := dnsutils.AcquireDNSMessageBatch(sz)
				for j := 0; j < sz; j++ {
					msg := dm
					batch.Messages = append(batch.Messages, &msg)
				}
				sink.GetInputChannel() <- batch
			}
		})
	}
}
