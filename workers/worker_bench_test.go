package workers

import (
	"testing"

	"github.com/dmachard/go-dnscollector/v2/dnsutils"
	"github.com/dmachard/go-dnscollector/v2/pkgconfig"
	"github.com/dmachard/go-logger"
)

func Benchmark_Worker_CountIngressTraffic_TelemetryOn(b *testing.B) {
	config := pkgconfig.GetDefaultConfig()
	config.Global.Telemetry.Enabled = true

	devNull := NewDevNull(config, logger.New(false), "bench-devnull")
	go devNull.StartCollect()
	defer devNull.Stop()

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		devNull.CountIngressTraffic()
	}
}

func Benchmark_Worker_CountIngressTraffic_TelemetryOff(b *testing.B) {
	config := pkgconfig.GetDefaultConfig()
	config.Global.Telemetry.Enabled = false

	devNull := NewDevNull(config, logger.New(false), "bench-devnull")
	go devNull.StartCollect()
	defer devNull.Stop()

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		devNull.CountIngressTraffic()
	}
}

func Benchmark_Worker_SendForwardedTo_TelemetryOn(b *testing.B) {
	config := pkgconfig.GetDefaultConfig()
	config.Global.Telemetry.Enabled = true

	devNull := NewDevNull(config, logger.New(false), "bench-devnull")
	go devNull.StartCollect()
	defer devNull.Stop()

	target := NewDevNull(config, logger.New(false), "target-devnull")
	go target.StartCollect()
	defer target.Stop()

	routes := []chan *dnsutils.DNSMessage{target.GetInputChannel()}
	routesName := []string{"target-devnull"}
	dm := dnsutils.GetFakeDNSMessage()

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		msg := dm
		devNull.SendForwardedTo(routes, routesName, &msg)
	}
}
