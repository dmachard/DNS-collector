package workers

import (
	"io"
	"testing"

	"github.com/dmachard/go-dnscollector/v2/dnsutils"
	"github.com/dmachard/go-dnscollector/v2/pkg/config"
	"github.com/dmachard/go-logger"
)

func benchmarkStdoutMode(b *testing.B, mode string) {
	cfg := config.GetDefaultConfig()
	cfg.Loggers.Stdout.Mode = mode
	cfg.Global.Worker.ChannelBufferSize = 65536

	stdout := NewStdOut(cfg, logger.New(false), "stdout")
	if mode == config.ModePCAP {
		stdout.SetPcapWriter(io.Discard)
	} else {
		stdout.SetTextWriter(io.Discard)
	}

	go stdout.StartCollect()
	defer stdout.Stop()

	dm := dnsutils.GetFakeDNSMessage()
	dm.DNS.Payload = []byte{0x00, 0x01, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
	inChan := stdout.GetInputChannel()

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		msg := dm
		inChan <- dnsutils.NewDNSMessageBatch(&msg)
	}
}

func Benchmark_Stdout_ModeText(b *testing.B) {
	benchmarkStdoutMode(b, config.ModeText)
}

func Benchmark_Stdout_ModeJSON(b *testing.B) {
	benchmarkStdoutMode(b, config.ModeJSON)
}

func Benchmark_Stdout_ModeFlatJSON(b *testing.B) {
	benchmarkStdoutMode(b, config.ModeFlatJSON)
}

func Benchmark_Stdout_ModePCAP(b *testing.B) {
	benchmarkStdoutMode(b, config.ModePCAP)
}
