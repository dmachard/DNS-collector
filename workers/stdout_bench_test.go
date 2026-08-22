package workers

import (
	"io"
	"testing"

	"github.com/dmachard/go-dnscollector/v2/dnsutils"
	"github.com/dmachard/go-dnscollector/v2/pkgconfig"
	"github.com/dmachard/go-logger"
)

func benchmarkStdoutMode(b *testing.B, mode string) {
	config := pkgconfig.GetDefaultConfig()
	config.Loggers.Stdout.Mode = mode
	config.Global.Worker.ChannelBufferSize = 65536

	stdout := NewStdOut(config, logger.New(false), "stdout")
	if mode == pkgconfig.ModePCAP {
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
		inChan <- dnsutils.NewDNSMessageBatchFromMessage(&msg)
	}
}

func Benchmark_Stdout_ModeText(b *testing.B) {
	benchmarkStdoutMode(b, pkgconfig.ModeText)
}

func Benchmark_Stdout_ModeJSON(b *testing.B) {
	benchmarkStdoutMode(b, pkgconfig.ModeJSON)
}

func Benchmark_Stdout_ModeFlatJSON(b *testing.B) {
	benchmarkStdoutMode(b, pkgconfig.ModeFlatJSON)
}

func Benchmark_Stdout_ModePCAP(b *testing.B) {
	benchmarkStdoutMode(b, pkgconfig.ModePCAP)
}
