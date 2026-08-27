package workers

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/dmachard/go-dnscollector/v3/dnsutils"
	"github.com/dmachard/go-dnscollector/v3/pkg/config"
	"github.com/dmachard/go-logger"
)

func benchmarkLogFileMode(b *testing.B, mode string) {
	tempDir := b.TempDir()
	filePath := filepath.Join(tempDir, "bench_logfile.log")

	cfg := config.GetDefaultConfig()
	cfg.Loggers.LogFile.FilePath = filePath
	cfg.Loggers.LogFile.Mode = mode
	cfg.Global.Worker.ChannelBufferSize = 65536
	cfg.Loggers.LogFile.FlushInterval = 0

	g := NewLogFile(cfg, logger.New(false), "bench-logfile")
	go g.StartCollect()
	defer g.Stop()

	dm := dnsutils.GetFakeDNSMessage()
	dm.DNS.Payload = []byte{0x00, 0x01, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
	inChan := g.GetInputChannel()

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		msg := dm
		inChan <- dnsutils.NewDNSMessageBatch(&msg)
	}
	b.StopTimer()

	_ = os.Remove(filePath)
}

func Benchmark_LogFile_ModeText(b *testing.B) {
	benchmarkLogFileMode(b, config.ModeText)
}

func Benchmark_LogFile_ModeJSON(b *testing.B) {
	benchmarkLogFileMode(b, config.ModeJSON)
}

func Benchmark_LogFile_ModeFlatJSON(b *testing.B) {
	benchmarkLogFileMode(b, config.ModeFlatJSON)
}

func Benchmark_LogFile_ModePCAP(b *testing.B) {
	benchmarkLogFileMode(b, config.ModePCAP)
}
