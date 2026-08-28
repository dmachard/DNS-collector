package workers

import (
	"io"
	"testing"

	"github.com/dmachard/go-dnscollector/v3/dnsutils"
	"github.com/dmachard/go-dnscollector/v3/pkg/config"
	"github.com/dmachard/go-logger"
)

func Benchmark_TopN_Record_Direct(b *testing.B) {
	cfg := config.GetDefaultConfig()
	cfg.Loggers.TopN.Enable = true
	cfg.Loggers.TopN.TopN = 50
	cfg.Loggers.TopN.TrackQnames = true
	cfg.Loggers.TopN.TrackClients = true
	cfg.Loggers.TopN.TrackRcodes = true
	cfg.Loggers.TopN.TrackTlds = true

	w := NewTopN(cfg, logger.New(false), "bench-topn")
	w.SetWriter(io.Discard)

	dm := dnsutils.GetFakeDNSMessage()
	dm.DNS.Qname = "dnscollector.dev"
	dm.NetworkInfo.QueryIP = "192.168.1.100"
	dm.DNS.Rcode = "NOERROR"
	dm.PublicSuffix = &dnsutils.TransformPublicSuffix{
		QnamePublicSuffix: "dev",
	}

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		w.RecordQname(dm.DNS.Qname)
		w.RecordClient(dm.NetworkInfo.QueryIP)
		w.RecordRcode(dm.DNS.Rcode)
		w.RecordTld(dm.PublicSuffix.QnamePublicSuffix)
		w.totalQueries.Add(1)
	}
}

func Benchmark_TopN_GenerateReport_Text(b *testing.B) {
	cfg := config.GetDefaultConfig()
	cfg.Loggers.TopN.Enable = true
	cfg.Loggers.TopN.Mode = "text"
	cfg.Loggers.TopN.TopN = 50
	cfg.Loggers.TopN.TrackQnames = true
	cfg.Loggers.TopN.TrackClients = true
	cfg.Loggers.TopN.TrackRcodes = true

	w := NewTopN(cfg, logger.New(false), "bench-topn-text")
	w.SetWriter(io.Discard)

	for i := 0; i < 50; i++ {
		w.RecordQname("domain.com")
		w.RecordClient("192.0.2.1")
		w.RecordRcode("NOERROR")
	}

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		w.GenerateReport(60)
	}
}

func Benchmark_TopN_GenerateReport_JSON(b *testing.B) {
	cfg := config.GetDefaultConfig()
	cfg.Loggers.TopN.Enable = true
	cfg.Loggers.TopN.Mode = "json"
	cfg.Loggers.TopN.TopN = 50
	cfg.Loggers.TopN.TrackQnames = true
	cfg.Loggers.TopN.TrackClients = true
	cfg.Loggers.TopN.TrackRcodes = true

	w := NewTopN(cfg, logger.New(false), "bench-topn-json")
	w.SetWriter(io.Discard)

	for i := 0; i < 50; i++ {
		w.RecordQname("domain.com")
		w.RecordClient("192.0.2.1")
		w.RecordRcode("NOERROR")
	}

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		w.GenerateReport(60)
	}
}

func Benchmark_TopN_GenerateReport_FlatJSON(b *testing.B) {
	cfg := config.GetDefaultConfig()
	cfg.Loggers.TopN.Enable = true
	cfg.Loggers.TopN.Mode = "flat-json"
	cfg.Loggers.TopN.TopN = 50
	cfg.Loggers.TopN.TrackQnames = true
	cfg.Loggers.TopN.TrackClients = true
	cfg.Loggers.TopN.TrackRcodes = true

	w := NewTopN(cfg, logger.New(false), "bench-topn-flat")
	w.SetWriter(io.Discard)

	for i := 0; i < 50; i++ {
		w.RecordQname("domain.com")
		w.RecordClient("192.0.2.1")
		w.RecordRcode("NOERROR")
	}

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		w.GenerateReport(60)
	}
}
