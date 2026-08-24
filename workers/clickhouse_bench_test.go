package workers

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/dmachard/go-dnscollector/v2/dnsutils"
	"github.com/dmachard/go-dnscollector/v2/pkgconfig"
	"github.com/dmachard/go-logger"
)

func Benchmark_Clickhouse_Record_EncodeJSON(b *testing.B) {
	dm := dnsutils.GetFakeDNSMessage()
	dm.DNS.Qname = "dnscollector.dev"
	dm.DNS.Flags = dnsutils.DNSFlags{
		QR: true,
		AA: true,
		RD: true,
		RA: true,
	}
	dm.DNSTap.Latency = 0.00123

	buf := new(bytes.Buffer)
	enc := json.NewEncoder(buf)

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		buf.Reset()
		record := convertDNSMessageToRecord(&dm)
		_ = enc.Encode(record)
	}
}

func Benchmark_Clickhouse_Throughput_Batch100(b *testing.B) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("Ok."))
	}))
	defer server.Close()

	cfg := pkgconfig.GetDefaultConfig()
	cfg.Loggers.ClickhouseClient.URL = server.URL
	cfg.Loggers.ClickhouseClient.BufferSize = 100
	cfg.Loggers.ClickhouseClient.FlushInterval = 60

	client := NewClickhouseClient(cfg, logger.New(false), "bench_clickhouse")
	go client.StartCollect()
	defer client.Stop()

	dm := dnsutils.GetFakeDNSMessage()
	dm.DNS.Qname = "dnscollector.dev"
	dm.DNS.Flags = dnsutils.DNSFlags{QR: true, RD: true}
	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		batch := dnsutils.NewDNSMessageBatch(&dm)
		client.GetInputChannel() <- batch
	}
}

func Benchmark_Clickhouse_Throughput_Batch1000(b *testing.B) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("Ok."))
	}))
	defer server.Close()

	cfg := pkgconfig.GetDefaultConfig()
	cfg.Loggers.ClickhouseClient.URL = server.URL
	cfg.Loggers.ClickhouseClient.BufferSize = 1000
	cfg.Loggers.ClickhouseClient.FlushInterval = 60

	client := NewClickhouseClient(cfg, logger.New(false), "bench_clickhouse")
	go client.StartCollect()
	defer client.Stop()

	dm := dnsutils.GetFakeDNSMessage()
	dm.DNS.Qname = "dnscollector.dev"
	dm.DNS.Flags = dnsutils.DNSFlags{QR: true, RD: true}
	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		batch := dnsutils.NewDNSMessageBatch(&dm)
		client.GetInputChannel() <- batch
	}
}
