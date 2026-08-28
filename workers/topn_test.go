package workers

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/dmachard/go-dnscollector/v3/dnsutils"
	"github.com/dmachard/go-dnscollector/v3/pkg/config"
	"github.com/dmachard/go-logger"
)

func TestTopN_JSONReport(t *testing.T) {
	cfg := &config.Config{}
	cfg.SetDefault()
	cfg.Loggers.TopN.Enable = true
	cfg.Loggers.TopN.Mode = "json"
	cfg.Loggers.TopN.TopN = 5
	cfg.Loggers.TopN.TrackQnames = true
	cfg.Loggers.TopN.TrackClients = true
	cfg.Loggers.TopN.TrackRcodes = true

	log := logger.New(true)
	w := NewTopN(cfg, log, "test-topn")

	var buf bytes.Buffer
	w.SetWriter(&buf)

	// Record traffic directly
	w.RecordQname("google.com")
	w.RecordQname("google.com")
	w.RecordQname("google.com")
	w.RecordQname("github.com")

	w.RecordClient("192.0.2.1")
	w.RecordClient("192.0.2.1")
	w.RecordClient("192.0.2.2")

	w.RecordRcode("NOERROR")
	w.RecordRcode("NXDOMAIN")

	w.totalQueries.Store(7)

	w.GenerateReport(60)

	output := buf.String()
	if !strings.Contains(output, "google.com") || !strings.Contains(output, "192.0.2.1") {
		t.Fatalf("expected output to contain recorded keys, got: %s", output)
	}

	var report TopNReport
	if err := json.Unmarshal(buf.Bytes(), &report); err != nil {
		t.Fatalf("failed to unmarshal topn json report: %v", err)
	}

	if report.TotalQueries != 7 {
		t.Fatalf("expected total queries 7, got %d", report.TotalQueries)
	}
	if len(report.TopQnames) < 2 || report.TopQnames[0].Name != "google.com" || report.TopQnames[0].Count != 3 {
		t.Fatalf("unexpected top qnames: %+v", report.TopQnames)
	}
	if len(report.TopClients) < 2 || report.TopClients[0].Name != "192.0.2.1" || report.TopClients[0].Count != 2 {
		t.Fatalf("unexpected top clients: %+v", report.TopClients)
	}
}

func TestTopN_FlatJSONReport(t *testing.T) {
	cfg := &config.Config{}
	cfg.SetDefault()
	cfg.Loggers.TopN.Enable = true
	cfg.Loggers.TopN.Mode = "flat-json"
	cfg.Loggers.TopN.TopN = 5

	log := logger.New(true)
	w := NewTopN(cfg, log, "test-topn")

	var buf bytes.Buffer
	w.SetWriter(&buf)

	w.RecordQname("domain1.com")
	w.RecordClient("10.0.0.1")
	w.totalQueries.Store(2)

	w.GenerateReport(30)

	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
	if len(lines) != 2 {
		t.Fatalf("expected 2 flat json lines, got %d: %s", len(lines), buf.String())
	}
}

func TestTopN_TextReport(t *testing.T) {
	cfg := &config.Config{}
	cfg.SetDefault()
	cfg.Loggers.TopN.Enable = true
	cfg.Loggers.TopN.Mode = "text"
	cfg.Loggers.TopN.TopN = 5

	log := logger.New(true)
	w := NewTopN(cfg, log, "test-topn")

	var buf bytes.Buffer
	w.SetWriter(&buf)

	w.RecordQname("text-domain.com")
	w.totalQueries.Store(1)

	w.GenerateReport(60)

	output := buf.String()
	if !strings.Contains(output, "Top-N Summary Report") || !strings.Contains(output, "text-domain.com") {
		t.Fatalf("expected text table output, got: %s", output)
	}
}

func TestTopN_StartCollect(t *testing.T) {
	cfg := &config.Config{}
	cfg.SetDefault()
	cfg.Loggers.TopN.Enable = true
	cfg.Loggers.TopN.Interval = 1 // 1 second interval for test

	log := logger.New(true)
	w := NewTopN(cfg, log, "test-topn")

	var buf bytes.Buffer
	w.SetWriter(&buf)

	go w.StartCollect()

	dm := dnsutils.GetFakeDNSMessage()
	dm.DNS.Qname = "streaming-domain.com"
	dm.NetworkInfo.QueryIP = "192.168.1.100"

	w.GetInputChannel() <- dnsutils.NewDNSMessageBatch(&dm)

	time.Sleep(1200 * time.Millisecond)

	w.Stop()

	if !strings.Contains(buf.String(), "streaming-domain.com") {
		t.Fatalf("expected background report loop to output domain, got: %s", buf.String())
	}
}
