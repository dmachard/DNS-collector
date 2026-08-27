package transformers

import (
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/dmachard/go-dnscollector/v2/dnsutils"
	"github.com/dmachard/go-dnscollector/v2/pkg/bgpmrt"
	"github.com/dmachard/go-dnscollector/v2/pkg/config"
	"github.com/dmachard/go-logger"
)

func createSampleMRTFile(t *testing.T, dir string) string {
	t.Helper()
	mrtPath := filepath.Join(dir, "test_table.mrt")
	f, err := os.Create(mrtPath)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	routes := []bgpmrt.BGPRecord{
		{Prefix: "192.0.2.0/24", OriginASN: "65001", ASPath: "100 200 65001"},
		{Prefix: "192.0.2.128/25", OriginASN: "65002", ASPath: "100 300 65002"},
		{Prefix: "198.51.100.0/24", OriginASN: "65003", ASPath: "400 65003"},
		{Prefix: "2001:db8::/32", OriginASN: "65010", ASPath: "1000 65010"},
		{Prefix: "2001:db8:1::/48", OriginASN: "65011", ASPath: "1000 2000 65011"},
	}

	if err := bgpmrt.WriteSampleMRT(f, routes); err != nil {
		t.Fatal(err)
	}
	return mrtPath
}

func Test_BGP_MRT_ParseAndLookup(t *testing.T) {
	tempDir := t.TempDir()
	mrtPath := createSampleMRTFile(t, tempDir)

	parser := bgpmrt.NewMRTParser()
	tree, err := parser.ParseFile(mrtPath)
	if err != nil {
		t.Fatalf("failed to parse sample MRT: %v", err)
	}

	if tree.TotalPrefixes() != 5 {
		t.Errorf("expected 5 prefixes, got %d", tree.TotalPrefixes())
	}

	// 1. Exact match /24
	rec := tree.Lookup(net.ParseIP("192.0.2.1"))
	if rec == nil || rec.OriginASN != "65001" || rec.Prefix != "192.0.2.0/24" {
		t.Errorf("unexpected record for 192.0.2.1: %+v", rec)
	}

	// 2. Longest Prefix Match /25 vs /24
	recLPM := tree.Lookup(net.ParseIP("192.0.2.130"))
	if recLPM == nil || recLPM.OriginASN != "65002" || recLPM.Prefix != "192.0.2.128/25" {
		t.Errorf("expected LPM /25 match for 192.0.2.130, got %+v", recLPM)
	}

	// 3. IPv6 LPM /48 vs /32
	recV6 := tree.Lookup(net.ParseIP("2001:db8:1::53"))
	if recV6 == nil || recV6.OriginASN != "65011" || recV6.Prefix != "2001:db8:1::/48" {
		t.Errorf("expected IPv6 LPM match for 2001:db8:1::53, got %+v", recV6)
	}

	// 4. Unannounced IP (No match)
	recNone := tree.Lookup(net.ParseIP("203.0.113.1"))
	if recNone != nil {
		t.Errorf("expected nil for unannounced IP, got %+v", recNone)
	}
}

func Test_BGP_Transform(t *testing.T) {
	tempDir := t.TempDir()
	mrtPath := createSampleMRTFile(t, tempDir)

	cfg := config.GetFakeConfigTransformers()
	cfg.BGP.Enable = true
	cfg.BGP.MrtFile = mrtPath
	cfg.BGP.OriginASN = true
	cfg.BGP.ASPath = true
	cfg.BGP.Prefix = true

	outChan := make(chan *dnsutils.DNSMessageBatch, 10)
	transforms := NewTransforms(cfg, logger.New(false), "test", []chan *dnsutils.DNSMessageBatch{outChan}, 0)

	dm := dnsutils.AcquireDNSMessage()
	dm.Init()
	dm.NetworkInfo.SetQueryIPBytes(net.ParseIP("192.0.2.130"))

	res, err := transforms.ProcessMessage(dm)
	if err != nil {
		t.Fatalf("unexpected error processing message: %v", err)
	}
	if res != ReturnKeep {
		t.Fatalf("expected ReturnKeep, got %d", res)
	}

	if dm.BGP == nil {
		t.Fatal("expected dm.BGP to be non-nil")
	}
	if dm.BGP.OriginASN != "65002" {
		t.Errorf("expected OriginASN 65002, got %s", dm.BGP.OriginASN)
	}
	if dm.BGP.ASPath != "100 300 65002" {
		t.Errorf("expected ASPath '100 300 65002', got %s", dm.BGP.ASPath)
	}
	if dm.BGP.Prefix != "192.0.2.128/25" {
		t.Errorf("expected Prefix '192.0.2.128/25', got %s", dm.BGP.Prefix)
	}
}

func Test_BGP_LookupECS(t *testing.T) {
	tempDir := t.TempDir()
	mrtPath := createSampleMRTFile(t, tempDir)

	cfg := config.GetFakeConfigTransformers()
	cfg.BGP.Enable = true
	cfg.BGP.MrtFile = mrtPath
	cfg.BGP.LookupECS = true

	outChan := make(chan *dnsutils.DNSMessageBatch, 10)
	transforms := NewTransforms(cfg, logger.New(false), "test-ecs", []chan *dnsutils.DNSMessageBatch{outChan}, 0)

	dm := dnsutils.AcquireDNSMessage()
	dm.Init()
	// Query IP is unannounced
	dm.NetworkInfo.SetQueryIPBytes(net.ParseIP("203.0.113.50"))
	// ECS IP is 198.51.100.5
	dm.EDNS.Options = []dnsutils.DNSOption{
		{Code: 8, Name: "CLIENT-SUBNET", Data: "198.51.100.5/32"},
	}

	_, err := transforms.ProcessMessage(dm)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if dm.BGP == nil || dm.BGP.OriginASN != "65003" {
		t.Errorf("expected ECS OriginASN 65003, got %+v", dm.BGP)
	}
}

func Test_BGP_AutoReload(t *testing.T) {
	tempDir := t.TempDir()
	mrtPath := filepath.Join(tempDir, "reload_test.mrt")

	// Write initial route
	f, err := os.Create(mrtPath)
	if err != nil {
		t.Fatal(err)
	}
	initialRoutes := []bgpmrt.BGPRecord{
		{Prefix: "10.0.0.0/8", OriginASN: "65100", ASPath: "65100"},
	}
	_ = bgpmrt.WriteSampleMRT(f, initialRoutes)
	f.Close()

	cfg := config.GetFakeConfigTransformers()
	cfg.BGP.Enable = true
	cfg.BGP.MrtFile = mrtPath
	cfg.BGP.MrtCheckUpdateInterval = 1 // Check every 1 second

	bgpTrans := NewDNSBGPTransform(cfg, logger.New(false), "test-reload", 0, nil)
	if err := bgpTrans.Open(); err != nil {
		t.Fatalf("failed to open BGPTransform: %v", err)
	}
	defer bgpTrans.Close()

	rec := bgpTrans.Lookup(net.ParseIP("10.1.2.3"))
	if rec == nil || rec.OriginASN != "65100" {
		t.Fatalf("initial lookup failed: %+v", rec)
	}

	// Update file with new routes
	time.Sleep(1100 * time.Millisecond)
	f2, err := os.Create(mrtPath)
	if err != nil {
		t.Fatal(err)
	}
	updatedRoutes := []bgpmrt.BGPRecord{
		{Prefix: "10.0.0.0/8", OriginASN: "65200", ASPath: "65200"},
	}
	_ = bgpmrt.WriteSampleMRT(f2, updatedRoutes)
	f2.Close()

	// Wait for reload loop to detect modification
	time.Sleep(1500 * time.Millisecond)

	recUpdated := bgpTrans.Lookup(net.ParseIP("10.1.2.3"))
	if recUpdated == nil || recUpdated.OriginASN != "65200" {
		t.Errorf("expected reloaded OriginASN 65200, got %+v", recUpdated)
	}
}
