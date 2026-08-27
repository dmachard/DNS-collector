package transformers

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"testing"

	"github.com/dmachard/go-dnscollector/v3/dnsutils"
	"github.com/dmachard/go-dnscollector/v3/pkg/bgpmrt"
	"github.com/dmachard/go-dnscollector/v3/pkg/config"
	"github.com/dmachard/go-logger"
)

func Benchmark_BGPRadixTree_Lookup(b *testing.B) {
	tempDir := b.TempDir()
	mrtPath := filepath.Join(tempDir, "bench_table.mrt")
	f, err := os.Create(mrtPath)
	if err != nil {
		b.Fatal(err)
	}

	// Generate 1000 simulated BGP routes
	var routes []bgpmrt.BGPRecord
	for i := 0; i < 250; i++ {
		routes = append(routes, bgpmrt.BGPRecord{
			Prefix:    fmt.Sprintf("10.%d.0.0/16", i),
			OriginASN: fmt.Sprintf("%d", 60000+i),
			ASPath:    fmt.Sprintf("174 2914 %d", 60000+i),
		})
		routes = append(routes, bgpmrt.BGPRecord{
			Prefix:    fmt.Sprintf("10.%d.128.0/24", i),
			OriginASN: fmt.Sprintf("%d", 70000+i),
			ASPath:    fmt.Sprintf("174 3356 %d", 70000+i),
		})
	}
	_ = bgpmrt.WriteSampleMRT(f, routes)
	f.Close()

	parser := bgpmrt.NewMRTParser()
	tree, err := parser.ParseFile(mrtPath)
	if err != nil {
		b.Fatal(err)
	}

	testIP := net.ParseIP("10.50.128.1")

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		rec := tree.Lookup(testIP)
		if rec == nil {
			b.Fatal("lookup failed")
		}
	}
}

func Benchmark_BGPTransform_ProcessMessage(b *testing.B) {
	tempDir := b.TempDir()
	mrtPath := filepath.Join(tempDir, "bench_table.mrt")
	f, err := os.Create(mrtPath)
	if err != nil {
		b.Fatal(err)
	}

	routes := []bgpmrt.BGPRecord{
		{Prefix: "192.0.2.0/24", OriginASN: "65001", ASPath: "174 2914 65001"},
		{Prefix: "192.0.2.128/25", OriginASN: "65002", ASPath: "174 3356 65002"},
	}
	_ = bgpmrt.WriteSampleMRT(f, routes)
	f.Close()

	cfg := config.GetFakeConfigTransformers()
	cfg.BGP.Enable = true
	cfg.BGP.MrtFile = mrtPath
	cfg.BGP.OriginASN = true
	cfg.BGP.ASPath = true
	cfg.BGP.Prefix = true

	outChan := make(chan *dnsutils.DNSMessageBatch, 100)
	transforms := NewTransforms(cfg, logger.New(false), "bench-bgp", []chan *dnsutils.DNSMessageBatch{outChan}, 0)

	dm := dnsutils.AcquireDNSMessage()
	dm.Init()
	dm.NetworkInfo.SetQueryIPBytes(net.ParseIP("192.0.2.130"))

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		_, _ = transforms.ProcessMessage(dm)
	}
}
