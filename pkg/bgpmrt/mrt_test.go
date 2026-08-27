package bgpmrt

import (
	"net"
	"os"
	"path/filepath"
	"testing"
)

func createSampleMRTFile(t *testing.T, dir string) string {
	t.Helper()
	mrtPath := filepath.Join(dir, "test_table.mrt")
	f, err := os.Create(mrtPath)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	routes := []BGPRecord{
		{Prefix: "192.0.2.0/24", OriginASN: "65001", ASPath: "100 200 65001"},
		{Prefix: "192.0.2.128/25", OriginASN: "65002", ASPath: "100 300 65002"},
		{Prefix: "198.51.100.0/24", OriginASN: "65003", ASPath: "400 65003"},
		{Prefix: "2001:db8::/32", OriginASN: "65010", ASPath: "1000 65010"},
		{Prefix: "2001:db8:1::/48", OriginASN: "65011", ASPath: "1000 2000 65011"},
	}

	if err := WriteSampleMRT(f, routes); err != nil {
		t.Fatal(err)
	}
	return mrtPath
}

func Test_BGP_MRT_ParseAndLookup(t *testing.T) {
	tempDir := t.TempDir()
	mrtPath := createSampleMRTFile(t, tempDir)

	parser := NewMRTParser()
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
