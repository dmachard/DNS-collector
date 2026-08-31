package dnsutils

import (
	"os"
	"path/filepath"
	"testing"
)

func TestCompileMatcher_NilAndEmpty(t *testing.T) {
	var nilMatcher *CompiledMatcher
	dm := &DNSMessage{}
	if nilMatcher.Match(dm) {
		t.Errorf("nil matcher should return false")
	}

	emptyMatcher, err := CompileMatcher(nil)
	if err != nil {
		t.Fatalf("unexpected error for nil map: %v", err)
	}
	if emptyMatcher.Match(dm) {
		t.Errorf("empty matcher should return false")
	}

	emptyMapMatcher, err := CompileMatcher(map[string]interface{}{})
	if err != nil {
		t.Fatalf("unexpected error for empty map: %v", err)
	}
	if emptyMapMatcher.Match(dm) {
		t.Errorf("empty map matcher should return false")
	}
}

func TestCompileMatcher_StringFieldsAndRegex(t *testing.T) {
	dm := &DNSMessage{
		DNS: DNS{
			Qname:  "api.example.com",
			Qtype:  "AAAA",
			Rcode:  "NOERROR",
			Length: 128,
			ID:     42,
			Opcode: 0,
		},
		NetworkInfo: DNSNetInfo{
			Family:       "INET6",
			Protocol:     "TCP",
			QueryIP:      "2001:db8::1",
			ResponseIP:   "2001:db8::2",
			QueryPort:    "54321",
			ResponsePort: "53",
		},
		DNSTap: DNSTap{
			Operation: "CLIENT_QUERY",
			Identity:  "dns-probe-1",
		},
	}

	// Test exact match
	m1, err := CompileMatcher(map[string]interface{}{
		"dns.qname":             "api.example.com",
		"dns.qtype":             "AAAA",
		"dns.rcode":             "NOERROR",
		"network.family":        "INET6",
		"network.protocol":      "TCP",
		"network.query-ip":      "2001:db8::1",
		"network.response-ip":   "2001:db8::2",
		"network.query-port":    "54321",
		"network.response-port": "53",
		"dnstap.operation":      "CLIENT_QUERY",
		"dnstap.identity":       "dns-probe-1",
	})
	if err != nil {
		t.Fatalf("CompileMatcher error: %v", err)
	}
	if !m1.Match(dm) {
		t.Errorf("expected m1 to match dm")
	}

	// Test regex match
	mRegex, err := CompileMatcher(map[string]interface{}{
		"dns.qname": `^.*\.example\.com$`,
	})
	if err != nil {
		t.Fatalf("CompileMatcher regex error: %v", err)
	}
	if !mRegex.Match(dm) {
		t.Errorf("expected mRegex to match dm")
	}

	// Test invalid regex
	_, err = CompileMatcher(map[string]interface{}{
		"dns.qname": `[invalid(regex`,
	})
	if err == nil {
		t.Errorf("expected error for invalid regex pattern")
	}
}

func TestCompileMatcher_StringListAndRegexList(t *testing.T) {
	dm := &DNSMessage{
		DNS: DNS{Qname: "mail.test.org"},
	}

	matcher, err := CompileMatcher(map[string]interface{}{
		"dns.qname": []interface{}{"other.domain.com", `^mail\..*\.org$`},
	})
	if err != nil {
		t.Fatalf("CompileMatcher error: %v", err)
	}
	if !matcher.Match(dm) {
		t.Errorf("expected matcher to match via regex list item")
	}

	dmNoMatch := &DNSMessage{
		DNS: DNS{Qname: "ftp.test.org"},
	}
	if matcher.Match(dmNoMatch) {
		t.Errorf("expected matcher to not match ftp.test.org")
	}
}

func TestCompileMatcher_IntFieldsAndOperators(t *testing.T) {
	dm := &DNSMessage{
		DNS: DNS{
			ID:     100,
			Length: 512,
			Opcode: 2,
		},
	}

	// Greater than & lower than
	mInt, err := CompileMatcher(map[string]interface{}{
		"dns.id":     100,
		"dns.length": map[string]interface{}{MatchingOpGreaterThan: 500},
		"dns.opcode": map[string]interface{}{MatchingOpLowerThan: 5},
	})
	if err != nil {
		t.Fatalf("CompileMatcher error: %v", err)
	}
	if !mInt.Match(dm) {
		t.Errorf("expected mInt to match dm")
	}

	// Greater than failure
	mIntFail, err := CompileMatcher(map[string]interface{}{
		"dns.length": map[string]interface{}{MatchingOpGreaterThan: 1000},
	})
	if err != nil {
		t.Fatalf("CompileMatcher error: %v", err)
	}
	if mIntFail.Match(dm) {
		t.Errorf("expected mIntFail to not match dm")
	}

	// String integer representation
	mStrInt, err := CompileMatcher(map[string]interface{}{
		"dns.id": "100",
	})
	if err != nil {
		t.Fatalf("CompileMatcher error: %v", err)
	}
	if !mStrInt.Match(dm) {
		t.Errorf("expected string integer representation to match")
	}

	// Invalid int string
	_, err = CompileMatcher(map[string]interface{}{
		"dns.id": "not_an_int",
	})
	if err == nil {
		t.Errorf("expected error for invalid int string")
	}
}

func TestCompileMatcher_BoolFields(t *testing.T) {
	dm := &DNSMessage{
		DNS: DNS{
			Flags: DNSFlags{
				QR: true,
				AA: false,
				TC: true,
				RD: false,
				RA: true,
				AD: false,
				CD: true,
			},
		},
		NetworkInfo: DNSNetInfo{
			IPDefragmented: true,
			TCPReassembled: false,
		},
	}

	mBool, err := CompileMatcher(map[string]interface{}{
		"dns.flags.qr":            true,
		"dns.flags.aa":            "false", // test string bool parsing
		"dns.flags.tc":            true,
		"dns.flags.rd":            false,
		"dns.flags.ra":            "true",
		"dns.flags.ad":            false,
		"dns.flags.cd":            true,
		"network.ip-defragmented": true,
		"network.tcp-reassembled": false,
	})
	if err != nil {
		t.Fatalf("CompileMatcher error: %v", err)
	}
	if !mBool.Match(dm) {
		t.Errorf("expected mBool to match dm")
	}

	// Invalid bool string
	_, err = CompileMatcher(map[string]interface{}{
		"dns.flags.qr": "not_a_bool",
	})
	if err == nil {
		t.Errorf("expected error for invalid bool string")
	}
}

func TestCompileMatcher_GeoFields(t *testing.T) {
	dm := &DNSMessage{
		Geo: &TransformDNSGeo{
			CountryIsoCode:         "FR",
			City:                   "Paris",
			AutonomousSystemNumber: "AS12345",
			AutonomousSystemOrg:    "ISP-ORG",
		},
	}

	mGeo, err := CompileMatcher(map[string]interface{}{
		"geo.country-iso": "FR",
		"geo.city":        "Paris",
		"geo.as-number":   "AS12345",
		"geo.as-org":      "ISP-ORG",
	})
	if err != nil {
		t.Fatalf("CompileMatcher error: %v", err)
	}
	if !mGeo.Match(dm) {
		t.Errorf("expected mGeo to match dm")
	}

	// Test with nil Geo
	dmNilGeo := &DNSMessage{}
	if mGeo.Match(dmNilGeo) {
		t.Errorf("expected mGeo to not match dm with nil Geo")
	}
}

func TestCompileMatcher_FileSource(t *testing.T) {
	tempDir := t.TempDir()

	// 1. Plain text file matching
	listPath := filepath.Join(tempDir, "domains.txt")
	content := "# comment\nexample.com\ngoogle.com\n\ncloudflare.com\n"
	if err := os.WriteFile(listPath, []byte(content), 0644); err != nil {
		t.Fatalf("failed to write test file: %v", err)
	}

	mFile, err := CompileMatcher(map[string]interface{}{
		"dns.qname": map[string]interface{}{
			MatchingOpSource: "file://" + listPath,
		},
	})
	if err != nil {
		t.Fatalf("CompileMatcher error: %v", err)
	}

	dm1 := &DNSMessage{DNS: DNS{Qname: "example.com"}}
	dm2 := &DNSMessage{DNS: DNS{Qname: "unknown.com"}}

	if !mFile.Match(dm1) {
		t.Errorf("expected mFile to match example.com")
	}
	if mFile.Match(dm2) {
		t.Errorf("expected mFile to not match unknown.com")
	}

	// 2. Regex list file matching
	regexListPath := filepath.Join(tempDir, "regex.txt")
	regexContent := "^.*\\.internal$\n^vpn\\..*$\n"
	if err := os.WriteFile(regexListPath, []byte(regexContent), 0644); err != nil {
		t.Fatalf("failed to write test file: %v", err)
	}

	mRegexFile, err := CompileMatcher(map[string]interface{}{
		"dns.qname": map[string]interface{}{
			MatchingOpSource:     "file://" + regexListPath,
			MatchingOpSourceKind: MatchingKindRegexp,
		},
	})
	if err != nil {
		t.Fatalf("CompileMatcher error: %v", err)
	}

	dmRegex1 := &DNSMessage{DNS: DNS{Qname: "server.internal"}}
	dmRegex2 := &DNSMessage{DNS: DNS{Qname: "vpn.corp.com"}}
	dmRegex3 := &DNSMessage{DNS: DNS{Qname: "public.com"}}

	if !mRegexFile.Match(dmRegex1) {
		t.Errorf("expected mRegexFile to match server.internal")
	}
	if !mRegexFile.Match(dmRegex2) {
		t.Errorf("expected mRegexFile to match vpn.corp.com")
	}
	if mRegexFile.Match(dmRegex3) {
		t.Errorf("expected mRegexFile to not match public.com")
	}
}

func TestCompileMatcher_FallbackDynamic(t *testing.T) {
	dm := &DNSMessage{
		DNSTap: DNSTap{
			Extra: "custom_extra_value",
		},
	}

	mFallback, err := CompileMatcher(map[string]interface{}{
		"dnstap.extra": "custom_extra_value",
	})
	if err != nil {
		t.Fatalf("CompileMatcher error: %v", err)
	}
	if !mFallback.Match(dm) {
		t.Errorf("expected dynamic fallback to match dnstap.extra")
	}
}
