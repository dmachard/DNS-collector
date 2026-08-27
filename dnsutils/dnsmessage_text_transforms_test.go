package dnsutils

import (
	"bytes"
	"strings"
	"testing"

	"github.com/dmachard/go-dnscollector/v2/pkg/config"
)

func TestDnsMessage_TextFormat_Directives_PublicSuffix(t *testing.T) {
	cfg := config.GetDefaultConfig()

	testcases := []struct {
		name     string
		format   string
		dm       DNSMessage
		expected string
	}{
		{
			name:     "undefined",
			format:   "publicsuffix-tld",
			dm:       DNSMessage{},
			expected: "-",
		},
		{
			name:     "default",
			format:   "publicsuffix-tld publicsuffix-etld+1",
			dm:       DNSMessage{PublicSuffix: &TransformPublicSuffix{QnamePublicSuffix: "com", QnameEffectiveTLDPlusOne: "google.com"}},
			expected: "com google.com",
		},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			var buf bytes.Buffer
			err := tc.dm.ToTextLine(strings.Fields(tc.format), cfg.Global.TextFormatDelimiter, cfg.Global.TextFormatBoundary, &buf)
			if err != nil {
				t.Fatalf("failed to generate text line: %v", err)
			}

			line := buf.String()

			if line != tc.expected {
				t.Errorf("Want: %s, got: %s", tc.expected, line)
			}
		})
	}
}

func TestDnsMessage_TextFormat_Directives_Geo(t *testing.T) {
	cfg := config.GetDefaultConfig()

	testcases := []struct {
		name     string
		format   string
		dm       DNSMessage
		expected string
	}{
		{
			name:     "undefined",
			format:   "geoip-continent",
			dm:       DNSMessage{},
			expected: "-",
		},
		{
			name:   "default",
			format: "geoip-continent geoip-country geoip-city geoip-as-number geoip-as-owner geoip-lat geoip-lon",
			dm: DNSMessage{Geo: &TransformDNSGeo{City: "Paris", Continent: "Europe",
				CountryIsoCode: "FR", AutonomousSystemNumber: "AS1", AutonomousSystemOrg: "Google", Latitude: 48.85836, Longitude: 2.29448}},
			expected: "Europe FR Paris AS1 Google 48.85836 2.29448",
		},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			var buf bytes.Buffer
			err := tc.dm.ToTextLine(strings.Fields(tc.format), cfg.Global.TextFormatDelimiter, cfg.Global.TextFormatBoundary, &buf)
			if err != nil {
				t.Fatalf("failed to generate text line: %v", err)
			}

			line := buf.String()
			if line != tc.expected {
				t.Errorf("Want: %s, got: %s", tc.expected, line)
			}
		})
	}
}

func TestDnsMessage_TextFormat_Directives_ATags(t *testing.T) {
	cfg := config.GetDefaultConfig()

	testcases := []struct {
		name     string
		format   string
		dm       DNSMessage
		expected string
	}{
		{
			name:     "undefined",
			format:   "atags",
			dm:       DNSMessage{},
			expected: "-",
		},
		{
			name:     "empty_attributes",
			format:   "atags",
			dm:       DNSMessage{ATags: &TransformATags{}},
			expected: "-",
		},
		{
			name:     "tags_all",
			format:   "atags",
			dm:       DNSMessage{ATags: &TransformATags{Tags: []string{"tag1", "tag2"}}},
			expected: "tag1,tag2",
		},
		{
			name:     "tags_index",
			format:   "atags:1",
			dm:       DNSMessage{ATags: &TransformATags{Tags: []string{"tag1", "tag2"}}},
			expected: "tag2",
		},
		{
			name:     "tags_invalid_index",
			format:   "atags:3",
			dm:       DNSMessage{ATags: &TransformATags{Tags: []string{"tag1", "tag2"}}},
			expected: "-",
		},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			var buf bytes.Buffer
			err := tc.dm.ToTextLine(strings.Fields(tc.format), cfg.Global.TextFormatDelimiter, cfg.Global.TextFormatBoundary, &buf)
			if err != nil {
				t.Fatalf("failed to generate text line: %v", err)
			}

			line := buf.String()
			if line != tc.expected {
				t.Errorf("Want: %s, got: %s", tc.expected, line)
			}
		})
	}
}

func TestDnsMessage_TextFormat_Directives_Suspicious(t *testing.T) {
	cfg := config.GetDefaultConfig()

	testcases := []struct {
		name     string
		format   string
		dm       DNSMessage
		expected string
	}{
		{
			name:     "undefined",
			format:   "suspicious-score",
			dm:       DNSMessage{},
			expected: "-",
		},
		{
			name:     "default",
			format:   "suspicious-score",
			dm:       DNSMessage{Suspicious: &TransformSuspicious{Score: 4.0}},
			expected: "4",
		},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			var buf bytes.Buffer
			err := tc.dm.ToTextLine(strings.Fields(tc.format), cfg.Global.TextFormatDelimiter, cfg.Global.TextFormatBoundary, &buf)
			if err != nil {
				t.Fatalf("failed to generate text line: %v", err)
			}

			line := buf.String()
			if line != tc.expected {
				t.Errorf("Want: %s, got: %s", tc.expected, line)
			}
		})
	}
}

func TestDnsMessage_TextFormat_Directives_Reducer(t *testing.T) {
	cfg := config.GetDefaultConfig()

	testcases := []struct {
		name     string
		format   string
		dm       DNSMessage
		expected string
	}{
		{
			name:     "undefined",
			format:   "reducer-occurrences",
			dm:       DNSMessage{},
			expected: "-",
		},
		{
			name:     "default",
			format:   "reducer-occurrences",
			dm:       DNSMessage{Reducer: &TransformReducer{Occurrences: 1}},
			expected: "1",
		},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			var buf bytes.Buffer
			err := tc.dm.ToTextLine(strings.Fields(tc.format), cfg.Global.TextFormatDelimiter, cfg.Global.TextFormatBoundary, &buf)
			if err != nil {
				t.Fatalf("failed to generate text line: %v", err)
			}

			line := buf.String()
			if line != tc.expected {
				t.Errorf("Want: %s, got: %s", tc.expected, line)
			}
		})
	}
}

func TestDnsMessage_TextFormat_Directives_Extracted(t *testing.T) {
	cfg := config.GetDefaultConfig()

	testcases := []struct {
		name     string
		format   string
		dm       DNSMessage
		expected string
	}{
		{
			name:     "undefined",
			format:   "extracted-dns-payload",
			dm:       DNSMessage{},
			expected: "-",
		},
		{
			name:   "default",
			format: "extracted-dns-payload",
			dm: DNSMessage{Extracted: &TransformExtracted{}, DNS: DNS{Payload: []byte{
				0x9e, 0x84, 0x01, 0x20, 0x00, 0x03, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00,
				// query 1
				0x01, 0x61, 0x00,
				// type A, class IN
				0x00, 0x01, 0x00, 0x01,
				// query 2
				0x01, 0x62, 0x00,
				// type A, class IN
				0x00, 0x01, 0x00, 0x01,
				// query 3
				0x01, 0x63, 0x00,
				// type AAAA, class IN
				0x00, 0x1c, 0x00, 0x01,
			}}},
			expected: "noQBIAADAAAAAAAAAWEAAAEAAQFiAAABAAEBYwAAHAAB",
		},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			var buf bytes.Buffer
			err := tc.dm.ToTextLine(strings.Fields(tc.format), cfg.Global.TextFormatDelimiter, cfg.Global.TextFormatBoundary, &buf)
			if err != nil {
				t.Fatalf("failed to generate text line: %v", err)
			}

			line := buf.String()
			if line != tc.expected {
				t.Errorf("Want: %s, got: %s", tc.expected, line)
			}
		})
	}
}

func TestDnsMessage_TextFormat_Directives_Filtering(t *testing.T) {
	cfg := config.GetDefaultConfig()

	testcases := []struct {
		name     string
		format   string
		dm       DNSMessage
		expected string
	}{
		{
			name:     "undefined",
			format:   "filtering-sample-rate",
			dm:       DNSMessage{},
			expected: "-",
		},
		{
			name:     "default",
			format:   "filtering-sample-rate",
			dm:       DNSMessage{Filtering: &TransformFiltering{SampleRate: 22}},
			expected: "22",
		},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			var buf bytes.Buffer
			err := tc.dm.ToTextLine(strings.Fields(tc.format), cfg.Global.TextFormatDelimiter, cfg.Global.TextFormatBoundary, &buf)
			if err != nil {
				t.Fatalf("failed to generate text line: %v", err)
			}

			line := buf.String()
			if line != tc.expected {
				t.Errorf("Want: %s, got: %s", tc.expected, line)
			}
		})
	}
}

func Test_TransformTextBGP(t *testing.T) {
	cfg := config.GetDefaultConfig()

	testcases := []struct {
		name     string
		format   string
		dm       DNSMessage
		expected string
	}{
		{
			name:     "undefined",
			format:   "bgp-origin-asn bgp-as-path bgp-prefix",
			dm:       DNSMessage{},
			expected: "- - -",
		},
		{
			name:   "default",
			format: "bgp-origin-asn bgp-as-path bgp-prefix",
			dm: DNSMessage{BGP: &TransformBGP{
				OriginASN: "19281",
				ASPath:    "174 2914 19281",
				Prefix:    "149.112.112.0/24",
			}},
			expected: "19281 174 2914 19281 149.112.112.0/24",
		},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			var buf bytes.Buffer
			err := tc.dm.ToTextLine(strings.Fields(tc.format), cfg.Global.TextFormatDelimiter, cfg.Global.TextFormatBoundary, &buf)
			if err != nil {
				t.Fatalf("failed to generate text line: %v", err)
			}

			line := buf.String()
			if line != tc.expected {
				t.Errorf("Want: %s, got: %s", tc.expected, line)
			}
		})
	}
}
