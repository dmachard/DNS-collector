package dnsutils

import (
	"bytes"
	"strings"
	"testing"

	"github.com/dmachard/go-dnscollector/v3/pkg/config"
)

// Tests for TEXT format
func TestDnsMessage_TextFormat_ToString(t *testing.T) {

	cfg := config.GetDefaultConfig()

	testcases := []struct {
		name      string
		delimiter string
		boundary  string
		format    string
		qname     string
		identity  string
		expected  string
	}{
		{
			name:      "default",
			delimiter: cfg.Global.TextFormatDelimiter,
			boundary:  cfg.Global.TextFormatBoundary,
			format:    cfg.Global.TextFormat,
			qname:     "dnscollector.fr",
			identity:  "collector",
			expected:  "- collector CLIENT_QUERY NOERROR 1.2.3.4 1234 IPv4 UDP 0b dnscollector.fr A -",
		},
		{
			name:      "custom_delimiter",
			delimiter: ";",
			boundary:  cfg.Global.TextFormatBoundary,
			format:    cfg.Global.TextFormat,
			qname:     "dnscollector.fr",
			identity:  "collector",
			expected:  "-;collector;CLIENT_QUERY;NOERROR;1.2.3.4;1234;IPv4;UDP;0b;dnscollector.fr;A;-",
		},
		{
			name:      "empty_delimiter",
			delimiter: "",
			boundary:  cfg.Global.TextFormatBoundary,
			format:    cfg.Global.TextFormat,
			qname:     "dnscollector.fr",
			identity:  "collector",
			expected:  "-collectorCLIENT_QUERYNOERROR1.2.3.41234IPv4UDP0bdnscollector.frA-",
		},
		{
			name:      "qname_quote",
			delimiter: cfg.Global.TextFormatDelimiter,
			boundary:  cfg.Global.TextFormatBoundary,
			format:    cfg.Global.TextFormat,
			qname:     "dns collector.fr",
			identity:  "collector",
			expected:  "- collector CLIENT_QUERY NOERROR 1.2.3.4 1234 IPv4 UDP 0b \"dns collector.fr\" A -",
		},
		{
			name:      "default_boundary",
			delimiter: cfg.Global.TextFormatDelimiter,
			boundary:  cfg.Global.TextFormatBoundary,
			format:    cfg.Global.TextFormat,
			qname:     "dns\"coll tor\".fr",
			identity:  "collector",
			expected:  "- collector CLIENT_QUERY NOERROR 1.2.3.4 1234 IPv4 UDP 0b \"dns\\\"coll tor\\\".fr\" A -",
		},
		{
			name:      "custom_boundary",
			delimiter: cfg.Global.TextFormatDelimiter,
			boundary:  "!",
			format:    cfg.Global.TextFormat,
			qname:     "dnscoll tor.fr",
			identity:  "collector",
			expected:  "- collector CLIENT_QUERY NOERROR 1.2.3.4 1234 IPv4 UDP 0b !dnscoll tor.fr! A -",
		},
		{
			name:      "custom_text",
			delimiter: cfg.Global.TextFormatDelimiter,
			boundary:  cfg.Global.TextFormatBoundary,
			format:    "qname {IN} qtype",
			qname:     "dnscollector.fr",
			identity:  "",
			expected:  "dnscollector.fr IN A",
		},
		{
			name:      "quote_dnstap_version",
			delimiter: cfg.Global.TextFormatDelimiter,
			boundary:  cfg.Global.TextFormatBoundary,
			format:    "identity version qname",
			qname:     "dnscollector.fr",
			identity:  "collector",
			expected:  "collector \"dnscollector 1.0.0\" dnscollector.fr",
		},
		{
			name:      "quote_dnstap_identity",
			delimiter: cfg.Global.TextFormatDelimiter,
			boundary:  cfg.Global.TextFormatBoundary,
			format:    "identity qname",
			qname:     "dnscollector.fr",
			identity:  "dns collector",
			expected:  "\"dns collector\" dnscollector.fr",
		},
		{
			name:      "quote_dnstap_peername",
			delimiter: cfg.Global.TextFormatDelimiter,
			boundary:  cfg.Global.TextFormatBoundary,
			format:    "peer-name qname",
			qname:     "dnscollector.fr",
			identity:  "",
			expected:  "\"localhost (127.0.0.1)\" dnscollector.fr",
		},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			dm := GetFakeDNSMessage()

			dm.DNS.Qname = tc.qname
			dm.DNSTap.Identity = tc.identity

			var buf bytes.Buffer
			err := dm.ToTextLine(strings.Fields(tc.format), tc.delimiter, tc.boundary, &buf)
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

func TestDnsMessage_TextFormat_DefaultDirectives(t *testing.T) {
	cfg := config.GetDefaultConfig()

	testcases := []struct {
		name     string
		format   string
		dm       DNSMessage
		expected string
	}{
		{
			format:   "timestamp-rfc3339ns timestamp",
			dm:       DNSMessage{DNSTap: DNSTap{TimestampRFC3339: "2023-04-22T09:17:02.906922231Z"}},
			expected: "2023-04-22T09:17:02.906922231Z 2023-04-22T09:17:02.906922231Z",
		},
		{
			format:   "timestamp-unixns timestamp-unixus timestamp-unixms",
			dm:       DNSMessage{DNSTap: DNSTap{Timestamp: 1682152174001850960}},
			expected: "1682152174001850960 1682152174001850 1682152174001",
		},
		{
			format:   "latency",
			dm:       DNSMessage{DNSTap: DNSTap{Latency: 0.00001}},
			expected: "0.000010000",
		},
		{
			format:   "latency_ms",
			dm:       DNSMessage{DNSTap: DNSTap{LatencyMs: 20}},
			expected: "20",
		},
		{
			format:   "qname qtype opcode",
			dm:       DNSMessage{DNS: DNS{Qname: "dnscollector.fr", Qtype: "AAAA", Opcode: 42}},
			expected: "dnscollector.fr AAAA 42",
		},
		{
			format:   "qclass",
			dm:       DNSMessage{DNS: DNS{Qclass: "CH"}},
			expected: "CH",
		},
		{
			format:   "operation",
			dm:       DNSMessage{DNSTap: DNSTap{Operation: "CLIENT_QUERY"}},
			expected: "CLIENT_QUERY",
		},
		{
			format:   "family protocol",
			dm:       DNSMessage{NetworkInfo: DNSNetInfo{Family: "IPv4", Protocol: "UDP"}},
			expected: "IPv4 UDP",
		},
		{
			format:   "length",
			dm:       DNSMessage{DNS: DNS{Length: 42}},
			expected: "42",
		},
		{
			format:   "length-unit",
			dm:       DNSMessage{DNS: DNS{Length: 42}},
			expected: "42b",
		},
		{
			format:   "malformed",
			dm:       DNSMessage{DNS: DNS{MalformedPacket: true}},
			expected: "PKTERR",
		},
		{
			format:   "tc aa ra ad",
			dm:       DNSMessage{DNS: DNS{Flags: DNSFlags{TC: true, AA: true, RA: true, AD: true}}},
			expected: "TC AA RA AD",
		},
		{
			format:   "rd",
			dm:       DNSMessage{DNS: DNS{Flags: DNSFlags{RD: true}}},
			expected: "RD",
		},
		{
			format:   "tc aa ra ad rd",
			dm:       DNSMessage{DNS: DNS{Flags: DNSFlags{TC: false, AA: false, RA: false, AD: false, RD: false}}},
			expected: "- - - - -",
		},
		{
			format:   "df tr",
			dm:       DNSMessage{NetworkInfo: DNSNetInfo{IPDefragmented: true, TCPReassembled: true}},
			expected: "DF TR",
		},
		{
			format:   "queryip queryport",
			dm:       DNSMessage{NetworkInfo: DNSNetInfo{QueryIP: "1.2.3.4", QueryPort: "4200"}},
			expected: "1.2.3.4 4200",
		},
		{
			format:   "responseip responseport",
			dm:       DNSMessage{NetworkInfo: DNSNetInfo{ResponseIP: "1.2.3.4", ResponsePort: "4200"}},
			expected: "1.2.3.4 4200",
		},
		{
			format: "policy-rule policy-type policy-action policy-match policy-value",
			dm: DNSMessage{DNSTap: DNSTap{PolicyRule: "rule", PolicyType: "type",
				PolicyAction: "action", PolicyMatch: "match",
				PolicyValue: "value"}},
			expected: "rule type action match value",
		},
		{
			format:   "peer-name",
			dm:       DNSMessage{DNSTap: DNSTap{PeerName: "testpeer"}},
			expected: "testpeer",
		},
		{
			format:   "query-zone",
			dm:       DNSMessage{DNSTap: DNSTap{QueryZone: "queryzone.test"}},
			expected: "queryzone.test",
		},
		{
			format:   "qdcount",
			dm:       DNSMessage{DNS: DNS{QdCount: 1}},
			expected: "1",
		},
		{
			format:   "ancount nscount arcount",
			dm:       DNSMessage{DNS: DNS{AnCount: 1, ArCount: 2, NsCount: 3}},
			expected: "1 3 2",
		},
		{
			format: "answer-ip answer-a",
			dm: DNSMessage{
				DNS: DNS{
					DNSRRs: DNSRRs{
						Answers: []DNSAnswer{
							{
								Name:      "dnscollector.fr",
								Rdatatype: "A",
								Class:     "IN",
								Rdata:     "127.0.0.1",
							},
						},
					},
				},
			},
			expected: "127.0.0.1 127.0.0.1",
		},
		{
			format: "answer-aaaa",
			dm: DNSMessage{
				DNS: DNS{
					DNSRRs: DNSRRs{
						Answers: []DNSAnswer{
							{
								Name:      "dnscollector.fr",
								Rdatatype: Rdatatypes[28],
								Class:     "IN",
								Rdata:     "::1",
							},
						},
					},
				},
			},
			expected: "::1",
		},
		{
			format: "answer-ips",
			dm: DNSMessage{
				DNS: DNS{
					DNSRRs: DNSRRs{
						Answers: []DNSAnswer{
							{
								Name:      "dnscollector.fr",
								Rdatatype: "A",
								Class:     "IN",
								Rdata:     "127.0.0.1",
							},
							{
								Name:      "dnscollector.fr",
								Rdatatype: "A",
								Class:     "IN",
								Rdata:     "127.0.0.2",
							},
						},
					},
				},
			},
			expected: "127.0.0.1;127.0.0.2",
		},
		{
			format: "rdatatype",
			dm: DNSMessage{
				DNS: DNS{
					DNSRRs: DNSRRs{
						Answers: []DNSAnswer{
							{
								Name:      "dnscollector.fr",
								Rdatatype: "A",
								Class:     "IN",
								Rdata:     "127.0.0.1",
							},
							{
								Name:      "dnscollector.fr",
								Rdatatype: "A",
								Class:     "IN",
								Rdata:     "127.0.0.2",
							},
						},
					},
				},
			},
			expected: "A",
		},
		{
			format: "rdatatypes",
			dm: DNSMessage{
				DNS: DNS{
					DNSRRs: DNSRRs{
						Answers: []DNSAnswer{
							{
								Name:      "dnscollector.fr",
								Rdatatype: "A",
								Class:     "IN",
								Rdata:     "127.0.0.1",
							},
							{
								Name:      "dnscollector.fr",
								Rdatatype: "A",
								Class:     "IN",
								Rdata:     "127.0.0.2",
							},
						},
					},
				},
			},
			expected: "A;A",
		},
		{
			format:   "http-protocol",
			dm:       DNSMessage{DNSTap: DNSTap{HttpProtocol: "HTTP3"}},
			expected: "HTTP3",
		},
	}

	for _, tc := range testcases {
		t.Run(tc.format, func(t *testing.T) {
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

func TestDnsMessage_TextFormat_InvalidDirectives(t *testing.T) {
	testcases := []struct {
		name   string
		dm     DNSMessage
		format string
	}{
		{
			name:   "default",
			dm:     DNSMessage{},
			format: "invalid",
		},
		{
			name:   "publicsuffix",
			dm:     DNSMessage{PublicSuffix: &TransformPublicSuffix{}},
			format: "publicsuffix-invalid",
		},
		{
			name:   "powerdns",
			dm:     DNSMessage{PowerDNS: &CollectorPowerDNS{}},
			format: "powerdns-invalid",
		},
		{
			name:   "geoip",
			dm:     DNSMessage{Geo: &TransformDNSGeo{}},
			format: "geoip-invalid",
		},
		{
			name:   "suspicious",
			dm:     DNSMessage{Suspicious: &TransformSuspicious{}},
			format: "suspicious-invalid",
		},
		{
			name:   "extracted",
			dm:     DNSMessage{Extracted: &TransformExtracted{}},
			format: "extracted-invalid",
		},
		{
			name:   "filtering",
			dm:     DNSMessage{Filtering: &TransformFiltering{}},
			format: "filtering-invalid",
		},
		{
			name:   "reducer",
			dm:     DNSMessage{Reducer: &TransformReducer{}},
			format: "reducer-invalid",
		},
		{
			name:   "ml",
			dm:     DNSMessage{MachineLearning: &TransformML{}},
			format: "ml-invalid",
		},
	}
	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			var buf bytes.Buffer
			err := tc.dm.ToTextLine(strings.Fields(tc.format), " ", "", &buf)
			if err == nil {
				t.Errorf("Want err, got nil")
			} else if err.Error() != ErrorUnexpectedDirective+tc.format {
				t.Errorf("Unexpected error: %s", err.Error())
			}
		})
	}
}
