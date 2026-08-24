package dnsutils

import (
	"bytes"
	"strings"
	"testing"

	"github.com/dmachard/go-dnscollector/v2/pkgconfig"
)

func TestDnsMessage_TextFormat_Directives_OpenTelemetry(t *testing.T) {
	config := pkgconfig.GetDefaultConfig()

	testcases := []struct {
		name     string
		format   string
		dm       DNSMessage
		expected string
	}{
		{
			name:     "undefined",
			format:   "otel-trace-id",
			dm:       DNSMessage{},
			expected: "-",
		},
		{
			name:     "default",
			format:   "otel-trace-id",
			dm:       DNSMessage{OpenTelemetry: &LoggerOpenTelemetry{TraceID: "27c3e94ad6284eec9a50cfc5bd7384d6"}},
			expected: "27c3e94ad6284eec9a50cfc5bd7384d6",
		},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			var buf bytes.Buffer
			err := tc.dm.ToTextLine(strings.Fields(tc.format), config.Global.TextFormatDelimiter, config.Global.TextFormatBoundary, &buf)
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

func TestDnsMessage_TextFormat_Directives_Pdns(t *testing.T) {
	config := pkgconfig.GetDefaultConfig()

	testcases := []struct {
		name     string
		format   string
		dm       DNSMessage
		expected string
	}{
		{
			name:     "undefined",
			format:   "powerdns-tags",
			dm:       DNSMessage{},
			expected: "-",
		},
		{
			name:     "empty_attributes",
			format:   "powerdns-tags powerdns-applied-policy powerdns-original-request-subnet powerdns-metadata",
			dm:       DNSMessage{PowerDNS: &CollectorPowerDNS{}},
			expected: "- - - -",
		},
		{
			name:   "applied_policy",
			format: "powerdns-applied-policy powerdns-applied-policy-hit powerdns-applied-policy-kind powerdns-applied-policy-trigger powerdns-applied-policy-type",
			dm: DNSMessage{PowerDNS: &CollectorPowerDNS{
				AppliedPolicy:        "policy",
				AppliedPolicyHit:     "hit",
				AppliedPolicyKind:    "kind",
				AppliedPolicyTrigger: "trigger",
				AppliedPolicyType:    "type",
			}},
			expected: "policy hit kind trigger type",
		},
		{
			name:     "original_request_subnet",
			format:   "powerdns-original-request-subnet",
			dm:       DNSMessage{PowerDNS: &CollectorPowerDNS{OriginalRequestSubnet: "test"}},
			expected: "test",
		},
		{
			name:     "metadata_badsyntax",
			format:   "powerdns-metadata",
			dm:       DNSMessage{PowerDNS: &CollectorPowerDNS{Metadata: map[string]string{"test_key1": "test_value1"}}},
			expected: "-",
		},
		{
			name:     "metadata",
			format:   "powerdns-metadata:test_key1",
			dm:       DNSMessage{PowerDNS: &CollectorPowerDNS{Metadata: map[string]string{"test_key1": "test_value1"}}},
			expected: "test_value1",
		},
		{
			name:     "metadata_invalid",
			format:   "powerdns-metadata:test_key2",
			dm:       DNSMessage{PowerDNS: &CollectorPowerDNS{Metadata: map[string]string{"test_key1": "test_value1"}}},
			expected: "-",
		},
		{
			name:     "tags_all",
			format:   "powerdns-tags",
			dm:       DNSMessage{PowerDNS: &CollectorPowerDNS{Tags: []string{"tag1", "tag2"}}},
			expected: "tag1,tag2",
		},
		{
			name:     "tags_index",
			format:   "powerdns-tags:1",
			dm:       DNSMessage{PowerDNS: &CollectorPowerDNS{Tags: []string{"tag1", "tag2"}}},
			expected: "tag2",
		},
		{
			name:     "tags_invalid_index",
			format:   "powerdns-tags:3",
			dm:       DNSMessage{PowerDNS: &CollectorPowerDNS{Tags: []string{"tag1", "tag2"}}},
			expected: "-",
		},
		{
			name:     "message_id",
			format:   "powerdns-message-id",
			dm:       DNSMessage{PowerDNS: &CollectorPowerDNS{MessageID: "27c3e94ad6284eec9a50cfc5bd7384d6"}},
			expected: "27c3e94ad6284eec9a50cfc5bd7384d6",
		},
		{
			name:     "initial_requestor_id",
			format:   "powerdns-initial-requestor-id",
			dm:       DNSMessage{PowerDNS: &CollectorPowerDNS{InitialRequestorID: "5e006236c8a74f7eafc6af126e6d0689"}},
			expected: "5e006236c8a74f7eafc6af126e6d0689",
		},
		{
			name:     "requestor_id",
			format:   "powerdns-requestor-id",
			dm:       DNSMessage{PowerDNS: &CollectorPowerDNS{RequestorID: "5e006236c8a74f7eafc6af126e6d0689"}},
			expected: "5e006236c8a74f7eafc6af126e6d0689",
		},
		{
			name:     "device_id_name",
			format:   "powerdns-device-id powerdns-device-name",
			dm:       DNSMessage{PowerDNS: &CollectorPowerDNS{DeviceID: "5e006236c8a74f7eafc6af126e6d0689", DeviceName: "test"}},
			expected: "5e006236c8a74f7eafc6af126e6d0689 test",
		},
		{
			name:     "edns_version",
			format:   "powerdns-edns-version",
			dm:       DNSMessage{PowerDNS: &CollectorPowerDNS{EdnsVersion: "1"}},
			expected: "1",
		},
		{
			name:     "opentelemetry_data",
			format:   "powerdns-opentelemetry-data",
			dm:       DNSMessage{PowerDNS: &CollectorPowerDNS{OpenTelemetryData: "5e006236c8a74f7eafc6af126e6d0689"}},
			expected: "5e006236c8a74f7eafc6af126e6d0689",
		},
		{
			name:     "ede",
			format:   "powerdns-ede",
			dm:       DNSMessage{PowerDNS: &CollectorPowerDNS{Ede: func(i int) *int { return &i }(15)}},
			expected: "15",
		},
		{
			name:     "ede_text",
			format:   "powerdns-ede-text",
			dm:       DNSMessage{PowerDNS: &CollectorPowerDNS{EdeText: "Blocked by RPZ"}},
			expected: "Blocked by RPZ",
		},
		{
			name:     "opentelemetry_trace_id",
			format:   "powerdns-opentelemetry-trace-id",
			dm:       DNSMessage{PowerDNS: &CollectorPowerDNS{OpenTelemetryTraceID: "4bf92f3577b34da6a3ce929d0e0e4736"}},
			expected: "4bf92f3577b34da6a3ce929d0e0e4736",
		},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			var buf bytes.Buffer
			err := tc.dm.ToTextLine(strings.Fields(tc.format), config.Global.TextFormatDelimiter, config.Global.TextFormatBoundary, &buf)
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
