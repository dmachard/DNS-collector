package dnsutils

import (
	"bytes"
	"errors"
	"net"
	"testing"

	"github.com/miekg/dns"
)

func TestRcodeValid(t *testing.T) {
	rcode := RcodeToString(0)
	if rcode != "NOERROR" {
		t.Errorf("rcode noerror expected: %s", rcode)
	}
}

func TestRcodeInvalid(t *testing.T) {
	rcode := RcodeToString(100000)
	if rcode != "UNKNOWN" {
		t.Errorf("invalid rcode - expected: %s", rcode)
	}
}

func TestParseIP_IPv4(t *testing.T) {
	tests := []struct {
		name     string
		input    []byte
		expected string
	}{
		{"Localhost", []byte{127, 0, 0, 1}, "127.0.0.1"},
		{"Zero", []byte{0, 0, 0, 0}, "0.0.0.0"},
		{"Broadcast", []byte{255, 255, 255, 255}, "255.255.255.255"},
		{"Private A", []byte{10, 255, 0, 42}, "10.255.0.42"},
		{"Private C", []byte{192, 168, 1, 100}, "192.168.1.100"},
		{"Public DNS 1", []byte{8, 8, 8, 8}, "8.8.8.8"},
		{"Public DNS 2", []byte{1, 1, 1, 1}, "1.1.1.1"},
		{"Mixed digits", []byte{100, 200, 150, 99}, "100.200.150.99"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseIP(tt.input, net.IPv4len)
			if err != nil {
				t.Fatalf("unexpected error for %s: %v", tt.name, err)
			}
			if got != tt.expected {
				t.Errorf("ParseIP(%v) = %q, want %q", tt.input, got, tt.expected)
			}
		})
	}
}

func TestParseIP_IPv6(t *testing.T) {
	tests := []struct {
		name     string
		input    []byte
		expected string
	}{
		{"Loopback", net.ParseIP("::1").To16(), "::1"},
		{"Google Public DNS", net.ParseIP("2001:4860:4860::8888").To16(), "2001:4860:4860::8888"},
		{"Link local", net.ParseIP("fe80::1").To16(), "fe80::1"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseIP(tt.input, net.IPv6len)
			if err != nil {
				t.Fatalf("unexpected error for %s: %v", tt.name, err)
			}
			if got != tt.expected {
				t.Errorf("ParseIP(%v) = %q, want %q", tt.input, got, tt.expected)
			}
		})
	}
}

func TestParseIP_TooShort(t *testing.T) {
	tooShort := []byte{192, 168, 1}
	_, err := ParseIP(tooShort, net.IPv4len)
	if !errors.Is(err, ErrDecodeDNSAnswerRdataTooShort) {
		t.Errorf("expected ErrDecodeDNSAnswerRdataTooShort, got: %v", err)
	}
}

func TestDecodeDns(t *testing.T) {
	dm := new(dns.Msg)
	dm.SetQuestion(TestQName, dns.TypeA)

	payload, _ := dm.Pack()
	_, err := DecodeDNS(payload)
	if err != nil {
		t.Errorf("decode dns error: %s", err)
	}
}

func TestDecodeDns_HeaderTooShort(t *testing.T) {
	decoded := []byte{183, 59}
	_, err := DecodeDNS(decoded)
	if !errors.Is(err, ErrDecodeDNSHeaderTooShort) {
		t.Errorf("bad error returned: %v", err)
	}
}

func TestWriteIPv4(t *testing.T) {
	tests := []struct {
		name     string
		input    []byte
		expected string
	}{
		{"Localhost", []byte{127, 0, 0, 1}, "127.0.0.1"},
		{"Zero", []byte{0, 0, 0, 0}, "0.0.0.0"},
		{"Broadcast", []byte{255, 255, 255, 255}, "255.255.255.255"},
		{"Private A", []byte{10, 255, 0, 42}, "10.255.0.42"},
		{"Private C", []byte{192, 168, 1, 100}, "192.168.1.100"},
		{"Public DNS 1", []byte{8, 8, 8, 8}, "8.8.8.8"},
		{"Public DNS 2", []byte{1, 1, 1, 1}, "1.1.1.1"},
		{"Mixed digits", []byte{100, 200, 150, 99}, "100.200.150.99"},
		{"Single digit octets", []byte{1, 2, 3, 4}, "1.2.3.4"},
		{"Invalid length fallback", []byte{10, 0, 1}, net.IP([]byte{10, 0, 1}).String()},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var buf bytes.Buffer
			WriteIPv4(&buf, tt.input)
			if got := buf.String(); got != tt.expected {
				t.Errorf("WriteIPv4(%v) = %q, want %q", tt.input, got, tt.expected)
			}
		})
	}
}

func TestWriteIP(t *testing.T) {
	tests := []struct {
		name     string
		input    []byte
		expected string
	}{
		{"IPv4 standard", []byte{192, 168, 0, 1}, "192.168.0.1"},
		{"IPv6 loopback", net.ParseIP("::1").To16(), "::1"},
		{"IPv6 full", net.ParseIP("2001:4860:4860::8888").To16(), "2001:4860:4860::8888"},
		{"Empty input", []byte{}, "-"},
		{"Nil input", nil, "-"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var buf bytes.Buffer
			WriteIP(&buf, tt.input)
			if got := buf.String(); got != tt.expected {
				t.Errorf("WriteIP(%v) = %q, want %q", tt.input, got, tt.expected)
			}
		})
	}
}
