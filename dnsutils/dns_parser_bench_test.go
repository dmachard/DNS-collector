package dnsutils

import (
	"net"
	"testing"

	"github.com/dmachard/go-dnscollector/v2/pkgconfig"
	"github.com/miekg/dns"
)

func BenchmarkLookupRdatatypeToString(b *testing.B) {
	// Simulate A, NS, CNAME, SOA, AAAA
	input := []int{1, 2, 5, 6, 28}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = RdatatypeToString(input[i%len(input)])
	}
}

func BenchmarkLookupRcodeToString(b *testing.B) {
	// The NOERROR rcode (0) represents 99% of traffic
	input := 0
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = RcodeToString(input)
	}
}

func BenchmarkLookupClassToString(b *testing.B) {
	// The IN class (1) represents 99% of traffic
	input := 1
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = ClassToString(input)
	}
}

func BenchmarkParseIP_v4(b *testing.B) {
	// simulate IPv4 rdata (4 octets)
	input := []byte{192, 168, 1, 1}
	size := net.IPv4len

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := ParseIP(input, size)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkParseIP_v6(b *testing.B) {
	// simulate IPv6 rdata (16 octets)
	input := []byte{0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}
	size := net.IPv6len

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := ParseIP(input, size)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkParseRdata_TypeA(b *testing.B) {
	rdata := []byte{192, 168, 1, 1}
	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_, _ = ParseRdata(1, rdata, nil, 0, false)
	}
}

func BenchmarkParseRdata_TypeAAAA(b *testing.B) {
	rdata := []byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}
	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_, _ = ParseRdata(28, rdata, nil, 0, false)
	}
}

var exampleDNSPacket = []byte{
	0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
	// Question: example.com
	0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 0x03, 'c', 'o', 'm', 0x00,
	0x00, 0x01, 0x00, 0x01,
	// Answer: example.com (pointer) -> A -> 60s -> 4 bytes
	0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x3c, 0x00, 0x04, 0x5d, 0xb8, 0xd8, 0x22,
}
var resultMsg *DNSMessage

func BenchmarkCustomDecodeDNS(b *testing.B) {
	config := &pkgconfig.Config{}
	dm := &DNSMessage{}
	dm.DNS.Payload = exampleDNSPacket

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		header, _ := DecodeDNS(exampleDNSPacket)
		_ = DecodePayload(dm, &header, config)
		resultMsg = dm
	}
}

func BenchmarkMiekgDecodeDNS(b *testing.B) {
	msg := new(dns.Msg)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if err := msg.Unpack(exampleDNSPacket); err != nil {
			b.Fatal(err)
		}
	}
}
