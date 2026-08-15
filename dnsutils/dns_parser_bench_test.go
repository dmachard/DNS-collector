package dnsutils

import (
	"net"
	"testing"

	dnstap "github.com/dmachard/go-dnstap-protobuf"
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

func BenchmarkOptCodeToString(b *testing.B) {
	// Simulate EDNS Cookie (10) or CSUBNET (8)
	input := 10
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = OptCodeToString(input)
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

var resultMsg *DNSMessage

func BenchmarkCustomDecodeDNS(b *testing.B) {
	pkt, err := GetDNSResponsePacket()
	if err != nil {
		b.Fatalf("failed to pack DNS response: %v", err)
	}
	config := &pkgconfig.Config{}
	dm := &DNSMessage{}
	dm.DNS.Payload = pkt

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		header, _ := DecodeDNS(pkt)
		_ = DecodePayload(dm, &header, config)
		resultMsg = dm
	}
}

func BenchmarkMiekgDecodeDNS(b *testing.B) {
	pkt, err := GetDNSResponsePacket()
	if err != nil {
		b.Fatalf("failed to pack DNS response: %v", err)
	}
	msg := new(dns.Msg)

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if err := msg.Unpack(pkt); err != nil {
			b.Fatal(err)
		}
	}
}

func Benchmark_DnstapEnum_ProtobufString(b *testing.B) {
	msgType := dnstap.Message_CLIENT_QUERY
	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		_ = msgType.String()
	}
}

func Benchmark_DnstapEnum_ArrayLookup(b *testing.B) {
	msgType := dnstap.Message_CLIENT_QUERY
	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		_ = DnstapOperationToString(int(msgType))
	}
}

func Benchmark_TimeFormatRFC3339Nano(b *testing.B) {
	ts := time.Now()
	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		_ = ts.UTC().Format(time.RFC3339Nano)
	}
}
