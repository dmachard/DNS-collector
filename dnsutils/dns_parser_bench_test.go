package dnsutils

import (
	"bytes"
	"net"
	"testing"
	"time"

	"github.com/dmachard/go-dnscollector/v3/pkg/config"
	dnstap "github.com/dmachard/go-dnstap-protobuf"
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
	cfg := &config.Config{}
	dm := &DNSMessage{}
	dm.DNS.Payload = pkt

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		header, _ := DecodeDNS(pkt)
		_ = DecodePayload(dm, &header, cfg)
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

func Benchmark_NetIPString(b *testing.B) {
	ip := net.ParseIP("192.168.1.100").To4()
	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = ip.String()
	}
}

func Benchmark_FastIPv4ToString(b *testing.B) {
	ip := []byte{192, 168, 1, 100}
	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = FastIPv4ToString(ip)
	}
}

func Benchmark_IPv6_NetIPString(b *testing.B) {
	ip := net.ParseIP("2001:db8:85a3::8a2e:370:7334")
	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = ip.String()
	}
}

func Benchmark_FastIPv6ToString(b *testing.B) {
	ip := []byte{0x20, 0x01, 0x0d, 0xb8, 0x85, 0xa3, 0, 0, 0, 0, 0x8a, 0x2e, 0x03, 0x70, 0x73, 0x34}
	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = FastIPv6ToString(ip)
	}
}

func Benchmark_WriteIP_IPv4(b *testing.B) {
	ip := []byte{192, 168, 1, 100}
	var buf bytes.Buffer
	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		buf.Reset()
		WriteIP(&buf, ip)
	}
}

func Benchmark_WriteIP_IPv6(b *testing.B) {
	ip := []byte{0x20, 0x01, 0x0d, 0xb8, 0x85, 0xa3, 0, 0, 0, 0, 0x8a, 0x2e, 0x03, 0x70, 0x73, 0x34}
	var buf bytes.Buffer
	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		buf.Reset()
		WriteIP(&buf, ip)
	}
}

func BenchmarkDecodeQuestion_StandardQuery(b *testing.B) {
	// Standard DNS query: 12-byte header + \x0cdscollector\x02fr\x00 + Type A (1) + Class IN (1)
	payload := []byte{
		0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		12, 'd', 'n', 's', 'c', 'o', 'l', 'l', 'e', 'c', 't', 'o', 'r',
		2, 'f', 'r',
		0,
		0x00, 0x01,
		0x00, 0x01,
	}

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_, _, _, _, _ = DecodeQuestion(1, payload)
	}
}

func BenchmarkDecodeQuestion_SubdomainQuery(b *testing.B) {
	// Subdomain query: sub.domain.test.example.com
	payload := []byte{
		0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		3, 's', 'u', 'b',
		6, 'd', 'o', 'm', 'a', 'i', 'n',
		4, 't', 'e', 's', 't',
		7, 'e', 'x', 'a', 'm', 'p', 'l', 'e',
		3, 'c', 'o', 'm',
		0,
		0x00, 0x1c, // AAAA
		0x00, 0x01, // IN
	}

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_, _, _, _, _ = DecodeQuestion(1, payload)
	}
}

func BenchmarkCustomDecodeDNS_Query(b *testing.B) {
	payload := []byte{
		0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		12, 'd', 'n', 's', 'c', 'o', 'l', 'l', 'e', 'c', 't', 'o', 'r',
		2, 'f', 'r',
		0,
		0x00, 0x01,
		0x00, 0x01,
	}
	cfg := &config.Config{}
	dm := &DNSMessage{}
	dm.DNS.Payload = payload

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		header, _ := DecodeDNS(payload)
		_ = DecodePayload(dm, &header, cfg)
		resultMsg = dm
	}
}
