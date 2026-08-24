package dnsutils

import (
	"testing"

	"github.com/dmachard/go-netutils"
	"github.com/miekg/dns"
)

func getBenchDNSMessage(family, proto string) *DNSMessage {
	dm := &DNSMessage{}
	dm.Init()
	dm.InitTransforms()

	dnsmsg := new(dns.Msg)
	dnsmsg.SetQuestion("dnscollector.dev.", dns.TypeAAAA)
	dnsquestion, _ := dnsmsg.Pack()

	dm.NetworkInfo.Family = family
	dm.NetworkInfo.Protocol = proto
	if family == netutils.ProtoIPv4 {
		dm.NetworkInfo.QueryIP = "192.168.1.100"
		dm.NetworkInfo.ResponseIP = "8.8.8.8"
	} else {
		dm.NetworkInfo.QueryIP = "2001:db8::1"
		dm.NetworkInfo.ResponseIP = "2001:4860:4860::8888"
	}
	dm.NetworkInfo.QueryPort = "54321"
	dm.NetworkInfo.ResponsePort = "53"
	dm.DNS.Type = DNSQuery
	dm.DNS.Payload = dnsquestion
	dm.DNS.Length = len(dnsquestion)
	return dm
}

func Benchmark_Pcap_IPv4_UDP(b *testing.B) {
	dm := getBenchDNSMessage(netutils.ProtoIPv4, netutils.ProtoUDP)
	var buf [512]byte
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := dm.EncodeToPacketBytes(buf[:0], false)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func Benchmark_Pcap_IPv4_TCP(b *testing.B) {
	dm := getBenchDNSMessage(netutils.ProtoIPv4, netutils.ProtoTCP)
	var buf [512]byte
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := dm.EncodeToPacketBytes(buf[:0], false)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func Benchmark_Pcap_IPv6_UDP(b *testing.B) {
	dm := getBenchDNSMessage(netutils.ProtoIPv6, netutils.ProtoUDP)
	var buf [512]byte
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := dm.EncodeToPacketBytes(buf[:0], false)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func Benchmark_Pcap_IPv6_TCP(b *testing.B) {
	dm := getBenchDNSMessage(netutils.ProtoIPv6, netutils.ProtoTCP)
	var buf [512]byte
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := dm.EncodeToPacketBytes(buf[:0], false)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func Benchmark_Pcap_FullSerialize_IPv4_UDP(b *testing.B) {
	dm := getBenchDNSMessage(netutils.ProtoIPv4, netutils.ProtoUDP)
	var buf [512]byte
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		raw, err := dm.EncodeToPacketBytes(buf[:0], false)
		if err != nil {
			b.Fatal(err)
		}
		_ = raw
	}
}
