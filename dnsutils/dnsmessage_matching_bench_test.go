package dnsutils

import (
	"testing"
)

func Benchmark_Matching_Integer_Current(b *testing.B) {
	dm := &DNSMessage{DNS: DNS{Opcode: 1}}
	matching := map[string]interface{}{"dns.opcode": 1}

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		_, _ = dm.Matching(matching)
	}
}

func Benchmark_Matching_Integer_Compiled(b *testing.B) {
	dm := &DNSMessage{DNS: DNS{Opcode: 1}}
	matching := map[string]interface{}{"dns.opcode": 1}
	matcher, err := CompileMatcher(matching)
	if err != nil {
		b.Fatal(err)
	}

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		_ = matcher.Match(dm)
	}
}

func Benchmark_Matching_String_Current(b *testing.B) {
	dm := &DNSMessage{DNS: DNS{Qname: "www.example.com"}}
	matching := map[string]interface{}{"dns.qname": "www.example.com"}

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		_, _ = dm.Matching(matching)
	}
}

func Benchmark_Matching_String_Compiled(b *testing.B) {
	dm := &DNSMessage{DNS: DNS{Qname: "www.example.com"}}
	matching := map[string]interface{}{"dns.qname": "www.example.com"}
	matcher, err := CompileMatcher(matching)
	if err != nil {
		b.Fatal(err)
	}

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		_ = matcher.Match(dm)
	}
}

func Benchmark_Matching_Multiple_Current(b *testing.B) {
	dm := &DNSMessage{
		DNS: DNS{
			Opcode: 1,
			Qname:  "www.example.com",
			Qtype:  "A",
			Flags:  DNSFlags{QR: true},
		},
		NetworkInfo: DNSNetInfo{
			Family:   "INET",
			Protocol: "UDP",
		},
	}
	matching := map[string]interface{}{
		"dns.flags.qr":     true,
		"dns.opcode":       1,
		"dns.qname":        "www.example.com",
		"network.family":   "INET",
		"network.protocol": "UDP",
	}

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		_, _ = dm.Matching(matching)
	}
}

func Benchmark_Matching_Multiple_Compiled(b *testing.B) {
	dm := &DNSMessage{
		DNS: DNS{
			Opcode: 1,
			Qname:  "www.example.com",
			Qtype:  "A",
			Flags:  DNSFlags{QR: true},
		},
		NetworkInfo: DNSNetInfo{
			Family:   "INET",
			Protocol: "UDP",
		},
	}
	matching := map[string]interface{}{
		"dns.flags.qr":     true,
		"dns.opcode":       1,
		"dns.qname":        "www.example.com",
		"network.family":   "INET",
		"network.protocol": "UDP",
	}
	matcher, err := CompileMatcher(matching)
	if err != nil {
		b.Fatal(err)
	}

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		_ = matcher.Match(dm)
	}
}

func Benchmark_Matching_RegexSlice_Current(b *testing.B) {
	dm := &DNSMessage{DNS: DNS{Qname: "api.github.com"}}
	matching := map[string]interface{}{
		"dns.qname": []interface{}{
			"^.*\\.google\\.com$",
			"^.*\\.github\\.com$",
		},
	}

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		_, _ = dm.Matching(matching)
	}
}

func Benchmark_Matching_RegexSlice_Compiled(b *testing.B) {
	dm := &DNSMessage{DNS: DNS{Qname: "api.github.com"}}
	matching := map[string]interface{}{
		"dns.qname": []interface{}{
			"^.*\\.google\\.com$",
			"^.*\\.github\\.com$",
		},
	}
	matcher, err := CompileMatcher(matching)
	if err != nil {
		b.Fatal(err)
	}

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		_ = matcher.Match(dm)
	}
}
