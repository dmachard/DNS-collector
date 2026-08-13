package dnsutils

import (
	"testing"
)

func Benchmark_DNSMessage_ToJSON(b *testing.B) {
	dm := DNSMessage{}
	dm.Init()
	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = dm.ToJSON()
	}
}

func Benchmark_DNSMessage_ToFlatJSON(b *testing.B) {
	dm := DNSMessage{}
	dm.Init()
	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_, _ = dm.ToFlatJSON()
	}
}
