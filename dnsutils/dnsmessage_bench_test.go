package dnsutils

import (
	"bytes"
	"sync"
	"testing"
)

var textBufferPool = sync.Pool{
	New: func() interface{} {
		return bytes.NewBuffer(make([]byte, 0, 512))
	},
}

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

func BenchmarkDnsMessage_ToTextFormat(b *testing.B) {
	dm := DNSMessage{}
	dm.Init()
	dm.InitTransforms()

	textFormat := []string{
		"timestamp-rfc3339ns", "identity",
		"operation", "rcode", "queryip", "queryport", "family",
		"protocol", "length-unit", "qname", "qtype", "latency", "latency_ms",
	}

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		buf := textBufferPool.Get().(*bytes.Buffer)
		buf.Reset()

		err := dm.ToTextLine(textFormat, " ", "\"", buf)
		if err != nil {
			b.Fatalf("could not encode to text format: %v\n", err)
		}

		textBufferPool.Put(buf)
	}
}
