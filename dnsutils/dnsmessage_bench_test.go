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

func BenchmarkDnsMessage_ToTextFormat_Transformers(b *testing.B) {
	dm := DNSMessage{}
	dm.Init()
	dm.InitTransforms()

	textFormat := []string{
		"timestamp-rfc3339ns", "identity", "operation", "rcode",
		"geoip-country", "powerdns-applied-policy", "atags", "otel-trace-id", "ml-entropy", "suspicious-score",
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

func BenchmarkDnsMessage_TextFormatter(b *testing.B) {
	dm := DNSMessage{}
	dm.Init()
	dm.InitTransforms()

	textFormat := []string{
		"timestamp-rfc3339ns", "identity",
		"operation", "rcode", "queryip", "queryport", "family",
		"protocol", "length-unit", "qname", "qtype", "latency", "latency_ms",
	}

	formatter, err := NewTextFormatter(textFormat, " ", "\"")
	if err != nil {
		b.Fatalf("failed to create formatter: %v", err)
	}

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		buf := textBufferPool.Get().(*bytes.Buffer)
		buf.Reset()

		err := formatter.Format(&dm, buf)
		if err != nil {
			b.Fatalf("could not encode to text format: %v\n", err)
		}

		textBufferPool.Put(buf)
	}
}

func BenchmarkDnsMessage_TextFormatter_Transformers(b *testing.B) {
	dm := DNSMessage{}
	dm.Init()
	dm.InitTransforms()

	textFormat := []string{
		"timestamp-rfc3339ns", "identity", "operation", "rcode",
		"geoip-country", "powerdns-applied-policy", "atags", "otel-trace-id", "ml-entropy", "suspicious-score",
	}

	formatter, err := NewTextFormatter(textFormat, " ", "\"")
	if err != nil {
		b.Fatalf("failed to create formatter: %v", err)
	}

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		buf := textBufferPool.Get().(*bytes.Buffer)
		buf.Reset()

		err := formatter.Format(&dm, buf)
		if err != nil {
			b.Fatalf("could not encode to text format: %v\n", err)
		}

		textBufferPool.Put(buf)
	}
}
