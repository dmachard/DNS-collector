package dnsutils

import (
	"testing"
)

func Benchmark_DNSMessageBatch_AcquireRelease(b *testing.B) {
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		batch := AcquireDNSMessageBatch(64)
		batch.Release()
	}
}

func Benchmark_DNSMessageBatch_AppendAndRelease(b *testing.B) {
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		batch := AcquireDNSMessageBatch(64)
		for j := 0; j < 64; j++ {
			dm := AcquireDNSMessage()
			batch.Messages = append(batch.Messages, dm)
		}
		batch.Release()
	}
}

func Benchmark_DNSMessageBatch_RetainRelease_Fanout(b *testing.B) {
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		batch := AcquireDNSMessageBatch(64)
		dm := AcquireDNSMessage()
		batch.Messages = append(batch.Messages, dm)

		// 3 downstream consumers
		batch.Retain(2)
		batch.Release()
		batch.Release()
		batch.Release()
	}
}

func Benchmark_DNSMessageBatch_NewFromMessage(b *testing.B) {
	dm := AcquireDNSMessage()
	defer dm.Release()

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		batch := NewDNSMessageBatch(dm)
		// retain so dm is not reset
		dm.Retain(1)
		batch.Release()
	}
}
