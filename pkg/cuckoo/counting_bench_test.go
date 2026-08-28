package cuckoo

import (
	"fmt"
	"testing"
)

func BenchmarkCountingCuckooFilter_Increment(b *testing.B) {
	cf := NewCountingCuckooFilter(100000)
	keys := make([]string, 10000)
	for i := range keys {
		keys[i] = fmt.Sprintf("bench-domain-%d.com", i)
	}

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = cf.Increment(keys[i%len(keys)])
	}
}

func BenchmarkCountingCuckooFilter_Lookup(b *testing.B) {
	cf := NewCountingCuckooFilter(100000)
	keys := make([]string, 10000)
	for i := range keys {
		keys[i] = fmt.Sprintf("bench-domain-%d.com", i)
		cf.Increment(keys[i])
	}

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = cf.Lookup(keys[i%len(keys)])
	}
}
