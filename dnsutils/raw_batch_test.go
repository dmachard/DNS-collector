package dnsutils

import (
	"testing"
)

func TestRawBatchPool_AcquireAndRelease(t *testing.T) {
	batch := AcquireRawBatch()
	if batch == nil {
		t.Fatalf("expected non-nil RawBatch")
	}
	if len(batch.Frames) != 0 {
		t.Fatalf("expected empty frames, got %d", len(batch.Frames))
	}
	if cap(batch.Frames) < DefaultRawBatchSize {
		t.Fatalf("expected capacity at least %d, got %d", DefaultRawBatchSize, cap(batch.Frames))
	}

	// Add some dummy frames
	for i := 0; i < 100; i++ {
		batch.Frames = append(batch.Frames, []byte("test frame"))
	}
	if len(batch.Frames) != 100 {
		t.Fatalf("expected 100 frames, got %d", len(batch.Frames))
	}

	// Release back to pool
	batch.Release()

	// Acquire again, must be reset to 0 length
	batch2 := AcquireRawBatch()
	if len(batch2.Frames) != 0 {
		t.Fatalf("expected recycled batch to have 0 length, got %d", len(batch2.Frames))
	}
	batch2.Release()
}

func TestRawBatchPool_ExcessiveCapacityShrink(t *testing.T) {
	batch := AcquireRawBatch()

	// Force capacity beyond 1024
	for i := 0; i < 1500; i++ {
		batch.Frames = append(batch.Frames, []byte("overflow frame"))
	}
	if cap(batch.Frames) <= 1024 {
		t.Fatalf("expected capacity > 1024, got %d", cap(batch.Frames))
	}

	// Release should shrink back to DefaultRawBatchSize
	batch.Release()

	batch2 := AcquireRawBatch()
	if cap(batch2.Frames) > 1024 {
		t.Fatalf("expected shrink to capacity <= 1024, got %d", cap(batch2.Frames))
	}
	batch2.Release()
}

func TestRawBatch_NilRelease(t *testing.T) {
	var b *RawBatch
	// Should not panic on nil release
	b.Release()
}

func BenchmarkRawBatchPool(b *testing.B) {
	dummy := []byte("bench")
	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		batch := AcquireRawBatch()
		batch.Frames = append(batch.Frames, dummy)
		batch.Release()
	}
}
