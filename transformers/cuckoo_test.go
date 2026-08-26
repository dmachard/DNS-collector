package transformers

import (
	"fmt"
	"testing"
	"time"
)

func TestCuckooFilter_Basic(t *testing.T) {
	cf := NewCuckooFilter(1000)

	h1 := fastHash64([]byte("example.com/A/1.2.3.4"))
	h2 := fastHash64([]byte("google.com/A/8.8.8.8"))

	if cf.Lookup(h1) {
		t.Fatalf("expected h1 not to be in filter")
	}

	if !cf.Insert(h1) {
		t.Fatalf("failed to insert h1")
	}

	if !cf.Lookup(h1) {
		t.Fatalf("expected h1 to be found")
	}

	if cf.Lookup(h2) {
		t.Fatalf("expected h2 not to be found")
	}
}

func TestCuckooFilter_FalsePositiveRate(t *testing.T) {
	capacity := 10000
	cf := NewCuckooFilter(capacity)

	for i := 0; i < capacity; i++ {
		h := fastHash64([]byte(fmt.Sprintf("domain%d.com/A/10.0.0.1", i)))
		cf.Insert(h)
	}

	// Test false positive with 10,000 distinct items not inserted
	fps := 0
	trials := 10000
	for i := capacity; i < capacity+trials; i++ {
		h := fastHash64([]byte(fmt.Sprintf("domain%d.com/A/10.0.0.1", i)))
		if cf.Lookup(h) {
			fps++
		}
	}

	fpRate := float64(fps) / float64(trials)
	t.Logf("False positive count: %d / %d (%.4f%%)", fps, trials, fpRate*100)

	if fpRate > 0.005 { // Ensure FP rate is less than 0.5% (typically ~0.003%)
		t.Fatalf("false positive rate too high: %.4f", fpRate)
	}
}

func TestSlidingCuckooFilter_Rotation(t *testing.T) {
	scf := NewSlidingCuckooFilter(1000, 20*time.Millisecond)
	defer scf.Close()

	h1 := hashTuple("test.com", "A", "1.1.1.1")

	// First time: should be new
	if !scf.TestAndAdd(h1) {
		t.Fatalf("expected h1 to be added as new")
	}

	// Second time immediately: should be recognized as existing
	if scf.TestAndAdd(h1) {
		t.Fatalf("expected h1 to be recognized as already known")
	}

	// Rotate once: h1 is in previous, should still be known
	scf.Rotate()
	if scf.TestAndAdd(h1) {
		t.Fatalf("expected h1 to still be remembered in previous window")
	}

	// Rotate again: h1 is dropped from previous, should be recognized as new!
	scf.Rotate()
	if !scf.TestAndAdd(h1) {
		t.Fatalf("expected h1 to be new after two rotations")
	}
}
