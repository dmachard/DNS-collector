package cuckoo

import (
	"fmt"
	"sync"
	"testing"
	"time"
)

func TestCuckooFilter_Basic(t *testing.T) {
	cf := NewCuckooFilter(1000)

	h1 := FastHash64([]byte("example.com/A/1.2.3.4"))
	h2 := FastHash64([]byte("google.com/A/8.8.8.8"))

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
		h := FastHash64([]byte(fmt.Sprintf("domain%d.com/A/10.0.0.1", i)))
		cf.Insert(h)
	}

	// Test false positive with 10,000 distinct items not inserted
	fps := 0
	trials := 10000
	for i := capacity; i < capacity+trials; i++ {
		h := FastHash64([]byte(fmt.Sprintf("domain%d.com/A/10.0.0.1", i)))
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
	scf := NewSlidingCuckooFilter(1000, 20*time.Millisecond, 16)
	defer scf.Close()

	h1 := HashTuple("test.com", "A", "1.1.1.1")

	// First time: should be new
	if !scf.TestAndAdd(h1) {
		t.Fatalf("expected h1 to be added as new")
	}

	// Second time immediately: should be recognized as existing
	if !scf.Lookup(h1) {
		t.Fatalf("expected h1 to be recognized as already known")
	}

	// Rotate once: h1 is in previous, should still be known via Lookup
	scf.Rotate()
	if !scf.Lookup(h1) {
		t.Fatalf("expected h1 to still be remembered in previous window")
	}

	// Rotate again: unaccessed h1 is dropped from previous, should be recognized as new!
	scf.Rotate()
	if scf.Lookup(h1) {
		t.Fatalf("expected untouched h1 to expire after two rotations")
	}
	if !scf.TestAndAdd(h1) {
		t.Fatalf("expected h1 to be new after two rotations")
	}
}

func TestCuckooFilter_CapacitySaturation(t *testing.T) {
	capacity := 500
	cf := NewCuckooFilter(capacity)

	inserted := 0
	for i := 0; i < 2000; i++ {
		h := FastHash64([]byte(fmt.Sprintf("sat-domain%d.com/A/1.2.3.4", i)))
		if cf.Insert(h) {
			inserted++
		}
	}

	if inserted < capacity {
		t.Fatalf("expected at least %d items to be inserted, got %d", capacity, inserted)
	}
}

func TestSlidingCuckooFilter_ConcurrentAccess(t *testing.T) {
	scf := NewSlidingCuckooFilter(5000, 50*time.Millisecond, 16)
	defer scf.Close()

	var wg sync.WaitGroup
	numWorkers := 30
	numOpsPerWorker := 500

	for w := 0; w < numWorkers; w++ {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()
			for i := 0; i < numOpsPerWorker; i++ {
				domain := fmt.Sprintf("worker%d-domain%d.com", workerID, i%100)
				h := HashTuple(domain, "A", "10.0.0.1")
				_ = scf.TestAndAdd(h)
				_ = scf.Lookup(h)
			}
		}(w)
	}

	wg.Wait()
}

func TestSlidingCuckooFilter_HotItemPromotion(t *testing.T) {
	scf := NewSlidingCuckooFilter(1000, 20*time.Millisecond, 16)
	defer scf.Close()

	hHot := HashTuple("hot-domain.com", "A", "1.1.1.1")
	hCold := HashTuple("cold-domain.com", "A", "2.2.2.2")

	// 1. Initial insert of hot and cold items (both are new)
	if !scf.TestAndAdd(hHot) || !scf.TestAndAdd(hCold) {
		t.Fatalf("expected initial inserts to be true")
	}

	// 2. Rotate once: hHot and hCold are now in `previous`
	scf.Rotate()

	// 3. Query hHot while it is in previous (simulating active traffic on hot domain)
	// It should return false (already known), and get promoted into the active window!
	if scf.TestAndAdd(hHot) {
		t.Fatalf("expected hHot to be known")
	}

	// 4. Rotate second time:
	// - The unaccessed hCold in `previous` is discarded completely.
	// - The promoted hHot in `active` now shifts to `previous`.
	scf.Rotate()

	// 5. Check hCold -> Should be forgotten (returns true, recognized as new)
	if !scf.TestAndAdd(hCold) {
		t.Fatalf("expected cold item to expire after 2 rotations without traffic")
	}

	// 6. Check hHot -> Should STILL be remembered (returns false) because it was promoted!
	if scf.TestAndAdd(hHot) {
		t.Fatalf("expected hot item to remain remembered across rotations due to LRU promotion")
	}
}

func TestCuckooFilter_BitWidths(t *testing.T) {
	widths := []int{8, 16, 32}
	for _, w := range widths {
		t.Run(fmt.Sprintf("%d-bit", w), func(t *testing.T) {
			scf := NewSlidingCuckooFilter(1000, 100*time.Millisecond, w)
			defer scf.Close()

			h := HashTuple("width-test.com", "A", "1.2.3.4")
			if !scf.TestAndAdd(h) {
				t.Fatalf("expected item to be added for %d-bit filter", w)
			}
			if scf.TestAndAdd(h) {
				t.Fatalf("expected item to be duplicate for %d-bit filter", w)
			}
		})
	}
}
