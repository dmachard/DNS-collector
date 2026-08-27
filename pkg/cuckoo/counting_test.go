package cuckoo

import (
	"fmt"
	"sync"
	"testing"
)

func TestCountingCuckooFilter_IncrementAndLookup(t *testing.T) {
	cf := NewCountingCuckooFilter(1000)

	// Initially 0
	if c := cf.Lookup("example.com"); c != 0 {
		t.Fatalf("expected 0 for absent key, got %d", c)
	}

	// Increment 5 times
	for i := 1; i <= 5; i++ {
		c := cf.Increment("example.com")
		if c != uint32(i) {
			t.Fatalf("expected count %d on increment, got %d", i, c)
		}
	}

	// Lookup should return 5
	if c := cf.Lookup("example.com"); c != 5 {
		t.Fatalf("expected lookup count 5, got %d", c)
	}

	// Distinct key
	if c := cf.Increment("other.org"); c != 1 {
		t.Fatalf("expected count 1 for other.org, got %d", c)
	}
	if c := cf.Lookup("example.com"); c != 5 {
		t.Fatalf("expected lookup count 5 for example.com, got %d", c)
	}
}

func TestCountingCuckooFilter_DecayAndReset(t *testing.T) {
	cf := NewCountingCuckooFilter(1000)

	cf.Increment("domain1.com")
	cf.Increment("domain1.com")
	cf.Increment("domain1.com")
	cf.Increment("domain1.com") // count = 4

	cf.Increment("domain2.com") // count = 1

	// Decay by 0.5 -> domain1 should become 2, domain2 should become 0 and be evicted
	cf.Decay(0.5)

	if c := cf.Lookup("domain1.com"); c != 2 {
		t.Fatalf("expected domain1 count 2 after decay, got %d", c)
	}
	if c := cf.Lookup("domain2.com"); c != 0 {
		t.Fatalf("expected domain2 count 0 after decay, got %d", c)
	}

	// Reset
	cf.Reset()
	if c := cf.Lookup("domain1.com"); c != 0 {
		t.Fatalf("expected domain1 count 0 after reset, got %d", c)
	}
	if cf.Count() != 0 {
		t.Fatalf("expected total count 0 after reset, got %d", cf.Count())
	}
}

func TestCountingCuckooFilter_Concurrent(t *testing.T) {
	cf := NewCountingCuckooFilter(10000)
	var wg sync.WaitGroup

	numGoroutines := 16
	numOps := 500

	for g := 0; g < numGoroutines; g++ {
		wg.Add(1)
		go func(gid int) {
			defer wg.Done()
			for i := 0; i < numOps; i++ {
				key := fmt.Sprintf("domain-%d.com", i%50)
				cf.Increment(key)
				_ = cf.Lookup(key)
			}
		}(g)
	}

	wg.Wait()

	if cf.Count() == 0 {
		t.Fatalf("expected non-zero entries in filter")
	}
}
