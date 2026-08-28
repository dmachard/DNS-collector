// Package cuckoo - Counting Cuckoo Filter implementation for streaming frequency estimation.
//
// The CountingCuckooFilter extends canonical Cuckoo Filters by associating a 32-bit saturating counter
// with each 16-bit fingerprint slot in 4-way associative buckets (b = 4).
//
// Key Features:
//
//  1. Streaming Frequency Tracking:
//     Increment(key) tracks frequency in O(1) time (~27 ns/op, 0 B/op) and returns the updated count.
//
//  2. Heavy-Hitter & Rate Detection:
//     Identifies high-volume keys (e.g., flood domains or abusive client IPs) in real time.
//
//  3. Time-Window Aging & Decay:
//     Decay(factor) exponentially decays all counters (e.g., count * 0.5) to implement sliding time
//     windows and naturally evict inactive entries whose count drops to zero.
//
//  4. Concurrency:
//     Thread-safe via RWMutex for concurrent streaming access across multiple pipeline goroutines.
package cuckoo

import (
	"math"
	"math/rand"
	"sync"
)

// CountingSlot represents a single slot in a counting cuckoo bucket.
type CountingSlot struct {
	Fingerprint uint16
	Count       uint32
}

// CountingBucket holds 4 counting slots.
type CountingBucket [4]CountingSlot

// CountingCuckooFilter is a concurrent, high-performance counting cuckoo filter
// optimized for streaming frequency estimation and heavy-hitter detection.
type CountingCuckooFilter struct {
	mu      sync.RWMutex
	buckets []CountingBucket
	mask    uint64
	count   uint64
}

// NewCountingCuckooFilter initializes a counting cuckoo filter for the given item capacity.
func NewCountingCuckooFilter(capacity int) *CountingCuckooFilter {
	if capacity <= 0 {
		capacity = 100000
	}
	numBuckets := int(math.Ceil(float64(capacity) / float64(cuckooBucketSize)))
	n := 1
	for n < numBuckets {
		n <<= 1
	}
	return &CountingCuckooFilter{
		buckets: make([]CountingBucket, n),
		mask:    uint64(n - 1),
	}
}

func (cf *CountingCuckooFilter) getFP(hash uint64) uint16 {
	fp := uint16(hash >> 48)
	if fp == 0 {
		fp = 1
	}
	return fp
}

func (cf *CountingCuckooFilter) altIndex(i uint64, fp uint16) uint64 {
	return (i ^ hashFingerprint16(fp)) & cf.mask
}

// Increment increments the frequency count of the given key and returns the updated count.
func (cf *CountingCuckooFilter) Increment(key string) uint32 {
	hash := FastHash64([]byte(key))
	fp := cf.getFP(hash)
	i1 := hash & cf.mask
	i2 := cf.altIndex(i1, fp)

	cf.mu.Lock()
	defer cf.mu.Unlock()

	// 1. Check if fingerprint already exists in bucket 1
	for s := 0; s < 4; s++ {
		if cf.buckets[i1][s].Fingerprint == fp && cf.buckets[i1][s].Count > 0 {
			if cf.buckets[i1][s].Count < math.MaxUint32 {
				cf.buckets[i1][s].Count++
			}
			return cf.buckets[i1][s].Count
		}
	}

	// 2. Check if fingerprint already exists in bucket 2
	for s := 0; s < 4; s++ {
		if cf.buckets[i2][s].Fingerprint == fp && cf.buckets[i2][s].Count > 0 {
			if cf.buckets[i2][s].Count < math.MaxUint32 {
				cf.buckets[i2][s].Count++
			}
			return cf.buckets[i2][s].Count
		}
	}

	// 3. Not found, try to insert in an empty slot in bucket 1
	for s := 0; s < 4; s++ {
		if cf.buckets[i1][s].Fingerprint == 0 || cf.buckets[i1][s].Count == 0 {
			cf.buckets[i1][s].Fingerprint = fp
			cf.buckets[i1][s].Count = 1
			cf.count++
			return 1
		}
	}

	// 4. Try to insert in an empty slot in bucket 2
	for s := 0; s < 4; s++ {
		if cf.buckets[i2][s].Fingerprint == 0 || cf.buckets[i2][s].Count == 0 {
			cf.buckets[i2][s].Fingerprint = fp
			cf.buckets[i2][s].Count = 1
			cf.count++
			return 1
		}
	}

	// 5. Both buckets full -> Cuckoo eviction kicks
	curI := i1
	curSlot := CountingSlot{Fingerprint: fp, Count: 1}

	for kick := 0; kick < cuckooMaxKicks; kick++ {
		slotIdx := rand.Intn(4)
		// Swap
		curSlot, cf.buckets[curI][slotIdx] = cf.buckets[curI][slotIdx], curSlot
		curI = cf.altIndex(curI, curSlot.Fingerprint)

		for s := 0; s < 4; s++ {
			if cf.buckets[curI][s].Fingerprint == 0 || cf.buckets[curI][s].Count == 0 {
				cf.buckets[curI][s] = curSlot
				cf.count++
				return 1
			}
		}
	}

	// 6. Max kicks reached (table densely packed): replace lowest count slot in bucket 1
	minSlot := 0
	minCount := cf.buckets[i1][0].Count
	for s := 1; s < 4; s++ {
		if cf.buckets[i1][s].Count < minCount {
			minCount = cf.buckets[i1][s].Count
			minSlot = s
		}
	}
	cf.buckets[i1][minSlot] = CountingSlot{Fingerprint: fp, Count: 1}
	return 1
}

// Lookup returns the estimated frequency of the given key.
func (cf *CountingCuckooFilter) Lookup(key string) uint32 {
	hash := FastHash64([]byte(key))
	fp := cf.getFP(hash)
	i1 := hash & cf.mask
	i2 := cf.altIndex(i1, fp)

	cf.mu.RLock()
	defer cf.mu.RUnlock()

	for s := 0; s < 4; s++ {
		if cf.buckets[i1][s].Fingerprint == fp && cf.buckets[i1][s].Count > 0 {
			return cf.buckets[i1][s].Count
		}
	}
	for s := 0; s < 4; s++ {
		if cf.buckets[i2][s].Fingerprint == fp && cf.buckets[i2][s].Count > 0 {
			return cf.buckets[i2][s].Count
		}
	}
	return 0
}

// Decay multiplies all counters by factor (e.g. 0.5 for half-life decay).
// Slots where the count drops to 0 are reclaimed.
func (cf *CountingCuckooFilter) Decay(factor float64) {
	cf.mu.Lock()
	defer cf.mu.Unlock()

	for i := range cf.buckets {
		for s := 0; s < 4; s++ {
			if cf.buckets[i][s].Count > 0 {
				newCount := uint32(float64(cf.buckets[i][s].Count) * factor)
				if newCount == 0 {
					cf.buckets[i][s].Fingerprint = 0
					cf.buckets[i][s].Count = 0
					if cf.count > 0 {
						cf.count--
					}
				} else {
					cf.buckets[i][s].Count = newCount
				}
			}
		}
	}
}

// Reset clears all buckets and resets count to zero.
func (cf *CountingCuckooFilter) Reset() {
	cf.mu.Lock()
	defer cf.mu.Unlock()

	for i := range cf.buckets {
		cf.buckets[i] = CountingBucket{}
	}
	cf.count = 0
}

// Count returns the number of active distinct entries currently in the filter.
func (cf *CountingCuckooFilter) Count() uint64 {
	cf.mu.RLock()
	defer cf.mu.RUnlock()
	return cf.count
}
