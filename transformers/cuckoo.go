package transformers

import (
	"encoding/binary"
	"math"
	"math/rand"
	"sync"
	"sync/atomic"
	"time"
)

const (
	cuckooBucketSize = 4
	cuckooMaxKicks   = 500
)

// fastHash64 implements a fast 64-bit FNV-1a hash with avalanche bit mixing.
func fastHash64(data []byte) uint64 {
	var h uint64 = 14695981039346656037
	for _, b := range data {
		h ^= uint64(b)
		h *= 1099511628211
	}
	// Murmur3 finalizer mix
	h ^= h >> 33
	h *= 0xff51afd7ed558ccd
	h ^= h >> 33
	h *= 0xc4ceb9fe1a85ec53
	h ^= h >> 33
	return h
}

// hashTuple hashes qname, rtype, and rdata in one pass without string concatenations.
func hashTuple(qname, rtype, rdata string) uint64 {
	var h uint64 = 14695981039346656037
	for i := 0; i < len(qname); i++ {
		b := qname[i]
		if b >= 'A' && b <= 'Z' {
			b += 'a' - 'A'
		}
		h ^= uint64(b)
		h *= 1099511628211
	}
	h ^= uint64('/')
	h *= 1099511628211
	for i := 0; i < len(rtype); i++ {
		h ^= uint64(rtype[i])
		h *= 1099511628211
	}
	h ^= uint64('/')
	h *= 1099511628211
	for i := 0; i < len(rdata); i++ {
		h ^= uint64(rdata[i])
		h *= 1099511628211
	}
	h ^= h >> 33
	h *= 0xff51afd7ed558ccd
	h ^= h >> 33
	h *= 0xc4ceb9fe1a85ec53
	h ^= h >> 33
	return h
}

// hashFingerprint derives a secondary bucket offset from a 16-bit fingerprint.
func hashFingerprint(fp uint16) uint64 {
	var b [2]byte
	binary.LittleEndian.PutUint16(b[:], fp)
	return fastHash64(b[:])
}

// cuckooBucket stores up to 4 16-bit fingerprints.
type cuckooBucket [cuckooBucketSize]uint16

// CuckooFilter is a compact, cache-friendly Cuckoo Filter storing 16-bit fingerprints.
type CuckooFilter struct {
	buckets []cuckooBucket
	mask    uint64
	count   uint64
}

// NewCuckooFilter creates a new Cuckoo Filter sized for expectedCapacity.
func NewCuckooFilter(expectedCapacity int) *CuckooFilter {
	if expectedCapacity < 128 {
		expectedCapacity = 128
	}
	// Calculate number of buckets (power of 2) with ~95% load factor target
	numBuckets := int(math.Ceil(float64(expectedCapacity) / float64(cuckooBucketSize)))
	// Round up to next power of 2
	n := 1
	for n < numBuckets {
		n <<= 1
	}

	return &CuckooFilter{
		buckets: make([]cuckooBucket, n),
		mask:    uint64(n - 1),
	}
}

// getIndexAndFingerprint derives the primary bucket index and 16-bit non-zero fingerprint from a 64-bit hash.
func (cf *CuckooFilter) getIndexAndFingerprint(hash uint64) (uint64, uint16) {
	fp := uint16(hash >> 48)
	if fp == 0 {
		fp = 1 // 0 represents empty slot
	}
	i1 := hash & cf.mask
	return i1, fp
}

// getAltIndex calculates the alternative bucket index for a given index and fingerprint.
func (cf *CuckooFilter) getAltIndex(i uint64, fp uint16) uint64 {
	return (i ^ hashFingerprint(fp)) & cf.mask
}

// Lookup returns true if the hash is present in the filter.
func (cf *CuckooFilter) Lookup(hash uint64) bool {
	i1, fp := cf.getIndexAndFingerprint(hash)
	// Check primary bucket
	for _, slot := range cf.buckets[i1] {
		if slot == fp {
			return true
		}
	}
	// Check secondary bucket
	i2 := cf.getAltIndex(i1, fp)
	for _, slot := range cf.buckets[i2] {
		if slot == fp {
			return true
		}
	}
	return false
}

// Insert inserts a hash into the filter. Returns false if the filter is full and cannot accommodate the key.
func (cf *CuckooFilter) Insert(hash uint64) bool {
	i1, fp := cf.getIndexAndFingerprint(hash)

	// Try inserting into primary bucket if empty slot exists
	for s := 0; s < cuckooBucketSize; s++ {
		if cf.buckets[i1][s] == 0 {
			cf.buckets[i1][s] = fp
			cf.count++
			return true
		}
	}

	// Try inserting into secondary bucket if empty slot exists
	i2 := cf.getAltIndex(i1, fp)
	for s := 0; s < cuckooBucketSize; s++ {
		if cf.buckets[i2][s] == 0 {
			cf.buckets[i2][s] = fp
			cf.count++
			return true
		}
	}

	// Cuckoo evictions (kicks)
	curIndex := i1
	curFP := fp

	for kick := 0; kick < cuckooMaxKicks; kick++ {
		// Pick random slot in current bucket to kick
		slot := rand.Intn(cuckooBucketSize)
		curFP, cf.buckets[curIndex][slot] = cf.buckets[curIndex][slot], curFP
		curIndex = cf.getAltIndex(curIndex, curFP)

		// Check if kicked item can fit into empty slot in alt bucket
		for s := 0; s < cuckooBucketSize; s++ {
			if cf.buckets[curIndex][s] == 0 {
				cf.buckets[curIndex][s] = curFP
				cf.count++
				return true
			}
		}
	}

	return false
}

// Count returns the number of items stored.
func (cf *CuckooFilter) Count() uint64 {
	return cf.count
}

// SizeBytes returns the total memory consumed by the filter table in bytes.
func (cf *CuckooFilter) SizeBytes() int {
	return len(cf.buckets) * cuckooBucketSize * 2
}

// SlidingCuckooFilter manages generational Cuckoo Filters to provide time-based expiration (TTL).
type SlidingCuckooFilter struct {
	mu           sync.RWMutex
	capacity     int
	ttl          time.Duration
	active       *CuckooFilter
	previous     *CuckooFilter
	stopChan     chan struct{}
	rotationTick time.Duration
	closed       atomic.Bool
}

// NewSlidingCuckooFilter creates a new sliding window cuckoo filter.
func NewSlidingCuckooFilter(capacity int, ttl time.Duration) *SlidingCuckooFilter {
	scf := &SlidingCuckooFilter{
		capacity:     capacity,
		ttl:          ttl,
		active:       NewCuckooFilter(capacity),
		previous:     NewCuckooFilter(capacity),
		stopChan:     make(chan struct{}),
		rotationTick: ttl / 2,
	}

	if scf.rotationTick < 1*time.Second {
		scf.rotationTick = 1 * time.Second
	}

	go scf.rotationLoop()
	return scf
}

func (scf *SlidingCuckooFilter) rotationLoop() {
	ticker := time.NewTicker(scf.rotationTick)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			scf.Rotate()
		case <-scf.stopChan:
			return
		}
	}
}

// Rotate moves active filter to previous and allocates a clean active filter.
func (scf *SlidingCuckooFilter) Rotate() {
	scf.mu.Lock()
	defer scf.mu.Unlock()

	scf.previous = scf.active
	scf.active = NewCuckooFilter(scf.capacity)
}

// Lookup checks if a hash is known in the active or previous sliding window.
func (scf *SlidingCuckooFilter) Lookup(hash uint64) bool {
	scf.mu.RLock()
	defer scf.mu.RUnlock()

	if scf.active.Lookup(hash) {
		return true
	}
	return scf.previous.Lookup(hash)
}

// TestAndAdd checks if a hash is new; if new, it adds it to the active window and returns true.
func (scf *SlidingCuckooFilter) TestAndAdd(hash uint64) bool {
	scf.mu.Lock()
	defer scf.mu.Unlock()

	if scf.active.Lookup(hash) {
		return false
	}
	if scf.previous.Lookup(hash) {
		return false
	}

	scf.active.Insert(hash)
	return true
}

// Close terminates background rotation.
func (scf *SlidingCuckooFilter) Close() {
	if scf.closed.CompareAndSwap(false, true) {
		close(scf.stopChan)
	}
}

// SizeBytes returns the approximate total memory in bytes used by the sliding filters.
func (scf *SlidingCuckooFilter) SizeBytes() int {
	scf.mu.RLock()
	defer scf.mu.RUnlock()
	return scf.active.SizeBytes() + scf.previous.SizeBytes()
}
