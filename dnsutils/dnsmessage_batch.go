package dnsutils

import (
	"sync"
	"sync/atomic"
)

// DNSMessageBatch represents a contiguous batch of DNSMessage pointers
// transported across worker channels to amortize synchronization overhead.
type DNSMessageBatch struct {
	Messages []*DNSMessage
	RefCount int32
}

var DNSMessageBatchPool = sync.Pool{
	New: func() interface{} {
		return &DNSMessageBatch{
			Messages: make([]*DNSMessage, 0, 64),
		}
	},
}

func AcquireDNSMessageBatch(capacity int) *DNSMessageBatch {
	batch := DNSMessageBatchPool.Get().(*DNSMessageBatch)
	if capacity > cap(batch.Messages) {
		batch.Messages = make([]*DNSMessage, 0, capacity)
	} else {
		batch.Messages = batch.Messages[:0]
	}
	atomic.StoreInt32(&batch.RefCount, 1)
	return batch
}

func NewDNSMessageBatchFromMessage(dm *DNSMessage) *DNSMessageBatch {
	b := AcquireDNSMessageBatch(1)
	b.Messages = append(b.Messages, dm)
	return b
}

func (b *DNSMessageBatch) Retain(n int32) {
	if n > 0 {
		atomic.AddInt32(&b.RefCount, n)
	}
}

func (b *DNSMessageBatch) Release() {
	if b == nil {
		return
	}
	if atomic.AddInt32(&b.RefCount, -1) == 0 {
		for _, dm := range b.Messages {
			dm.Release()
		}
		b.Messages = b.Messages[:0]
		DNSMessageBatchPool.Put(b)
	}
}
