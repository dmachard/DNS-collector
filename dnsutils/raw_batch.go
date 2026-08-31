package dnsutils

import "sync"

const DefaultRawBatchSize = 512

type RawBatch struct {
	Frames [][]byte
}

var RawBatchPool = sync.Pool{
	New: func() interface{} {
		return &RawBatch{
			Frames: make([][]byte, 0, DefaultRawBatchSize),
		}
	},
}

func AcquireRawBatch() *RawBatch {
	b := RawBatchPool.Get().(*RawBatch)
	b.Frames = b.Frames[:0]
	return b
}

func (b *RawBatch) Release() {
	if b == nil {
		return
	}
	if cap(b.Frames) > 1024 {
		b.Frames = make([][]byte, 0, DefaultRawBatchSize)
	} else {
		b.Frames = b.Frames[:0]
	}
	RawBatchPool.Put(b)
}
