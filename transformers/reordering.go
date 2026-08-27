package transformers

import (
	"cmp"
	"slices"
	"sync"
	"time"

	"github.com/dmachard/go-dnscollector/v3/dnsutils"
	"github.com/dmachard/go-dnscollector/v3/pkg/config"
	"github.com/dmachard/go-logger"
)

type ReorderingTransform struct {
	GenericTransformer
	config      *config.TransformReordering
	buffer      []*dnsutils.DNSMessage
	backBuffer  []*dnsutils.DNSMessage
	mutex       sync.Mutex
	flushTicker *time.Ticker
	flushSignal chan struct{}
	stopChan    chan struct{}
	nextWorkers []chan *dnsutils.DNSMessageBatch
}

// NewLogReorderTransform creates an instance of the transformer.
func NewReorderingTransform(cfg *config.TransformReordering, logger *logger.Logger, name string, instance int, nextWorkers []chan *dnsutils.DNSMessageBatch) *ReorderingTransform {
	t := &ReorderingTransform{
		config: cfg, GenericTransformer: NewTransformer(logger, "reordering", name, instance, nextWorkers),
		stopChan:    make(chan struct{}),
		flushSignal: make(chan struct{}),
		nextWorkers: nextWorkers,
	}

	return t
}

// GetTransforms returns the available subtransformations.
func (t *ReorderingTransform) GetTransforms() ([]Subtransform, error) {
	subtransforms := []Subtransform{}
	if t.config.Enable {
		subtransforms = append(subtransforms, Subtransform{name: "reordering:sort-by-timestamp", processFunc: t.ReorderLogs})
		// Start a goroutine to handle periodic flushing.
		t.flushTicker = time.NewTicker(time.Duration(t.config.FlushInterval) * time.Second)
		t.buffer = make([]*dnsutils.DNSMessage, 0, t.config.MaxBufferSize)
		t.backBuffer = make([]*dnsutils.DNSMessage, 0, t.config.MaxBufferSize)
		go t.flushPeriodically()

	}
	return subtransforms, nil
}

// ReorderLogs adds a log to the buffer and flushes if the buffer is full.
func (t *ReorderingTransform) ReorderLogs(dm *dnsutils.DNSMessage) (int, error) {
	// If Timestamp is not set (e.g. in tests or certain collectors), parse RFC3339 once.
	if dm.DNSTap.Timestamp == 0 && dm.DNSTap.TimestampRFC3339 != "" && dm.DNSTap.TimestampRFC3339 != "-" {
		if ti, err := time.Parse(time.RFC3339Nano, dm.DNSTap.TimestampRFC3339); err == nil {
			dm.DNSTap.Timestamp = ti.UnixNano()
		}
	}

	// Add the log to the buffer.
	t.mutex.Lock()
	dm.Retain(1)
	t.buffer = append(t.buffer, dm)
	isFull := len(t.buffer) >= t.config.MaxBufferSize
	t.mutex.Unlock()

	// If the buffer exceeds a certain size, flush it.
	if isFull {
		select {
		case t.flushSignal <- struct{}{}:
		default:
		}
	}

	return ReturnDrop, nil
}

// Close stops the periodic flushing.
func (t *ReorderingTransform) Reset() {
	select {
	case <-t.stopChan:
	default:
		close(t.stopChan)
	}
}

// flushPeriodically periodically flushes the buffer based on a timer.
func (t *ReorderingTransform) flushPeriodically() {
	for {
		select {
		case <-t.flushTicker.C:
			t.flushBuffer()
		case <-t.flushSignal:
			t.flushBuffer()
		case <-t.stopChan:
			t.flushTicker.Stop()
			return
		}
	}
}

// flushBuffer sorts and sends the logs in the buffer to the next workers.
func (t *ReorderingTransform) flushBuffer() {
	t.mutex.Lock()
	if len(t.buffer) == 0 {
		t.mutex.Unlock()
		return
	}

	// Swap buffers and clear the active one
	t.buffer, t.backBuffer = t.backBuffer, t.buffer
	t.buffer = t.buffer[:0]
	t.mutex.Unlock()

	// Sort the buffer by timestamp using pdqsort without reflection or allocation.
	slices.SortFunc(t.backBuffer, func(a, b *dnsutils.DNSMessage) int {
		return cmp.Compare(a.DNSTap.Timestamp, b.DNSTap.Timestamp)
	})

	// Send sorted logs to the next workers in a single batch.
	b := dnsutils.AcquireDNSMessageBatch(len(t.backBuffer))
	b.Messages = append(b.Messages, t.backBuffer...)
	if len(t.nextWorkers) > 1 {
		b.Retain(int32(len(t.nextWorkers) - 1))
	}
	for _, worker := range t.nextWorkers {
		// Non-blocking send to avoid worker congestion.
		select {
		case worker <- b:
		default:
			b.Release()
			// Log or handle if the worker channel is full.
			t.logger.Info("Worker channel is full, dropping message")
		}
	}
}
