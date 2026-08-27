package transformers

import (
	"sync/atomic"
	"time"

	"github.com/dmachard/go-dnscollector/v3/dnsutils"
	"github.com/dmachard/go-dnscollector/v3/pkg/config"
	"github.com/dmachard/go-dnscollector/v3/pkg/cuckoo"
	"github.com/dmachard/go-logger"
)

type FrequencyFilteringTransform struct {
	GenericTransformer
	config        *config.TransformFrequencyFiltering
	cuckooFilter  *cuckoo.CountingCuckooFilter
	stopChan      chan struct{}
	sampleCounter uint64
}

func NewFrequencyFilteringTransform(cfg *config.TransformFrequencyFiltering, logger *logger.Logger, name string, instance int, nextWorkers []chan *dnsutils.DNSMessageBatch) *FrequencyFilteringTransform {
	t := &FrequencyFilteringTransform{
		GenericTransformer: NewTransformer(logger, "frequency-filtering", name, instance, nextWorkers),
		config:             cfg,
		cuckooFilter:       cuckoo.NewCountingCuckooFilter(cfg.Capacity),
		stopChan:           make(chan struct{}),
	}
	if cfg.Enable && cfg.WindowSeconds > 0 {
		go t.decayLoop()
	}
	return t
}

func (t *FrequencyFilteringTransform) decayLoop() {
	ticker := time.NewTicker(time.Duration(t.config.WindowSeconds) * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			t.cuckooFilter.Decay(0.5)
		case <-t.stopChan:
			return
		}
	}
}

func (t *FrequencyFilteringTransform) Stop() {
	select {
	case <-t.stopChan:
		// already closed
	default:
		close(t.stopChan)
	}
}

func (t *FrequencyFilteringTransform) GetTransforms() ([]Subtransform, error) {
	subtransforms := []Subtransform{}
	if t.config.Enable {
		subtransforms = append(subtransforms, Subtransform{name: "frequency-filtering:filter", processFunc: t.filterFrequency})
	}
	return subtransforms, nil
}

func (t *FrequencyFilteringTransform) filterFrequency(dm *dnsutils.DNSMessage) (int, error) {
	var key string
	switch t.config.TrackBy {
	case "domain":
		if dm.PublicSuffix != nil && len(dm.PublicSuffix.QnameEffectiveTLDPlusOne) > 0 {
			key = dm.PublicSuffix.QnameEffectiveTLDPlusOne
		} else {
			key = dm.DNS.Qname
		}
	case "query-ip":
		key = dm.NetworkInfo.QueryIP
	case "qname":
		fallthrough
	default:
		key = dm.DNS.Qname
	}

	if len(key) == 0 || key == "-" {
		return ReturnKeep, nil
	}

	count := t.cuckooFilter.Increment(key)
	isHeavy := int(count) > t.config.Threshold

	dm.Frequency = &dnsutils.TransformFrequency{
		Count:         int(count),
		IsHeavyHitter: isHeavy,
		TrackedKey:    key,
	}

	if !isHeavy || t.config.TagOnly {
		return ReturnKeep, nil
	}

	// Heavy hitter and not TagOnly:
	if t.config.SampleRate <= 0 {
		return ReturnDrop, nil
	}

	cur := atomic.AddUint64(&t.sampleCounter, 1)
	if cur%uint64(t.config.SampleRate) == 0 {
		return ReturnKeep, nil
	}

	return ReturnDrop, nil
}
