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
		cuckooFilter:       cuckoo.NewCountingCuckooFilter(cfg.MaxCapacity),
		stopChan:           make(chan struct{}),
	}
	if cfg.Enable && cfg.TTL > 0 {
		go t.decayLoop()
	}
	return t
}

func (t *FrequencyFilteringTransform) decayLoop() {
	ticker := time.NewTicker(time.Duration(t.config.TTL) * time.Second)
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
	switch t.config.Target {
	case "domain":
		if dm.PublicSuffix != nil && len(dm.PublicSuffix.QnameEffectiveTLDPlusOne) > 0 {
			key = dm.PublicSuffix.QnameEffectiveTLDPlusOne
		} else {
			key = dm.DNS.Qname
		}
	case "client-ip", "query-ip":
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
	isHeavy := int(count) > t.config.ThresholdHeavy

	var tier string
	switch {
	case isHeavy:
		tier = "heavy"
	case count == 1:
		tier = "rare"
	default:
		tier = "frequent"
	}

	dm.Frequency = &dnsutils.TransformFrequency{
		Count:         int(count),
		IsHeavyHitter: isHeavy,
		Tier:          tier,
		Target:        key,
	}

	if !isHeavy {
		return ReturnKeep, nil
	}

	// Action when Heavy Hitter
	switch t.config.ActionOnHeavy {
	case "tag", "keep":
		return ReturnKeep, nil
	case "sample":
		if t.config.SampleRate <= 0 {
			return ReturnDrop, nil
		}
		cur := atomic.AddUint64(&t.sampleCounter, 1)
		if cur%uint64(t.config.SampleRate) == 0 {
			return ReturnKeep, nil
		}
		return ReturnDrop, nil
	case "drop":
		fallthrough
	default:
		return ReturnDrop, nil
	}
}
