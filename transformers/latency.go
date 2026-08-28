package transformers

import (
	"hash/fnv"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/dmachard/go-dnscollector/v3/dnsutils"
	"github.com/dmachard/go-dnscollector/v3/pkg/config"
	"github.com/dmachard/go-logger"
)

// queries map
type MapQueries struct {
	sync.RWMutex
	ttl      time.Duration
	kv       map[uint64]*dnsutils.DNSMessage
	channels []chan *dnsutils.DNSMessageBatch
}

func NewMapQueries(ttl time.Duration, channels []chan *dnsutils.DNSMessageBatch) MapQueries {
	return MapQueries{
		ttl:      ttl,
		kv:       make(map[uint64]*dnsutils.DNSMessage),
		channels: channels,
	}
}

func (mp *MapQueries) SetTTL(ttl time.Duration) {
	mp.ttl = ttl
}

func (mp *MapQueries) Exists(key uint64) (ok bool) {
	mp.RLock()
	defer mp.RUnlock()
	_, ok = mp.kv[key]
	return ok
}

func (mp *MapQueries) Set(key uint64, dm *dnsutils.DNSMessage) {
	mp.Lock()
	defer mp.Unlock()
	dm.Retain(1)
	mp.kv[key] = dm
	time.AfterFunc(mp.ttl, func() {
		mp.Lock()
		targetDM, exists := mp.kv[key]
		if exists {
			delete(mp.kv, key)
		}
		mp.Unlock()

		if exists {
			targetDM.DNS.Rcode = "TIMEOUT"
			b := dnsutils.AcquireDNSMessageBatch(1)
			b.Messages = append(b.Messages, targetDM)
			if len(mp.channels) > 1 {
				b.Retain(int32(len(mp.channels) - 1))
			}
			for i := range mp.channels {
				select {
				case mp.channels[i] <- b:
				default:
					b.Release()
				}
			}
		}
	})
}

func (mp *MapQueries) Delete(key uint64) {
	mp.Lock()
	defer mp.Unlock()
	if dm, ok := mp.kv[key]; ok {
		delete(mp.kv, key)
		dm.Release()
	}
}

// hash queries map
type HashQueries struct {
	sync.RWMutex
	ttl time.Duration
	kv  map[uint64]int64
}

func NewHashQueries(ttl time.Duration) HashQueries {
	return HashQueries{
		ttl: ttl,
		kv:  make(map[uint64]int64),
	}
}

func (mp *HashQueries) SetTTL(ttl time.Duration) {
	mp.ttl = ttl
}

func (mp *HashQueries) Get(key uint64) (value int64, ok bool) {
	mp.RLock()
	defer mp.RUnlock()
	result, ok := mp.kv[key]
	return result, ok
}

func (mp *HashQueries) Set(key uint64, value int64) {
	mp.Lock()
	defer mp.Unlock()
	mp.kv[key] = value
	time.AfterFunc(mp.ttl, func() {
		mp.Delete(key)
	})
}

func (mp *HashQueries) Delete(key uint64) {
	mp.Lock()
	defer mp.Unlock()
	delete(mp.kv, key)
}

// latency transformer
type LatencyTransform struct {
	GenericTransformer
	config      *config.TransformLatency
	hashQueries HashQueries
	mapQueries  MapQueries
}

func NewLatencyTransform(cfg *config.TransformLatency, logger *logger.Logger, name string, instance int, nextWorkers []chan *dnsutils.DNSMessageBatch) *LatencyTransform {
	t := &LatencyTransform{config: cfg, GenericTransformer: NewTransformer(logger, "latency", name, instance, nextWorkers)}
	t.hashQueries = NewHashQueries(time.Duration(cfg.QueriesTimeout) * time.Second)
	t.mapQueries = NewMapQueries(time.Duration(cfg.QueriesTimeout)*time.Second, nextWorkers)
	return t
}

func (t *LatencyTransform) GetTransforms() ([]Subtransform, error) {
	t.hashQueries.SetTTL(time.Duration(t.config.QueriesTimeout) * time.Second)
	t.mapQueries.SetTTL(time.Duration(t.config.QueriesTimeout) * time.Second)

	subtransforms := []Subtransform{}
	if t.config.MeasureLatency {
		subtransforms = append(subtransforms, Subtransform{name: "latency:add", processFunc: t.measureLatency})
	}
	if t.config.UnansweredQueries {
		subtransforms = append(subtransforms, Subtransform{name: "latency:timeout", processFunc: t.detectEvictedTimeout})
	}
	return subtransforms, nil
}

func (t *LatencyTransform) measureLatency(dm *dnsutils.DNSMessage) (int, error) {
	queryIP := dm.NetworkInfo.GetQueryIP()
	queryport, _ := strconv.Atoi(dm.NetworkInfo.QueryPort)
	if len(queryIP) > 0 && queryIP != "-" && queryport > 0 && !dm.DNS.MalformedPacket {
		// compute the hash of the query
		hashData := []string{queryIP, dm.NetworkInfo.QueryPort, strconv.Itoa(dm.DNS.ID)}

		hashfnv := fnv.New64a()
		hashfnv.Write([]byte(strings.Join(hashData, "+")))

		if dm.DNS.Type == dnsutils.DNSQuery || dm.DNS.Type == dnsutils.DNSQueryQuiet {
			t.hashQueries.Set(hashfnv.Sum64(), dm.DNSTap.Timestamp)
		} else {
			key := hashfnv.Sum64()
			value, ok := t.hashQueries.Get(key)
			if ok {
				t.hashQueries.Delete(key)
				latency := float64(dm.DNSTap.Timestamp-value) / float64(1000000000)
				dm.DNSTap.Latency = latency
				dm.DNSTap.LatencyMs = int(latency * 1000)
			}
		}
	}
	return ReturnKeep, nil
}

func (t *LatencyTransform) detectEvictedTimeout(dm *dnsutils.DNSMessage) (int, error) {
	queryIP := dm.NetworkInfo.GetQueryIP()
	queryport, _ := strconv.Atoi(dm.NetworkInfo.QueryPort)
	if len(queryIP) > 0 && queryIP != "-" && queryport > 0 && !dm.DNS.MalformedPacket {
		// compute the hash of the query
		hashData := []string{queryIP, dm.NetworkInfo.QueryPort, strconv.Itoa(dm.DNS.ID)}

		hashfnv := fnv.New64a()
		hashfnv.Write([]byte(strings.Join(hashData, "+")))
		key := hashfnv.Sum64()

		if dm.DNS.Type == dnsutils.DNSQuery || dm.DNS.Type == dnsutils.DNSQueryQuiet {
			t.mapQueries.Set(key, dm)
		} else if t.mapQueries.Exists(key) {
			t.mapQueries.Delete(key)
		}
	}
	return ReturnKeep, nil
}
