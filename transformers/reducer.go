package transformers

import (
	"fmt"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/dmachard/go-dnscollector/v2/dnsutils"
	"github.com/dmachard/go-dnscollector/v2/pkg/config"
	"github.com/dmachard/go-logger"
	publicsuffixlist "golang.org/x/net/publicsuffix"
)

const (
	numReducerShards = 32
	shardMask        = numReducerShards - 1
	offset64         = 14695981039346656037
	prime64          = 1099511628211
)

func hashBytes64(b []byte) uint64 {
	h := uint64(offset64)
	for _, c := range b {
		h ^= uint64(c)
		h *= prime64
	}
	return h
}

type expiredKey struct {
	key     string
	expTime time.Time
}

type trafficShard struct {
	sync.Mutex
	kv          map[string]*dnsutils.DNSMessage
	expiredKeys []expiredKey
}

type MapTraffic struct {
	ttl          time.Duration
	shards       [numReducerShards]*trafficShard
	channels     []chan *dnsutils.DNSMessageBatch
	droppedCount int
	logInfo      func(msg string, v ...interface{})
	logError     func(msg string, v ...interface{})
}

func NewMapTraffic(ttl time.Duration, channels []chan *dnsutils.DNSMessageBatch,
	logInfo func(msg string, v ...interface{}), logError func(msg string, v ...interface{})) *MapTraffic {
	mp := &MapTraffic{
		ttl:      ttl,
		channels: channels,
		logInfo:  logInfo,
		logError: logError,
	}
	for i := 0; i < numReducerShards; i++ {
		mp.shards[i] = &trafficShard{
			kv:          make(map[string]*dnsutils.DNSMessage),
			expiredKeys: make([]expiredKey, 0),
		}
	}
	return mp
}

func (mp *MapTraffic) SetTTL(ttl time.Duration) {
	mp.ttl = ttl
}

func (mp *MapTraffic) Set(keyBytes []byte, dm *dnsutils.DNSMessage) {
	h := hashBytes64(keyBytes)
	s := mp.shards[h&shardMask]
	s.Lock()
	defer s.Unlock()

	// Zero-allocation map lookup with string(keyBytes) compiler optimization
	if v, ok := s.kv[string(keyBytes)]; ok {
		v.Reducer.Occurrences++
		v.Reducer.CumulativeLength += dm.DNS.Length
		return
	}

	key := string(keyBytes)
	dmCopy := *dm
	dmCopy.Reducer.Occurrences = 1
	dmCopy.Reducer.CumulativeLength = dm.DNS.Length
	dmCopy.Retain(1)
	s.kv[key] = &dmCopy

	expTime := time.Now().Add(mp.ttl)
	s.expiredKeys = append(s.expiredKeys, expiredKey{key: key, expTime: expTime})
}

func (mp *MapTraffic) Run() {
	flushTimer := time.NewTimer(mp.ttl)
	for range flushTimer.C {
		if mp.droppedCount > 0 {
			mp.logError("reducer: event(s) %d dropped, output channel full", mp.droppedCount)
			mp.droppedCount = 0
		}
		mp.ProcessExpiredKeys()
		flushTimer.Reset(mp.ttl)
	}
}

func (mp *MapTraffic) ProcessExpiredKeys() {
	now := time.Now()
	var expiredMessages []*dnsutils.DNSMessage

	for sIdx := 0; sIdx < numReducerShards; sIdx++ {
		s := mp.shards[sIdx]
		s.Lock()
		if len(s.expiredKeys) == 0 {
			s.Unlock()
			continue
		}

		idx := 0
		for idx < len(s.expiredKeys) {
			if now.Before(s.expiredKeys[idx].expTime) {
				break
			}
			idx++
		}

		if idx > 0 {
			for i := 0; i < idx; i++ {
				k := s.expiredKeys[i].key
				if v, ok := s.kv[k]; ok {
					expiredMessages = append(expiredMessages, v)
					delete(s.kv, k)
				}
			}
			copy(s.expiredKeys, s.expiredKeys[idx:])
			s.expiredKeys = s.expiredKeys[:len(s.expiredKeys)-idx]
		}
		s.Unlock()
	}

	for _, dm := range expiredMessages {
		b := dnsutils.AcquireDNSMessageBatch(1)
		b.Messages = append(b.Messages, dm)
		if len(mp.channels) > 1 {
			b.Retain(int32(len(mp.channels) - 1))
		}
		for i := range mp.channels {
			select {
			case mp.channels[i] <- b:
			default:
				b.Release()
				mp.droppedCount++
			}
		}
	}
}

type fieldID int

const (
	fieldIdentity fieldID = iota
	fieldOperation
	fieldQueryIP
	fieldResponseIP
	fieldQname
	fieldQtype
	fieldLength
	fieldID_
	fieldOpcode
	fieldRcode
	fieldQclass
	fieldFamily
	fieldProtocol
	fieldCustom
)

type fieldSpec struct {
	id  fieldID
	tag string
}

func getFieldSpec(field string) fieldSpec {
	switch field {
	case "dnstap.identity":
		return fieldSpec{id: fieldIdentity}
	case "dnstap.operation":
		return fieldSpec{id: fieldOperation}
	case "network.query-ip":
		return fieldSpec{id: fieldQueryIP}
	case "network.response-ip":
		return fieldSpec{id: fieldResponseIP}
	case "dns.qname":
		return fieldSpec{id: fieldQname}
	case "dns.qtype":
		return fieldSpec{id: fieldQtype}
	case "dns.length":
		return fieldSpec{id: fieldLength}
	case "dns.id":
		return fieldSpec{id: fieldID_}
	case "dns.opcode":
		return fieldSpec{id: fieldOpcode}
	case "dns.rcode":
		return fieldSpec{id: fieldRcode}
	case "dns.qclass":
		return fieldSpec{id: fieldQclass}
	case "network.family":
		return fieldSpec{id: fieldFamily}
	case "network.protocol":
		return fieldSpec{id: fieldProtocol}
	default:
		return fieldSpec{id: fieldCustom, tag: field}
	}
}

func appendField(f fieldSpec, dm *dnsutils.DNSMessage, buf []byte) []byte {
	switch f.id {
	case fieldIdentity:
		return append(buf, dm.DNSTap.Identity...)
	case fieldOperation:
		return append(buf, dm.DNSTap.Operation...)
	case fieldQueryIP:
		if dm.NetworkInfo.QueryIPLen > 0 {
			return append(buf, dm.NetworkInfo.QueryIPBuf[:dm.NetworkInfo.QueryIPLen]...)
		}
		return append(buf, dm.NetworkInfo.GetQueryIP()...)
	case fieldResponseIP:
		if dm.NetworkInfo.ResponseIPLen > 0 {
			return append(buf, dm.NetworkInfo.ResponseIPBuf[:dm.NetworkInfo.ResponseIPLen]...)
		}
		return append(buf, dm.NetworkInfo.GetResponseIP()...)
	case fieldQname:
		return append(buf, dm.DNS.Qname...)
	case fieldQtype:
		return append(buf, dm.DNS.Qtype...)
	case fieldLength:
		return strconv.AppendInt(buf, int64(dm.DNS.Length), 10)
	case fieldID_:
		return strconv.AppendInt(buf, int64(dm.DNS.ID), 10)
	case fieldOpcode:
		return strconv.AppendInt(buf, int64(dm.DNS.Opcode), 10)
	case fieldRcode:
		return append(buf, dm.DNS.Rcode...)
	case fieldQclass:
		return append(buf, dm.DNS.Qclass...)
	case fieldFamily:
		return append(buf, dm.NetworkInfo.Family...)
	case fieldProtocol:
		return append(buf, dm.NetworkInfo.Protocol...)
	case fieldCustom:
		dmValue := reflect.ValueOf(dm).Elem()
		if value, found := dnsutils.GetFieldByJSONTag(dmValue, f.tag); found {
			switch value.Kind() {
			case reflect.Int, reflect.String:
				return append(buf, fmt.Sprintf("%v", value.Interface())...)
			}
		}
	}
	return buf
}

type ReducerTransform struct {
	GenericTransformer
	mapTraffic *MapTraffic
	fields     []fieldSpec
}

func NewReducerTransform(cfg *config.ConfigTransformers, logger *logger.Logger, name string, instance int, nextWorkers []chan *dnsutils.DNSMessageBatch) *ReducerTransform {
	t := &ReducerTransform{GenericTransformer: NewTransformer(cfg, logger, "reducer", name, instance, nextWorkers)}
	t.mapTraffic = NewMapTraffic(time.Duration(cfg.Reducer.WatchInterval)*time.Second, nextWorkers, t.LogInfo, t.LogError)
	t.initFields(cfg.Reducer.UniqueFields)
	return t
}

func (t *ReducerTransform) initFields(fields []string) {
	t.fields = make([]fieldSpec, len(fields))
	for i, field := range fields {
		t.fields[i] = getFieldSpec(field)
	}
}

func (t *ReducerTransform) ReloadConfig(cfg *config.ConfigTransformers) {
	t.GenericTransformer.ReloadConfig(cfg)
	t.mapTraffic.SetTTL(time.Duration(cfg.Reducer.WatchInterval) * time.Second)
	t.initFields(cfg.Reducer.UniqueFields)
	t.GetTransforms()
}

func (t *ReducerTransform) GetTransforms() ([]Subtransform, error) {
	subtransforms := []Subtransform{}
	if t.config.Reducer.RepetitiveTrafficDetector {
		subtransforms = append(subtransforms, Subtransform{name: "reducer", processFunc: t.repetitiveTrafficDetector})
		go t.mapTraffic.Run()
	}
	return subtransforms, nil
}

func (t *ReducerTransform) repetitiveTrafficDetector(dm *dnsutils.DNSMessage) (int, error) {
	if dm.Reducer == nil {
		dm.Reducer = &dnsutils.TransformReducer{}
	}

	// update qname ?
	if t.config.Reducer.QnamePlusOne {
		qname := strings.ToLower(dm.DNS.Qname)
		qname = strings.TrimSuffix(qname, ".")
		if etld, err := publicsuffixlist.EffectiveTLDPlusOne(qname); err == nil {
			dm.DNS.Qname = etld
		}
	}

	var keyBuf [256]byte
	keyBytes := keyBuf[:0]
	for _, f := range t.fields {
		keyBytes = appendField(f, dm, keyBytes)
	}

	t.mapTraffic.Set(keyBytes, dm)

	return ReturnDrop, nil
}
