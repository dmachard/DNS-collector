package transformers

import (
	"fmt"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/dmachard/go-dnscollector/v2/dnsutils"
	"github.com/dmachard/go-dnscollector/v2/pkgconfig"
	"github.com/dmachard/go-logger"
	publicsuffixlist "golang.org/x/net/publicsuffix"
)

type expiredKey struct {
	key     string
	expTime time.Time
}

type MapTraffic struct {
	sync.RWMutex
	ttl          time.Duration
	kv           map[string]*dnsutils.DNSMessage
	channels     []chan *dnsutils.DNSMessageBatch
	expiredKeys  []expiredKey
	droppedCount int
	logInfo      func(msg string, v ...interface{})
	logError     func(msg string, v ...interface{})
}

func NewMapTraffic(ttl time.Duration, channels []chan *dnsutils.DNSMessageBatch,
	logInfo func(msg string, v ...interface{}), logError func(msg string, v ...interface{})) MapTraffic {
	return MapTraffic{
		ttl:         ttl,
		kv:          make(map[string]*dnsutils.DNSMessage),
		channels:    channels,
		expiredKeys: make([]expiredKey, 0),
		logInfo:     logInfo,
		logError:    logError,
	}
}

func (mp *MapTraffic) SetTTL(ttl time.Duration) {
	mp.ttl = ttl
}

func (mp *MapTraffic) Set(keyBytes []byte, dm *dnsutils.DNSMessage) {
	mp.Lock()
	defer mp.Unlock()

	// Zero-allocation map lookup with string(keyBytes) compiler optimization
	if v, ok := mp.kv[string(keyBytes)]; ok {
		v.Reducer.Occurrences++
		v.Reducer.CumulativeLength += dm.DNS.Length
		return
	}

	key := string(keyBytes)
	dmCopy := *dm
	dmCopy.Reducer.Occurrences = 1
	dmCopy.Reducer.CumulativeLength = dm.DNS.Length
	dmCopy.Retain(1)
	mp.kv[key] = &dmCopy

	expTime := time.Now().Add(mp.ttl)
	mp.expiredKeys = append(mp.expiredKeys, expiredKey{key: key, expTime: expTime})
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
	mp.Lock()
	now := time.Now()
	if len(mp.expiredKeys) == 0 {
		mp.Unlock()
		return
	}

	idx := 0
	for idx < len(mp.expiredKeys) {
		if now.Before(mp.expiredKeys[idx].expTime) {
			break
		}
		idx++
	}

	if idx == 0 {
		mp.Unlock()
		return
	}

	expiredMessages := make([]*dnsutils.DNSMessage, 0, idx)
	for i := 0; i < idx; i++ {
		key := mp.expiredKeys[i].key
		if v, ok := mp.kv[key]; ok {
			expiredMessages = append(expiredMessages, v)
			delete(mp.kv, key)
		}
	}
	copy(mp.expiredKeys, mp.expiredKeys[idx:])
	mp.expiredKeys = mp.expiredKeys[:len(mp.expiredKeys)-idx]
	mp.Unlock()

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

const (
	fieldIdentity = iota + 1
	fieldOperation
	fieldQueryIP
	fieldResponseIP
	fieldQname
	fieldQtype
	fieldLength
	fieldID
	fieldOpcode
	fieldRcode
	fieldQclass
	fieldFamily
	fieldProtocol
	fieldQueryPort
	fieldResponsePort
	fieldCustom
)

type fieldSpec struct {
	id  int
	tag string
}

func getFieldSpec(tag string) fieldSpec {
	switch tag {
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
		return fieldSpec{id: fieldID}
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
	case "network.query-port":
		return fieldSpec{id: fieldQueryPort}
	case "network.response-port":
		return fieldSpec{id: fieldResponsePort}
	default:
		return fieldSpec{id: fieldCustom, tag: tag}
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
	case fieldID:
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
	case fieldQueryPort:
		return append(buf, dm.NetworkInfo.QueryPort...)
	case fieldResponsePort:
		return append(buf, dm.NetworkInfo.ResponsePort...)
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
	mapTraffic MapTraffic
	fields     []fieldSpec
}

func NewReducerTransform(config *pkgconfig.ConfigTransformers, logger *logger.Logger, name string, instance int, nextWorkers []chan *dnsutils.DNSMessageBatch) *ReducerTransform {
	t := &ReducerTransform{GenericTransformer: NewTransformer(config, logger, "reducer", name, instance, nextWorkers)}
	t.mapTraffic = NewMapTraffic(time.Duration(config.Reducer.WatchInterval)*time.Second, nextWorkers, t.LogInfo, t.LogError)
	t.initFields(config.Reducer.UniqueFields)
	return t
}

func (t *ReducerTransform) initFields(fields []string) {
	t.fields = make([]fieldSpec, len(fields))
	for i, field := range fields {
		t.fields[i] = getFieldSpec(field)
	}
}

func (t *ReducerTransform) ReloadConfig(config *pkgconfig.ConfigTransformers) {
	t.GenericTransformer.ReloadConfig(config)
	t.mapTraffic.SetTTL(time.Duration(config.Reducer.WatchInterval) * time.Second)
	t.initFields(config.Reducer.UniqueFields)
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
