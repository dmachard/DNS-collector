package transformers

import (
	"container/list"
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
	channels     []chan dnsutils.DNSMessage
	expiredKeys  *list.List
	droppedCount int
	logInfo      func(msg string, v ...interface{})
	logError     func(msg string, v ...interface{})
}

func NewMapTraffic(ttl time.Duration, channels []chan dnsutils.DNSMessage,
	logInfo func(msg string, v ...interface{}), logError func(msg string, v ...interface{})) MapTraffic {
	return MapTraffic{
		ttl:         ttl,
		kv:          make(map[string]*dnsutils.DNSMessage),
		channels:    channels,
		expiredKeys: list.New(),
		logInfo:     logInfo,
		logError:    logError,
	}
}

func (mp *MapTraffic) SetTTL(ttl time.Duration) {
	mp.ttl = ttl
}

func (mp *MapTraffic) Set(key string, dm *dnsutils.DNSMessage) {
	mp.Lock()
	defer mp.Unlock()

	if v, ok := mp.kv[key]; ok {
		v.Reducer.Occurrences++
		v.Reducer.CumulativeLength += dm.DNS.Length
		return
	}

	dm.Reducer.Occurrences = 1
	dm.Reducer.CumulativeLength = dm.DNS.Length
	mp.kv[key] = dm

	expTime := time.Now().Add(mp.ttl)
	mp.expiredKeys.PushBack(expiredKey{key, expTime})
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
	var expiredMessages []*dnsutils.DNSMessage

	for e := mp.expiredKeys.Front(); e != nil; {
		expired := e.Value.(expiredKey)
		if now.Before(expired.expTime) {
			break
		}
		key := expired.key
		if v, ok := mp.kv[key]; ok {
			expiredMessages = append(expiredMessages, v)
			delete(mp.kv, key)
		}

		next := e.Next()
		mp.expiredKeys.Remove(e)
		e = next
	}
	mp.Unlock()

	for _, dm := range expiredMessages {
		for i := range mp.channels {
			mp.channels[i] <- *dm
		}
	}
}

type FieldAccessor func(dm *dnsutils.DNSMessage) string

func getAccessor(tag string) FieldAccessor {
	switch tag {
	case "dnstap.identity":
		return func(dm *dnsutils.DNSMessage) string { return dm.DNSTap.Identity }
	case "dnstap.operation":
		return func(dm *dnsutils.DNSMessage) string { return dm.DNSTap.Operation }
	case "network.query-ip":
		return func(dm *dnsutils.DNSMessage) string { return dm.NetworkInfo.QueryIP }
	case "network.response-ip":
		return func(dm *dnsutils.DNSMessage) string { return dm.NetworkInfo.ResponseIP }
	case "dns.qname":
		return func(dm *dnsutils.DNSMessage) string { return dm.DNS.Qname }
	case "dns.qtype":
		return func(dm *dnsutils.DNSMessage) string { return dm.DNS.Qtype }
	case "dns.length":
		return func(dm *dnsutils.DNSMessage) string { return strconv.Itoa(dm.DNS.Length) }
	case "dns.id":
		return func(dm *dnsutils.DNSMessage) string { return strconv.Itoa(dm.DNS.ID) }
	case "dns.opcode":
		return func(dm *dnsutils.DNSMessage) string { return strconv.Itoa(dm.DNS.Opcode) }
	case "dns.rcode":
		return func(dm *dnsutils.DNSMessage) string { return dm.DNS.Rcode }
	case "dns.qclass":
		return func(dm *dnsutils.DNSMessage) string { return dm.DNS.Qclass }
	case "network.family":
		return func(dm *dnsutils.DNSMessage) string { return dm.NetworkInfo.Family }
	case "network.protocol":
		return func(dm *dnsutils.DNSMessage) string { return dm.NetworkInfo.Protocol }
	case "network.query-port":
		return func(dm *dnsutils.DNSMessage) string { return dm.NetworkInfo.QueryPort }
	case "network.response-port":
		return func(dm *dnsutils.DNSMessage) string { return dm.NetworkInfo.ResponsePort }
	}

	// Fallback to reflection if not standard
	return func(dm *dnsutils.DNSMessage) string {
		dmValue := reflect.ValueOf(dm).Elem()
		if value, found := dnsutils.GetFieldByJSONTag(dmValue, tag); found {
			switch value.Kind() {
			case reflect.Int, reflect.String:
				return fmt.Sprintf("%v", value.Interface())
			}
		}
		return ""
	}
}

type ReducerTransform struct {
	GenericTransformer
	mapTraffic MapTraffic
	accessors  []FieldAccessor
}

func NewReducerTransform(config *pkgconfig.ConfigTransformers, logger *logger.Logger, name string, instance int, nextWorkers []chan dnsutils.DNSMessage) *ReducerTransform {
	t := &ReducerTransform{GenericTransformer: NewTransformer(config, logger, "reducer", name, instance, nextWorkers)}
	t.mapTraffic = NewMapTraffic(time.Duration(config.Reducer.WatchInterval)*time.Second, nextWorkers, t.LogInfo, t.LogError)
	t.initAccessors(config.Reducer.UniqueFields)
	return t
}

func (t *ReducerTransform) initAccessors(fields []string) {
	t.accessors = make([]FieldAccessor, len(fields))
	for i, field := range fields {
		t.accessors[i] = getAccessor(field)
	}
}

func (t *ReducerTransform) ReloadConfig(config *pkgconfig.ConfigTransformers) {
	t.GenericTransformer.ReloadConfig(config)
	t.mapTraffic.SetTTL(time.Duration(config.Reducer.WatchInterval) * time.Second)
	t.initAccessors(config.Reducer.UniqueFields)
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

	var strBuilder strings.Builder
	for _, accessor := range t.accessors {
		strBuilder.WriteString(accessor(dm))
	}

	dmTag := strBuilder.String()

	dmCopy := *dm
	t.mapTraffic.Set(dmTag, &dmCopy)

	return ReturnDrop, nil
}
