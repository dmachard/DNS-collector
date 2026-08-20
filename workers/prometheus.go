package workers

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/dmachard/go-dnscollector/v2/dnsutils"
	"github.com/dmachard/go-dnscollector/v2/pkgconfig"
	"github.com/dmachard/go-dnscollector/v2/telemetry"
	"github.com/dmachard/go-dnscollector/v2/transformers"
	"github.com/dmachard/go-logger"
	"github.com/dmachard/go-netutils"
	"github.com/dmachard/go-topmap"
	"github.com/hashicorp/golang-lru/v2/expirable"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/collectors/version"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	// _ "net/http/pprof"
)

/*
This is the list of available label values selectors.
Configuration may specify a list of labels to use for metrics.
Any label in this catalogueSelectors can be specified in config (prometheus-labels stanza)
*/
var catalogueSelectors map[string]func(*dnsutils.DNSMessage) string = map[string]func(*dnsutils.DNSMessage) string{
	"stream_id":     GetStreamID,
	"resolver":      GetResolverIP,
	"stream_global": GetStreamGlobal,
}

type StringCounters struct {
	sync.Mutex
	val atomic.Pointer[map[string]*atomic.Uint64]
}

func newStringCounters() *StringCounters {
	sc := &StringCounters{}
	m := make(map[string]*atomic.Uint64)
	sc.val.Store(&m)
	return sc
}

func (sc *StringCounters) Inc(key string) {
	m := *sc.val.Load()
	if c, ok := m[key]; ok {
		c.Add(1)
		return
	}

	sc.Lock()
	m = *sc.val.Load()
	if c, ok := m[key]; ok {
		c.Add(1)
		sc.Unlock()
		return
	}
	newMap := make(map[string]*atomic.Uint64, len(m)+1)
	for k, v := range m {
		newMap[k] = v
	}
	c := &atomic.Uint64{}
	c.Store(1)
	newMap[key] = c
	sc.val.Store(&newMap)
	sc.Unlock()
}

func (sc *StringCounters) GetAll() map[string]float64 {
	m := *sc.val.Load()
	res := make(map[string]float64, len(m))
	for k, v := range m {
		res[k] = float64(v.Load())
	}
	return res
}

/*
EpsCounters (Events Per Second) - is a set of metrics we calculate on per-second basis.
For others we rely on averaging by collector
*/
type EpsCounters struct {
	Eps, EpsMax                  atomic.Uint64
	TotalEvents, TotalEventsPrev atomic.Uint64

	TotalRcodes, TotalQtypes                       *StringCounters
	TotalIPVersion, TotalIPProtocol                *StringCounters
	TotalOperations                                *StringCounters
	TotalDNSMessages                               atomic.Uint64
	TotalQueries, TotalReplies                     atomic.Uint64
	TotalBytes, TotalBytesSent, TotalBytesReceived atomic.Uint64

	TotalTC, TotalAA, TotalRA, TotalAD                atomic.Uint64
	TotalMalformed, TotalFragmented, TotalReassembled atomic.Uint64
}

type PrometheusCountersCatalogue interface {
	// Prometheus logger encapsulates stats counters (PrometheusCounterSet) inside
	// PromCounterCatalogueContainer's. For each label the logger creates a nested level
	// of containers.
	// Containers and CounterSets must implement PrometheusCountersCatalogue interface
	// to allow fetching a CounterSet by the list of metric/values by fetching values from
	// the DNS message it logs.
	// There is a schematic sample layout when there are two labels considered at the end of this file
	GetCountersSet(*dnsutils.DNSMessage) PrometheusCountersCatalogue
}

// This type represents a set of counters for a unique set of label name=value pairs.
// By default, we create a set per stream_id for backward compatibility
// However, we can allow slicing and dicing data using more dimensions.
// Each CounterSet is registered with Prometheus collection independently (wrapping label values)
type PrometheusCountersSet struct {
	prom *Prometheus

	// LRU cache counters per domains and IP
	requesters, allDomains             *expirable.LRU[string, int] // Requests number made by a specific requestor and to find out about a specific domain
	validDomains, nxDomains, sfDomains *expirable.LRU[string, int] // Requests number ended up  in NOERROR, NXDOMAIN and  in SERVFAIL
	tlds, etldplusone                  *expirable.LRU[string, int] // Requests number for a specific TLD and  eTLD+1
	suspicious, evicted                *expirable.LRU[string, int] // Requests number for a specific name that looked suspicious and for a specific name that timed out

	epsCounters EpsCounters

	topRequesters, topAllDomains, topEvicted    *topmap.TopMap
	topValidDomains, topSfDomains, topNxDomains *topmap.TopMap
	topTlds, topETLDPlusOne                     *topmap.TopMap
	topSuspicious                               *topmap.TopMap

	labels     prometheus.Labels // Do we really need to keep that map outside of registration?
	sync.Mutex                   // Each PrometheusCountersSet locks independently
}

// PromCounterCatalogueContainer is the implementation of PrometheusCountersCatalogue interface
// That maps a single label into other Containers or CounterSet
// The 'chain' of nested Containers keep track of labelNames requested by the config
// to figure out whether nested Container should be created, or, if all labels but the last one
// already considered at the upper levels, it is time to create individual CounterSet
type PromCounterCatalogueContainer struct {
	prom *Prometheus

	// labelNames - is a list of label *names* for PromCounterCatalogueContainer's in stats
	// map to use to get proper selectors.
	// The topmost instance of PromCounterCatalogueContainer has the full list of all names to
	// consider (the one provided by the config). Whenever it needs to create a new item in
	// it's stats map, it supplies labelNames[1:] to the constructor for the lower level
	// container to get the selector for the next level
	labelNames []string // This is list of label names for nested containers

	// This is the unique set of label-value pairs for this catalogue element.
	// The topmost Catalog has it empty, when it creates a new entry it provides the pair of
	// labelNames[0]->selector(message) to the constructor. Lower levels get these pair
	// collected. Ultimately, when all label names in labelNames is exhausted, Catalogue creates
	// an instance of newPrometheusCounterSet and provides it with labels map to properly wrap
	// in Prometheus registry.
	// The goal is to separate label/values pairs construction and individual counters collection
	labels map[string]string // This is the set of label=value pairs we collected to this level
	stats  map[string]PrometheusCountersCatalogue

	// selector is a function that obtains a value for a label considering DNS Message data
	// in most cases - just a field of that message
	selector func(*dnsutils.DNSMessage) string

	sync.RWMutex
}

/*
Selectors
*/
func GetStreamGlobal(dm *dnsutils.DNSMessage) string {
	return "enabled"
}

func GetStreamID(dm *dnsutils.DNSMessage) string {
	return dm.DNSTap.Identity
}

func GetResolverIP(dm *dnsutils.DNSMessage) string {
	return dm.NetworkInfo.ResponseIP
}

type Prometheus struct {
	*GenericWorker
	doneAPI      chan bool
	httpServer   *http.Server
	netListener  net.Listener
	promRegistry *prometheus.Registry

	sync.Mutex
	catalogueLabels []string
	counters        *PromCounterCatalogueContainer

	// All metrics use these descriptions when registering
	gaugeTopDomains, gaugeTopRequesters                        *prometheus.Desc
	gaugeTopNoerrDomains, gaugeTopNxDomains, gaugeTopSfDomains *prometheus.Desc
	gaugeTopTlds, gaugeTopETldsPlusOne                         *prometheus.Desc
	gaugeTopSuspicious, gaugeTopEvicted                        *prometheus.Desc

	gaugeDomainsAll, gaugeRequesters                  *prometheus.Desc
	gaugeDomainsValid, gaugeDomainsNx, gaugeDomainsSf *prometheus.Desc
	gaugeTlds, gaugeETldPlusOne                       *prometheus.Desc
	gaugeSuspicious, gaugeEvicted                     *prometheus.Desc

	gaugeEps, gaugeEpsMax *prometheus.Desc

	counterQtypes, counterRcodes                             *prometheus.Desc
	counterIPProtocol, counterIPVersion                      *prometheus.Desc
	counterDNSMessages, counterDNSQueries, counterDNSReplies *prometheus.Desc
	counterOperations                                        *prometheus.Desc

	counterFlagsTC, counterFlagsAA                                         *prometheus.Desc
	counterFlagsRA, counterFlagsAD                                         *prometheus.Desc
	counterFlagsMalformed, counterFlagsFragmented, counterFlagsReassembled *prometheus.Desc

	totalBytes, totalReceivedBytes, totalSentBytes *prometheus.Desc

	// Histograms are heavy and expensive, turned off
	// by default in configuration
	histogramQueriesLength, histogramRepliesLength *prometheus.HistogramVec
	histogramQnamesLength, histogramLatencies      *prometheus.HistogramVec
}

func newPrometheusCounterSet(w *Prometheus, labels prometheus.Labels) *PrometheusCountersSet {
	pcs := &PrometheusCountersSet{
		prom:   w,
		labels: labels,

		epsCounters: EpsCounters{
			TotalRcodes:     newStringCounters(),
			TotalQtypes:     newStringCounters(),
			TotalIPVersion:  newStringCounters(),
			TotalIPProtocol: newStringCounters(),
			TotalOperations: newStringCounters(),
		},
	}

	if w.GetConfig().Loggers.Prometheus.RequestersMetricsEnabled {
		pcs.requesters = expirable.NewLRU[string, int](w.GetConfig().Loggers.Prometheus.RequestersCacheSize, nil, time.Second*time.Duration(w.GetConfig().Loggers.Prometheus.RequestersCacheTTL))
		pcs.topRequesters = topmap.NewTopMap(w.GetConfig().Loggers.Prometheus.TopN)
	}
	if w.GetConfig().Loggers.Prometheus.DomainsMetricsEnabled {
		pcs.allDomains = expirable.NewLRU[string, int](w.GetConfig().Loggers.Prometheus.DomainsCacheSize, nil, time.Second*time.Duration(w.GetConfig().Loggers.Prometheus.DomainsCacheTTL))
		pcs.topAllDomains = topmap.NewTopMap(w.GetConfig().Loggers.Prometheus.TopN)
	}
	if w.GetConfig().Loggers.Prometheus.NoErrorMetricsEnabled {
		pcs.validDomains = expirable.NewLRU[string, int](w.GetConfig().Loggers.Prometheus.NoErrorDomainsCacheSize, nil, time.Second*time.Duration(w.GetConfig().Loggers.Prometheus.NoErrorDomainsCacheTTL))
		pcs.topValidDomains = topmap.NewTopMap(w.GetConfig().Loggers.Prometheus.TopN)
	}
	if w.GetConfig().Loggers.Prometheus.NonExistentMetricsEnabled {
		pcs.nxDomains = expirable.NewLRU[string, int](w.GetConfig().Loggers.Prometheus.NXDomainsCacheSize, nil, time.Second*time.Duration(w.GetConfig().Loggers.Prometheus.NXDomainsCacheTTL))
		pcs.topNxDomains = topmap.NewTopMap(w.GetConfig().Loggers.Prometheus.TopN)
	}
	if w.GetConfig().Loggers.Prometheus.ServfailMetricsEnabled {
		pcs.sfDomains = expirable.NewLRU[string, int](w.GetConfig().Loggers.Prometheus.ServfailDomainsCacheSize, nil, time.Second*time.Duration(w.GetConfig().Loggers.Prometheus.ServfailDomainsCacheTTL))
		pcs.topSfDomains = topmap.NewTopMap(w.GetConfig().Loggers.Prometheus.TopN)
	}
	if w.GetConfig().Loggers.Prometheus.TLDsMetricsEnabled {
		pcs.tlds = expirable.NewLRU[string, int](w.GetConfig().Loggers.Prometheus.DefaultDomainsCacheSize, nil, time.Second*time.Duration(w.GetConfig().Loggers.Prometheus.DefaultDomainsCacheTTL))
		pcs.etldplusone = expirable.NewLRU[string, int](w.GetConfig().Loggers.Prometheus.DefaultDomainsCacheSize, nil, time.Second*time.Duration(w.GetConfig().Loggers.Prometheus.DefaultDomainsCacheTTL))
		pcs.topTlds = topmap.NewTopMap(w.GetConfig().Loggers.Prometheus.TopN)
		pcs.topETLDPlusOne = topmap.NewTopMap(w.GetConfig().Loggers.Prometheus.TopN)
	}
	if w.GetConfig().Loggers.Prometheus.SuspiciousMetricsEnabled {
		pcs.suspicious = expirable.NewLRU[string, int](w.GetConfig().Loggers.Prometheus.DefaultDomainsCacheSize, nil, time.Second*time.Duration(w.GetConfig().Loggers.Prometheus.DefaultDomainsCacheTTL))
		pcs.topSuspicious = topmap.NewTopMap(w.GetConfig().Loggers.Prometheus.TopN)
	}
	if w.GetConfig().Loggers.Prometheus.TimeoutMetricsEnabled {
		pcs.evicted = expirable.NewLRU[string, int](w.GetConfig().Loggers.Prometheus.DefaultDomainsCacheSize, nil, time.Second*time.Duration(w.GetConfig().Loggers.Prometheus.DefaultDomainsCacheTTL))
		pcs.topEvicted = topmap.NewTopMap(w.GetConfig().Loggers.Prometheus.TopN)
	}

	prometheus.WrapRegistererWith(labels, w.promRegistry).MustRegister(pcs)
	return pcs
}

func (w *PrometheusCountersSet) GetCountersSet(dm *dnsutils.DNSMessage) PrometheusCountersCatalogue {
	return w
}

// each CounterSet has the same list of timeseries descriptors,
// so it uses descriptors from the Prometheus instance the set belongs to.
func (w *PrometheusCountersSet) Describe(ch chan<- *prometheus.Desc) {
	// Gauge metrics
	w.Lock()
	defer w.Unlock()
	if w.topAllDomains != nil {
		ch <- w.prom.gaugeTopDomains
	}
	if w.topValidDomains != nil {
		ch <- w.prom.gaugeTopNoerrDomains
	}
	if w.topNxDomains != nil {
		ch <- w.prom.gaugeTopNxDomains
	}
	if w.topSfDomains != nil {
		ch <- w.prom.gaugeTopSfDomains
	}
	if w.topRequesters != nil {
		ch <- w.prom.gaugeTopRequesters
	}
	if w.topTlds != nil {
		ch <- w.prom.gaugeTopTlds
	}
	if w.topETLDPlusOne != nil {
		ch <- w.prom.gaugeTopETldsPlusOne
	}
	if w.topSuspicious != nil {
		ch <- w.prom.gaugeTopSuspicious
	}
	if w.topEvicted != nil {
		ch <- w.prom.gaugeTopEvicted
	}

	// Counter metrics
	if w.allDomains != nil {
		ch <- w.prom.gaugeDomainsAll
	}
	if w.validDomains != nil {
		ch <- w.prom.gaugeDomainsValid
	}
	if w.nxDomains != nil {
		ch <- w.prom.gaugeDomainsNx
	}
	if w.sfDomains != nil {
		ch <- w.prom.gaugeDomainsSf
	}
	if w.requesters != nil {
		ch <- w.prom.gaugeRequesters
	}
	if w.tlds != nil {
		ch <- w.prom.gaugeTlds
	}
	if w.etldplusone != nil {
		ch <- w.prom.gaugeETldPlusOne
	}
	if w.suspicious != nil {
		ch <- w.prom.gaugeSuspicious
	}
	if w.evicted != nil {
		ch <- w.prom.gaugeEvicted
	}

	ch <- w.prom.gaugeEps
	ch <- w.prom.gaugeEpsMax

	ch <- w.prom.counterQtypes
	ch <- w.prom.counterRcodes
	ch <- w.prom.counterOperations
	ch <- w.prom.counterIPProtocol
	ch <- w.prom.counterIPVersion
	ch <- w.prom.counterDNSMessages
	ch <- w.prom.counterDNSQueries
	ch <- w.prom.counterDNSReplies

	ch <- w.prom.counterFlagsTC
	ch <- w.prom.counterFlagsAA
	ch <- w.prom.counterFlagsRA
	ch <- w.prom.counterFlagsAD
	ch <- w.prom.counterFlagsMalformed
	ch <- w.prom.counterFlagsFragmented
	ch <- w.prom.counterFlagsReassembled

	ch <- w.prom.totalBytes
	ch <- w.prom.totalReceivedBytes
	ch <- w.prom.totalSentBytes
}

// Updates all counters for a specific set of labelName=labelValue
func (w *PrometheusCountersSet) Record(dm *dnsutils.DNSMessage) {
	// count LRU caches and top maps if any enabled
	if w.requesters != nil || w.allDomains != nil || w.validDomains != nil || w.nxDomains != nil || w.sfDomains != nil || w.evicted != nil || w.tlds != nil || w.etldplusone != nil || w.suspicious != nil {
		w.Lock()
		if w.requesters != nil {
			count, _ := w.requesters.Get(dm.NetworkInfo.QueryIP)
			w.requesters.Add(dm.NetworkInfo.QueryIP, count+1)
			w.topRequesters.Record(dm.NetworkInfo.QueryIP, count+1)
		}

		if w.allDomains != nil {
			count, _ := w.allDomains.Get(dm.DNS.Qname)
			w.allDomains.Add(dm.DNS.Qname, count+1)
			w.topAllDomains.Record(dm.DNS.Qname, count+1)
		}

		switch {
		case dm.DNS.Rcode == dnsutils.DNSRcodeTimeout && w.evicted != nil:
			count, _ := w.evicted.Get(dm.DNS.Qname)
			w.evicted.Add(dm.DNS.Qname, count+1)
			w.topEvicted.Record(dm.DNS.Qname, count+1)

		case dm.DNS.Rcode == dnsutils.DNSRcodeServFail && w.sfDomains != nil:
			count, _ := w.sfDomains.Get(dm.DNS.Qname)
			w.sfDomains.Add(dm.DNS.Qname, count+1)
			w.topSfDomains.Record(dm.DNS.Qname, count+1)

		case dm.DNS.Rcode == dnsutils.DNSRcodeNXDomain && w.nxDomains != nil:
			count, _ := w.nxDomains.Get(dm.DNS.Qname)
			w.nxDomains.Add(dm.DNS.Qname, count+1)
			w.topNxDomains.Record(dm.DNS.Qname, count+1)

		case dm.DNS.Rcode == dnsutils.DNSRcodeNoError && w.validDomains != nil:
			count, _ := w.validDomains.Get(dm.DNS.Qname)
			w.validDomains.Add(dm.DNS.Qname, count+1)
			w.topValidDomains.Record(dm.DNS.Qname, count+1)
		}

		if w.tlds != nil && dm.PublicSuffix != nil && dm.PublicSuffix.QnamePublicSuffix != "-" {
			count, _ := w.tlds.Get(dm.PublicSuffix.QnamePublicSuffix)
			w.tlds.Add(dm.PublicSuffix.QnamePublicSuffix, count+1)
			w.topTlds.Record(dm.PublicSuffix.QnamePublicSuffix, count+1)
		}

		if w.etldplusone != nil && dm.PublicSuffix != nil && dm.PublicSuffix.QnameEffectiveTLDPlusOne != "-" {
			count, _ := w.etldplusone.Get(dm.PublicSuffix.QnameEffectiveTLDPlusOne)
			w.etldplusone.Add(dm.PublicSuffix.QnameEffectiveTLDPlusOne, count+1)
			w.topETLDPlusOne.Record(dm.PublicSuffix.QnameEffectiveTLDPlusOne, count+1)
		}

		if w.suspicious != nil && dm.Suspicious != nil && dm.Suspicious.Score > 0.0 {
			count, _ := w.suspicious.Get(dm.DNS.Qname)
			w.suspicious.Add(dm.DNS.Qname, count+1)
			w.topSuspicious.Record(dm.DNS.Qname, count+1)
		}
		w.Unlock()
	}

	// compute histograms, no more enabled by default to avoid to hurt performance.
	if w.prom.GetConfig().Loggers.Prometheus.HistogramMetricsEnabled {
		w.prom.histogramQnamesLength.With(w.labels).Observe(float64(len(dm.DNS.Qname)))

		if dm.DNSTap.Latency > 0.0 {
			w.prom.histogramLatencies.With(w.labels).Observe(dm.DNSTap.Latency)
		}

		if dm.DNS.Type == dnsutils.DNSQuery {
			w.prom.histogramQueriesLength.With(w.labels).Observe(float64(dm.DNS.Length))
		} else {
			w.prom.histogramRepliesLength.With(w.labels).Observe(float64(dm.DNS.Length))
		}
	}

	// Record EPS related data
	w.epsCounters.TotalEvents.Add(1)
	w.epsCounters.TotalBytes.Add(uint64(dm.DNS.Length))
	w.epsCounters.TotalDNSMessages.Add(1)

	w.epsCounters.TotalIPVersion.Inc(dm.NetworkInfo.Family)
	w.epsCounters.TotalIPProtocol.Inc(dm.NetworkInfo.Protocol)
	w.epsCounters.TotalQtypes.Inc(dm.DNS.Qtype)

	if dm.DNS.Rcode != "-" {
		w.epsCounters.TotalRcodes.Inc(dm.DNS.Rcode)
	}

	w.epsCounters.TotalOperations.Inc(dm.DNSTap.Operation)

	if dm.DNS.Type == dnsutils.DNSQuery {
		w.epsCounters.TotalBytesReceived.Add(uint64(dm.DNS.Length))
		w.epsCounters.TotalQueries.Add(1)
	}
	if dm.DNS.Type == dnsutils.DNSReply {
		w.epsCounters.TotalBytesSent.Add(uint64(dm.DNS.Length))
		w.epsCounters.TotalReplies.Add(1)
	}

	// flags
	if dm.DNS.Flags.TC {
		w.epsCounters.TotalTC.Add(1)
	}
	if dm.DNS.Flags.AA {
		w.epsCounters.TotalAA.Add(1)
	}
	if dm.DNS.Flags.RA {
		w.epsCounters.TotalRA.Add(1)
	}
	if dm.DNS.Flags.AD {
		w.epsCounters.TotalAD.Add(1)
	}
	if dm.DNS.MalformedPacket {
		w.epsCounters.TotalMalformed.Add(1)
	}
	if dm.NetworkInfo.IPDefragmented {
		w.epsCounters.TotalFragmented.Add(1)
	}
	if dm.NetworkInfo.TCPReassembled {
		w.epsCounters.TotalReassembled.Add(1)
	}
}

func (w *PrometheusCountersSet) Collect(ch chan<- prometheus.Metric) {
	w.Lock()
	defer w.Unlock()
	// Update number of all domains
	if w.allDomains != nil {
		ch <- prometheus.MustNewConstMetric(w.prom.gaugeDomainsAll, prometheus.GaugeValue,
			float64(w.allDomains.Len()),
		)
	}
	// Update number of valid domains (noerror)
	if w.validDomains != nil {
		ch <- prometheus.MustNewConstMetric(w.prom.gaugeDomainsValid, prometheus.GaugeValue,
			float64(w.validDomains.Len()),
		)
	}
	// Count NX domains
	if w.nxDomains != nil {
		ch <- prometheus.MustNewConstMetric(w.prom.gaugeDomainsNx, prometheus.GaugeValue,
			float64(w.nxDomains.Len()),
		)
	}
	// Count SERVFAIL domains
	if w.sfDomains != nil {
		ch <- prometheus.MustNewConstMetric(w.prom.gaugeDomainsSf, prometheus.GaugeValue,
			float64(w.sfDomains.Len()),
		)
	}
	// Requesters counter
	if w.requesters != nil {
		ch <- prometheus.MustNewConstMetric(w.prom.gaugeRequesters, prometheus.GaugeValue,
			float64(w.requesters.Len()),
		)
	}

	// Count number of unique TLDs
	if w.tlds != nil {
		ch <- prometheus.MustNewConstMetric(w.prom.gaugeTlds, prometheus.GaugeValue,
			float64(w.tlds.Len()),
		)
	}

	if w.etldplusone != nil {
		ch <- prometheus.MustNewConstMetric(w.prom.gaugeETldPlusOne, prometheus.GaugeValue,
			float64(w.etldplusone.Len()),
		)
	}

	// Count number of unique suspicious names
	if w.suspicious != nil {
		ch <- prometheus.MustNewConstMetric(w.prom.gaugeSuspicious, prometheus.GaugeValue,
			float64(w.suspicious.Len()),
		)
	}

	// Count number of unique unanswered (timedout) names
	if w.evicted != nil {
		ch <- prometheus.MustNewConstMetric(w.prom.gaugeEvicted, prometheus.GaugeValue,
			float64(w.evicted.Len()),
		)
	}

	// Count for all top domains
	if w.topAllDomains != nil {
		for _, r := range w.topAllDomains.Get() {
			ch <- prometheus.MustNewConstMetric(w.prom.gaugeTopDomains, prometheus.GaugeValue,
				float64(r.Hit), strings.ToValidUTF8(r.Name, "\ufffd"))
		}
	}

	if w.topValidDomains != nil {
		for _, r := range w.topValidDomains.Get() {
			ch <- prometheus.MustNewConstMetric(w.prom.gaugeTopNoerrDomains, prometheus.GaugeValue,
				float64(r.Hit), strings.ToValidUTF8(r.Name, "\ufffd"))
		}
	}

	if w.topNxDomains != nil {
		for _, r := range w.topNxDomains.Get() {
			ch <- prometheus.MustNewConstMetric(w.prom.gaugeTopNxDomains, prometheus.GaugeValue,
				float64(r.Hit), strings.ToValidUTF8(r.Name, "\ufffd"))
		}
	}

	if w.topSfDomains != nil {
		for _, r := range w.topSfDomains.Get() {
			ch <- prometheus.MustNewConstMetric(w.prom.gaugeTopSfDomains, prometheus.GaugeValue,
				float64(r.Hit), strings.ToValidUTF8(r.Name, "\ufffd"))
		}
	}

	if w.topRequesters != nil {
		for _, r := range w.topRequesters.Get() {
			ch <- prometheus.MustNewConstMetric(w.prom.gaugeTopRequesters, prometheus.GaugeValue,
				float64(r.Hit), strings.ToValidUTF8(r.Name, "\ufffd"))
		}
	}

	if w.topTlds != nil {
		for _, r := range w.topTlds.Get() {
			ch <- prometheus.MustNewConstMetric(w.prom.gaugeTopTlds, prometheus.GaugeValue,
				float64(r.Hit), strings.ToValidUTF8(r.Name, "\ufffd"))
		}
	}

	if w.topETLDPlusOne != nil {
		for _, r := range w.topETLDPlusOne.Get() {
			ch <- prometheus.MustNewConstMetric(w.prom.gaugeTopETldsPlusOne, prometheus.GaugeValue,
				float64(r.Hit), strings.ToValidUTF8(r.Name, "\ufffd"))
		}
	}

	if w.topSuspicious != nil {
		for _, r := range w.topSuspicious.Get() {
			ch <- prometheus.MustNewConstMetric(w.prom.gaugeTopSuspicious, prometheus.GaugeValue,
				float64(r.Hit), strings.ToValidUTF8(r.Name, "\ufffd"))
		}
	}

	if w.topEvicted != nil {
		for _, r := range w.topEvicted.Get() {
			ch <- prometheus.MustNewConstMetric(w.prom.gaugeTopEvicted, prometheus.GaugeValue,
				float64(r.Hit), strings.ToValidUTF8(r.Name, "\ufffd"))
		}
	}

	ch <- prometheus.MustNewConstMetric(w.prom.gaugeEps, prometheus.GaugeValue,
		float64(w.epsCounters.Eps.Load()),
	)
	ch <- prometheus.MustNewConstMetric(w.prom.gaugeEpsMax, prometheus.GaugeValue,
		float64(w.epsCounters.EpsMax.Load()),
	)

	// Update qtypes counter
	for k, v := range w.epsCounters.TotalQtypes.GetAll() {
		ch <- prometheus.MustNewConstMetric(w.prom.counterQtypes, prometheus.CounterValue,
			v, k,
		)
	}

	// Update Return Codes counter
	for k, v := range w.epsCounters.TotalRcodes.GetAll() {
		ch <- prometheus.MustNewConstMetric(w.prom.counterRcodes, prometheus.CounterValue,
			v, k,
		)
	}

	// Update DNSTap Operations counter
	for k, v := range w.epsCounters.TotalOperations.GetAll() {
		ch <- prometheus.MustNewConstMetric(w.prom.counterOperations, prometheus.CounterValue,
			v, k,
		)
	}

	// Update IP protocol counter
	for k, v := range w.epsCounters.TotalIPProtocol.GetAll() {
		ch <- prometheus.MustNewConstMetric(w.prom.counterIPProtocol, prometheus.CounterValue,
			v, k,
		)
	}

	// Update IP version counter
	for k, v := range w.epsCounters.TotalIPVersion.GetAll() {
		ch <- prometheus.MustNewConstMetric(w.prom.counterIPVersion, prometheus.CounterValue,
			v, k,
		)
	}

	// Update global number of dns messages
	ch <- prometheus.MustNewConstMetric(w.prom.counterDNSMessages, prometheus.CounterValue,
		float64(w.epsCounters.TotalDNSMessages.Load()))

	// Update number of dns queries
	ch <- prometheus.MustNewConstMetric(w.prom.counterDNSQueries, prometheus.CounterValue,
		float64(w.epsCounters.TotalQueries.Load()))

	// Update number of dns replies
	ch <- prometheus.MustNewConstMetric(w.prom.counterDNSReplies, prometheus.CounterValue,
		float64(w.epsCounters.TotalReplies.Load()))

	// Update flags
	ch <- prometheus.MustNewConstMetric(w.prom.counterFlagsTC, prometheus.CounterValue,
		float64(w.epsCounters.TotalTC.Load()))
	ch <- prometheus.MustNewConstMetric(w.prom.counterFlagsAA, prometheus.CounterValue,
		float64(w.epsCounters.TotalAA.Load()))
	ch <- prometheus.MustNewConstMetric(w.prom.counterFlagsRA, prometheus.CounterValue,
		float64(w.epsCounters.TotalRA.Load()))
	ch <- prometheus.MustNewConstMetric(w.prom.counterFlagsAD, prometheus.CounterValue,
		float64(w.epsCounters.TotalAD.Load()))
	ch <- prometheus.MustNewConstMetric(w.prom.counterFlagsMalformed, prometheus.CounterValue,
		float64(w.epsCounters.TotalMalformed.Load()))
	ch <- prometheus.MustNewConstMetric(w.prom.counterFlagsFragmented, prometheus.CounterValue,
		float64(w.epsCounters.TotalFragmented.Load()))
	ch <- prometheus.MustNewConstMetric(w.prom.counterFlagsReassembled, prometheus.CounterValue,
		float64(w.epsCounters.TotalReassembled.Load()))

	ch <- prometheus.MustNewConstMetric(w.prom.totalBytes,
		prometheus.CounterValue, float64(w.epsCounters.TotalBytes.Load()),
	)
	ch <- prometheus.MustNewConstMetric(w.prom.totalReceivedBytes, prometheus.CounterValue,
		float64(w.epsCounters.TotalBytesReceived.Load()),
	)
	ch <- prometheus.MustNewConstMetric(w.prom.totalSentBytes, prometheus.CounterValue,
		float64(w.epsCounters.TotalBytesSent.Load()))

}

func (w *PrometheusCountersSet) ComputeEventsPerSecond() {
	total := w.epsCounters.TotalEvents.Load()
	prev := w.epsCounters.TotalEventsPrev.Load()
	if total > 0 && prev > 0 && total >= prev {
		eps := total - prev
		w.epsCounters.Eps.Store(eps)
		for {
			max := w.epsCounters.EpsMax.Load()
			if eps <= max || w.epsCounters.EpsMax.CompareAndSwap(max, eps) {
				break
			}
		}
	}
	w.epsCounters.TotalEventsPrev.Store(total)
}

func NewPromCounterCatalogueContainer(w *Prometheus, selLabels []string, l map[string]string) *PromCounterCatalogueContainer {
	if len(selLabels) == 0 {
		w.LogFatal("Cannot create a new PromCounterCatalogueContainer with empty list of selLabels")
	}
	sel, ok := catalogueSelectors[selLabels[0]]
	if !ok {
		w.LogFatal(fmt.Sprintf("No selector for %v label", selLabels[0]))
	}

	// copy all the data over, to make sure this container does not share memory with other containers
	r := &PromCounterCatalogueContainer{
		prom:       w,
		stats:      make(map[string]PrometheusCountersCatalogue),
		selector:   sel,
		labelNames: make([]string, len(selLabels)),
		labels:     make(map[string]string),
	}
	for k, v := range l {
		r.labels[k] = v
	}
	copy(r.labelNames, selLabels)
	return r
}

// Returns a slice of all PrometheusCountersSet in a Container
func (w *PromCounterCatalogueContainer) GetAllCounterSets() []*PrometheusCountersSet {
	ret := []*PrometheusCountersSet{}
	w.RLock()
	for _, v := range w.stats {
		switch elem := v.(type) {
		case *PrometheusCountersSet:
			ret = append(ret, elem)
		case *PromCounterCatalogueContainer:
			ret = append(ret, elem.GetAllCounterSets()...)
		default:
			panic(fmt.Sprintf("Unexpected element in PromCounterCatalogueContainer of %T: %v", v, v))
		}
	}
	w.RUnlock()
	return ret
}

// Searches for an existing element for a label value, creating one if not found
func (w *PromCounterCatalogueContainer) GetCountersSet(dm *dnsutils.DNSMessage) PrometheusCountersCatalogue {
	if w.selector == nil {
		panic(fmt.Sprintf("%v: nil selector", w))
	}

	// w.selector fetches the value for the label *this* Catalogue Element considers.
	// Check if we already have item for it, and return it if we do (it is either catalogue or counter set)
	lbl := w.selector(dm)
	w.RLock()
	if r, ok := w.stats[lbl]; ok {
		w.RUnlock()
		return r.GetCountersSet(dm)
	}
	w.RUnlock()

	w.Lock()
	defer w.Unlock()
	if r, ok := w.stats[lbl]; ok {
		return r.GetCountersSet(dm)
	}

	// there is no existing element in the catalogue. We need to create a new entry.
	// Entry may be a new Catalogue, or PrometheusCounterSet.
	// If selector_labels consists of single element, we need to create a PrometheusCounterSet.
	// Otherwise, there is another layer of labels.
	var newElem PrometheusCountersCatalogue
	// Prepare labels for the new element (needed for ether CatalogueContainer and CounterSet)
	newLabels := map[string]string{
		w.labelNames[0]: lbl,
	}
	for k, v := range w.labels {
		newLabels[k] = v
	}
	if len(w.labelNames) > 1 {
		newElem = NewPromCounterCatalogueContainer(
			w.prom,
			w.labelNames[1:],
			newLabels, // Here we'll do an extra map copy...
		)
	} else {
		newElem = newPrometheusCounterSet(
			w.prom,
			prometheus.Labels(newLabels),
		)

	}
	w.stats[lbl] = newElem

	// GetCountersSet of the newly created element may take some time, and we will be holding the lock
	// of the current Container until it is done. This may be improved if we separate w.stats[lbl]
	// update and calling GetCountersSet on the new element.
	return w.stats[lbl].GetCountersSet(dm)
}

// This function checks the configuration, to determine which label dimensions were requested
// by configuration, and returns correct implementation of Catalogue.
func CreateSystemCatalogue(w *Prometheus) ([]string, *PromCounterCatalogueContainer) {
	lbls := w.GetConfig().Loggers.Prometheus.LabelsList

	// Default configuration is label with stream_id, to keep us backward compatible
	if len(lbls) == 0 {
		lbls = []string{"stream_id"}
	}
	return lbls, NewPromCounterCatalogueContainer(w, lbls, make(map[string]string))
}

func NewPrometheus(config *pkgconfig.Config, logger *logger.Logger, name string) *Prometheus {
	bufSize := config.Global.Worker.ChannelBufferSize
	if config.Loggers.Prometheus.ChannelBufferSize > 0 {
		bufSize = config.Loggers.Prometheus.ChannelBufferSize
	}
	w := &Prometheus{GenericWorker: NewGenericWorker(config, logger, name, "prometheus", bufSize, pkgconfig.DefaultMonitor)}
	w.doneAPI = make(chan bool)
	w.promRegistry = prometheus.NewPedanticRegistry()

	// This will create a catalogue of counters indexed by fields requested by config
	w.catalogueLabels, w.counters = CreateSystemCatalogue(w)

	// init prometheus
	w.InitProm()

	// middleware to add basic authentication
	authMiddleware := func(handler http.Handler) http.Handler {
		return http.HandlerFunc(func(httpWriter http.ResponseWriter, r *http.Request) {
			username, password, ok := r.BasicAuth()
			if !ok || username != w.GetConfig().Loggers.Prometheus.BasicAuthLogin || password != w.GetConfig().Loggers.Prometheus.BasicAuthPwd {
				httpWriter.Header().Set("WWW-Authenticate", `Basic realm="Restricted"`)
				httpWriter.WriteHeader(http.StatusUnauthorized)
				fmt.Fprintf(httpWriter, "Unauthorized\n")
				return
			}

			handler.ServeHTTP(httpWriter, r)
		})
	}

	mux := http.NewServeMux()
	mux.Handle("/metrics", promhttp.HandlerFor(w.promRegistry, promhttp.HandlerOpts{}))

	handler := authMiddleware(mux)

	w.httpServer = &http.Server{}
	if w.GetConfig().Loggers.Prometheus.BasicAuthEnabled {
		w.httpServer.Handler = handler
	} else {
		w.httpServer.Handler = mux
	}

	w.httpServer.ErrorLog = logger.ErrorLogger()
	return w
}

func (w *Prometheus) InitProm() {

	promPrefix := telemetry.SanitizeMetricName(w.GetConfig().Loggers.Prometheus.PromPrefix)

	// register metric about current version information.
	w.promRegistry.MustRegister(version.NewCollector(promPrefix))

	// export Go runtime metrics
	w.promRegistry.MustRegister(
		collectors.NewGoCollector(collectors.WithGoCollectorMemStatsMetricsDisabled()),
		collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}),
	)
	// also try collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}),

	// Metric description created in Prometheus object, but used in Describe method of PrometheusCounterSet
	// Prometheus class itself reports single metric - BuildInfo.
	w.gaugeTopDomains = prometheus.NewDesc(
		fmt.Sprintf("%s_top_domains", promPrefix),
		"Number of hit per domain topN, partitioned by qname",
		[]string{"domain"}, nil,
	)

	w.gaugeTopNoerrDomains = prometheus.NewDesc(
		fmt.Sprintf("%s_top_noerror_domains", promPrefix),
		"Number of hit per domain topN, partitioned by qname",
		[]string{"domain"}, nil,
	)

	w.gaugeTopNxDomains = prometheus.NewDesc(
		fmt.Sprintf("%s_top_nonexistent_domains", promPrefix),
		"Number of hit per nx domain topN, partitioned by qname",
		[]string{"domain"}, nil,
	)

	w.gaugeTopSfDomains = prometheus.NewDesc(
		fmt.Sprintf("%s_top_servfail_domains", promPrefix),
		"Number of hit per servfail domain topN, partitioned by stream and qname",
		[]string{"domain"}, nil,
	)

	w.gaugeTopRequesters = prometheus.NewDesc(
		fmt.Sprintf("%s_top_requesters", promPrefix),
		"Number of hit per requester topN, partitioned by client IP",
		[]string{"ip"}, nil,
	)

	w.gaugeTopTlds = prometheus.NewDesc(
		fmt.Sprintf("%s_top_tlds", promPrefix),
		"Number of hit per tld - topN",
		[]string{"suffix"}, nil,
	)
	// etldplusone_top_total
	w.gaugeTopETldsPlusOne = prometheus.NewDesc(
		fmt.Sprintf("%s_top_etlds_plusone", promPrefix),
		"Number of hit per eTLD+1 - topN",
		[]string{"suffix"}, nil,
	)

	w.gaugeTopSuspicious = prometheus.NewDesc(
		fmt.Sprintf("%s_top_suspicious", promPrefix),
		"Number of hit per suspicious domain - topN",
		[]string{"domain"}, nil,
	)

	w.gaugeTopEvicted = prometheus.NewDesc(
		fmt.Sprintf("%s_top_unanswered", promPrefix),
		"Number of hit per unanswered domain - topN",
		[]string{"domain"}, nil,
	)

	w.gaugeEps = prometheus.NewDesc(
		fmt.Sprintf("%s_throughput_ops", promPrefix),
		"Number of ops per second received, partitioned by stream",
		nil, nil,
	)

	w.gaugeEpsMax = prometheus.NewDesc(
		fmt.Sprintf("%s_throughput_ops_max", promPrefix),
		"Max number of ops per second observed, partitioned by stream",
		nil, nil,
	)

	// Counter metrics
	w.gaugeDomainsAll = prometheus.NewDesc(
		fmt.Sprintf("%s_total_domains_lru", promPrefix),
		"Total number of uniq domains most recently observed per stream identity ",
		nil, nil,
	)

	w.gaugeDomainsValid = prometheus.NewDesc(
		fmt.Sprintf("%s_total_noerror_domains_lru", promPrefix),
		"Total number of NOERROR domains most recently observed per stream identity ",
		nil, nil,
	)

	w.gaugeDomainsNx = prometheus.NewDesc(
		fmt.Sprintf("%s_total_nonexistent_domains_lru", promPrefix),
		"Total number of NX domains most recently observed per stream identity",
		nil, nil,
	)

	w.gaugeDomainsSf = prometheus.NewDesc(
		fmt.Sprintf("%s_total_servfail_domains_lru", promPrefix),
		"Total number of SERVFAIL domains most recently observed per stream identity",
		nil, nil,
	)

	w.gaugeRequesters = prometheus.NewDesc(
		fmt.Sprintf("%s_total_requesters_lru", promPrefix),
		"Total number of DNS clients most recently observed per stream identity.",
		nil, nil,
	)

	w.gaugeTlds = prometheus.NewDesc(
		fmt.Sprintf("%s_total_tlds_lru", promPrefix),
		"Total number of tld most recently observed per stream identity",
		nil, nil,
	)

	w.gaugeETldPlusOne = prometheus.NewDesc(
		fmt.Sprintf("%s_total_etlds_plusone_lru", promPrefix),
		"Total number of etld+one most recently observed per stream identity",
		nil, nil,
	)

	w.gaugeSuspicious = prometheus.NewDesc(
		fmt.Sprintf("%s_total_suspicious_lru", promPrefix),
		"Total number of suspicious domains most recently observed per stream identity",
		nil, nil,
	)

	w.gaugeEvicted = prometheus.NewDesc(
		fmt.Sprintf("%s_total_unanswered_lru", promPrefix),
		"Total number of unanswered domains most recently observed per stream identity",
		nil, nil,
	)

	w.counterQtypes = prometheus.NewDesc(
		fmt.Sprintf("%s_qtypes_total", promPrefix),
		"Counter of queries per qtypes",
		[]string{"query_type"}, nil,
	)

	w.counterRcodes = prometheus.NewDesc(
		fmt.Sprintf("%s_rcodes_total", promPrefix),
		"Counter of replies per return codes",
		[]string{"return_code"}, nil,
	)

	w.counterOperations = prometheus.NewDesc(
		fmt.Sprintf("%s_operations_total", promPrefix),
		"Counter of dns messages per operations",
		[]string{"operation"}, nil,
	)

	w.counterIPProtocol = prometheus.NewDesc(
		fmt.Sprintf("%s_ipprotocol_total", promPrefix),
		"Counter of packets per IP protocol",
		[]string{"net_transport"}, nil,
	)

	w.counterIPVersion = prometheus.NewDesc(
		fmt.Sprintf("%s_ipversion_total", promPrefix),
		"Counter of packets per IP version",
		[]string{"net_family"}, nil,
	)

	w.counterDNSMessages = prometheus.NewDesc(
		fmt.Sprintf("%s_dnsmessages_total", promPrefix),
		"Counter of DNS messages per stream",
		nil, nil,
	)

	w.counterDNSQueries = prometheus.NewDesc(
		fmt.Sprintf("%s_queries_total", promPrefix),
		"Counter of DNS queries per stream",
		nil, nil,
	)

	w.counterDNSReplies = prometheus.NewDesc(
		fmt.Sprintf("%s_replies_total", promPrefix),
		"Counter of DNS replies per stream",
		nil, nil,
	)

	w.counterFlagsTC = prometheus.NewDesc(
		fmt.Sprintf("%s_flag_tc_total", promPrefix),
		"Number of packet with flag TC",
		nil, nil,
	)

	w.counterFlagsAA = prometheus.NewDesc(
		fmt.Sprintf("%s_flag_aa_total", promPrefix),
		"Number of packet with flag AA",
		nil, nil,
	)

	w.counterFlagsRA = prometheus.NewDesc(
		fmt.Sprintf("%s_flag_ra_total", promPrefix),
		"Number of packet with flag RA",
		nil, nil,
	)

	w.counterFlagsAD = prometheus.NewDesc(
		fmt.Sprintf("%s_flag_ad_total", promPrefix),
		"Number of packet with flag AD",
		nil, nil,
	)

	w.counterFlagsMalformed = prometheus.NewDesc(
		fmt.Sprintf("%s_malformed_total", promPrefix),
		"Number of malformed packets",
		nil, nil,
	)

	w.counterFlagsFragmented = prometheus.NewDesc(
		fmt.Sprintf("%s_fragmented_total", promPrefix),
		"Number of IP fragmented packets",
		nil, nil,
	)

	w.counterFlagsReassembled = prometheus.NewDesc(
		fmt.Sprintf("%s_reassembled_total", promPrefix),
		"Number of TCP reassembled packets",
		nil, nil,
	)

	w.totalBytes = prometheus.NewDesc(
		fmt.Sprintf("%s_bytes_total", promPrefix),
		"The total bytes received and sent",
		nil, nil,
	)

	w.totalReceivedBytes = prometheus.NewDesc(
		fmt.Sprintf("%s_received_bytes_total", promPrefix),
		"The total bytes received",
		nil, nil,
	)

	w.totalSentBytes = prometheus.NewDesc(
		fmt.Sprintf("%s_sent_bytes_total", promPrefix),
		"The total bytes sent",
		nil, nil,
	)

	w.histogramQueriesLength = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    fmt.Sprintf("%s_queries_size_bytes", promPrefix),
			Help:    "Size of the queries in bytes.",
			Buckets: []float64{50, 100, 250, 500},
		},
		w.catalogueLabels,
	)
	w.promRegistry.MustRegister(w.histogramQueriesLength)

	w.histogramRepliesLength = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    fmt.Sprintf("%s_replies_size_bytes", promPrefix),
			Help:    "Size of the replies in bytes.",
			Buckets: []float64{50, 100, 250, 500},
		},
		w.catalogueLabels,
	)
	w.promRegistry.MustRegister(w.histogramRepliesLength)

	w.histogramQnamesLength = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    fmt.Sprintf("%s_qnames_size_bytes", promPrefix),
			Help:    "Size of the qname in bytes.",
			Buckets: []float64{10, 20, 40, 60, 100},
		},
		w.catalogueLabels,
	)
	w.promRegistry.MustRegister(w.histogramQnamesLength)

	w.histogramLatencies = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    fmt.Sprintf("%s_latencies", promPrefix),
			Help:    "Latency between query and reply",
			Buckets: []float64{0.001, 0.010, 0.050, 0.100, 0.5, 1.0},
		},
		w.catalogueLabels,
	)
	w.promRegistry.MustRegister(w.histogramLatencies)
}

func (w *Prometheus) ReadConfig() {
	if !netutils.IsValidTLS(w.GetConfig().Loggers.Prometheus.TLSMinVersion) {
		w.LogFatal(pkgconfig.PrefixLogWorker + "[" + w.GetName() + "] prometheus - invalid tls min version")
	}
}

func (w *Prometheus) Record(dm *dnsutils.DNSMessage) {
	// count number of dns messages per network family (ipv4 or v6)
	v := w.counters.GetCountersSet(dm)
	counterSet, ok := v.(*PrometheusCountersSet)
	if !ok {
		w.LogError(fmt.Sprintf("GetCountersSet returned an invalid value of %T, expected *PrometheusCountersSet", v))
	} else {
		counterSet.Record(dm)
	}
}

func (w *Prometheus) ComputeEventsPerSecond() {
	// for each stream compute the number of events per second
	for _, cntrSet := range w.counters.GetAllCounterSets() {
		cntrSet.ComputeEventsPerSecond()
	}
}

func (w *Prometheus) ListenAndServe() {
	w.LogInfo("starting http server...")

	var err error
	var listener net.Listener
	addrlisten := w.GetConfig().Loggers.Prometheus.ListenIP + ":" + strconv.Itoa(w.GetConfig().Loggers.Prometheus.ListenPort)
	// listening with tls enabled ?
	if w.GetConfig().Loggers.Prometheus.TLSSupport {
		w.LogInfo("tls support enabled")
		var cer tls.Certificate
		cer, err = tls.LoadX509KeyPair(w.GetConfig().Loggers.Prometheus.CertFile, w.GetConfig().Loggers.Prometheus.KeyFile)
		if err != nil {
			w.LogFatal("loading certificate failed:", err)
		}

		// prepare tls configuration
		tlsConfig := &tls.Config{
			Certificates: []tls.Certificate{cer},
			MinVersion:   tls.VersionTLS12,
		}

		// update tls min version according to the user config
		tlsConfig.MinVersion = netutils.TLSVersion[w.GetConfig().Loggers.Prometheus.TLSMinVersion]

		if w.GetConfig().Loggers.Prometheus.TLSMutual {

			// Create a CA certificate pool and add cert.pem to it
			var caCert []byte
			caCert, err = os.ReadFile(w.GetConfig().Loggers.Prometheus.CertFile)
			if err != nil {
				w.LogFatal(err)
			}
			caCertPool := x509.NewCertPool()
			caCertPool.AppendCertsFromPEM(caCert)

			tlsConfig.ClientCAs = caCertPool
			tlsConfig.ClientAuth = tls.RequireAndVerifyClientCert
		}

		listener, err = tls.Listen(netutils.SocketTCP, addrlisten, tlsConfig)

	} else {
		// basic listening
		listener, err = net.Listen(netutils.SocketTCP, addrlisten)
	}

	// something wrong ?
	if err != nil {
		w.LogFatal("http server listening failed:", err)
	}

	w.netListener = listener
	w.LogInfo("is listening on %s", listener.Addr())

	w.httpServer.Serve(w.netListener)

	w.LogInfo("http server terminated")
	w.doneAPI <- true
}

func (w *Prometheus) StartCollect() {
	w.LogInfo("starting data collection")
	defer w.CollectDone()

	// prepare next channels
	defaultRoutes, defaultNames := GetRoutes(w.GetDefaultRoutes())
	droppedRoutes, droppedNames := GetRoutes(w.GetDroppedRoutes())

	// prepare transforms
	subprocessors := transformers.NewTransforms(&w.GetConfig().OutgoingTransformers, w.GetLogger(), w.GetName(), w.GetOutputChannelAsList(), 0)

	// start http server
	go w.ListenAndServe()

	// goroutine to process transformed dns messages
	go w.StartLogging()

	// loop to process incoming messages
	for {
		select {
		case <-w.OnStop():
			w.StopLogger()
			subprocessors.Reset()
			w.LogInfo("stopping http server...")
			w.netListener.Close()
			<-w.doneAPI
			return

			// new config provided?
		case cfg := <-w.NewConfig():
			w.SetConfig(cfg)
			w.ReadConfig()
			subprocessors.ReloadConfig(&cfg.OutgoingTransformers)

		case dm, opened := <-w.GetInputChannel():
			if !opened {
				w.LogInfo("input channel closed!")
				return
			}
			// count global messages
			w.CountIngressTraffic()

			// apply transforms, init dns message with additional parts if necessary
			transformResult, err := subprocessors.ProcessMessage(dm)
			if err != nil {
				w.LogError(err.Error())
			}
			if transformResult == transformers.ReturnDrop {
				w.SendDroppedTo(droppedRoutes, droppedNames, dm)
				continue
			}

			w.SendToOutputAndForward(defaultRoutes, defaultNames, dm)
		}
	}
}

func (w *Prometheus) StartLogging() {
	w.LogInfo("logging has started")
	defer w.LoggingDone()

	// init timer to compute qps
	t1Interval := 1 * time.Second
	t1 := time.NewTimer(t1Interval)

	for {
		select {
		case <-w.OnLoggerStopped():
			return

		case dm, opened := <-w.GetOutputChannel():
			if !opened {
				w.LogInfo("output channel closed!")
				return
			}

			// record the dnstap message
			w.Record(dm)
			dm.Release()

		case <-t1.C:
			// compute eps each second
			w.ComputeEventsPerSecond()

			// reset the timer
			t1.Reset(t1Interval)
		}
	}
}

/*
This is an implementation of variadic dimensions map of label values.
Having nested structure offers the fastest operations, compared to super-flexible approach that prom client
uses with arbitrary set of labels.

Label values are obtained by the means of 'selectors' - functions that fetch a specific field of a DNS Message
offering fast operations.

Example of conterSet/Container for 2 labels

+----------------------------------------------------------------------------------------------------------+
| Container for label1                                                                                     |
| Container maps different values of label1 to other containers                                            |
| until the chain for all required label names is built.                                                   |
|                                                                                                          |
| Label1 values:                                                                                           |
|         value11                                                                 value12                  |
| +---------------------------------------------------------------------------+ +-------------------------+|
| | Container for label2                                                      | | Container for label2    ||
| | in this container ALL elements                                            | | all elements share      ||
| | have the same value for label1                                            | | the same value of label1||
| |                                                                           | |                         ||
| | Label2 values:                                                            | | +----------++----------+||
| |     value21                             value22                           | | | ....     ||  ,,,,,,  |||
| | +-----------------------------------++-----------------------------------+| | |          ||          |||
| | | CounterSet                        || CounterSet                        || | |          ||          |||
| | | In this set all metrics share the || In this set all metrics share the || | +----------++----------+||
| | | same values for both labels, so   || same values for both labels, so   || |                         ||
| | | no need to keep label values here || no need to keep label values here || |                         ||
| | |                                   ||                                   || |                         ||
| | | metric1                           || metric1                           || |                         ||
| | | metric2                           || metric2                           || |                         ||
| | +-----------------------------------++-----------------------------------+| |                         ||
| +---------------------------------------------------------------------------+ +-------------------------+|

*/
