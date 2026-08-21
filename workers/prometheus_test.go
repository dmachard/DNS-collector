package workers

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/dmachard/go-dnscollector/v2/dnsutils"
	"github.com/dmachard/go-dnscollector/v2/pkgconfig"
	"github.com/dmachard/go-logger"

	dto "github.com/prometheus/client_model/go"
)

const (
	UDP  = "UDP"
	IPv4 = "IPv4"
)

func TestPrometheus_BadAuth(t *testing.T) {
	// init the logger
	config := pkgconfig.GetDefaultConfig()
	g := NewPrometheus(config, logger.New(false), "test")

	tt := []struct {
		name       string
		uri        string
		handler    func(w http.ResponseWriter, r *http.Request)
		method     string
		statusCode int
	}{
		{
			name:       "total clients",
			uri:        "/metrics",
			handler:    g.httpServer.Handler.ServeHTTP,
			method:     http.MethodGet,
			statusCode: http.StatusUnauthorized,
		},
	}

	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {
			// init httptest
			request := httptest.NewRequest(tc.method, tc.uri, strings.NewReader(""))
			request.SetBasicAuth(config.Loggers.Prometheus.BasicAuthLogin, "badpassword")
			responseRecorder := httptest.NewRecorder()

			// call handler
			tc.handler(responseRecorder, request)

			// checking status code
			if responseRecorder.Code != tc.statusCode {
				t.Errorf("Want status '%d', got '%d'", tc.statusCode, responseRecorder.Code)
			}
		})
	}
}

func TestPrometheus_GetMetrics(t *testing.T) {
	// init the logger
	config := pkgconfig.GetDefaultConfig()
	config.Loggers.Prometheus.HistogramMetricsEnabled = true
	config.Loggers.Prometheus.TLDsMetricsEnabled = true

	// By default, prometheus uses 'stream_id' as the label
	t.Run("SingleLabelStreamID", getMetricsTestCase(config, map[string]string{"stream_id": "collector"}))

	config.Loggers.Prometheus.LabelsList = []string{"resolver", "stream_id"}
	t.Run("TwoLabelsStreamIDResolver", getMetricsTestCase(config, map[string]string{"resolver": "4.3.2.1", "stream_id": "collector"}))
}

// This helper generates a set of DNS packets for logger to count
// It then collects Prometheus metrics to verify they exist and have expected labels/values
// func getMetricsHelper(config *pkgconfig.Config, labels map[string]string, t *testing.T) {
func getMetricsTestCase(config *pkgconfig.Config, labels map[string]string) func(t *testing.T) {
	return func(t *testing.T) {
		g := NewPrometheus(config, logger.New(false), "test")

		// record one dns message to simulate some incoming data
		noErrorRecord := dnsutils.GetFakeDNSMessage()
		noErrorRecord.DNS.Type = dnsutils.DNSQuery
		noErrorRecord.PublicSuffix = &dnsutils.TransformPublicSuffix{
			QnamePublicSuffix: "faketld",
		}
		noErrorRecord.DNS.Flags.AA = true
		noErrorRecord.DNSTap.Latency = 0.05
		noErrorRecord.NetworkInfo.Protocol = UDP
		noErrorRecord.NetworkInfo.Family = IPv4
		noErrorRecord.DNS.Length = 123

		g.Record(&noErrorRecord)

		// compute metrics, this function is called every second
		g.ComputeEventsPerSecond()

		nxRecord := dnsutils.GetFakeDNSMessage()
		nxRecord.DNS.Type = dnsutils.DNSReply
		nxRecord.DNS.Rcode = dnsutils.DNSRcodeNXDomain
		nxRecord.NetworkInfo.Protocol = UDP
		nxRecord.NetworkInfo.Family = IPv4
		nxRecord.DNS.Length = 123
		nxRecord.DNSTap.Latency = 0.05

		g.Record(&nxRecord)

		sfRecord := dnsutils.GetFakeDNSMessage()
		sfRecord.DNS.Type = dnsutils.DNSReply
		sfRecord.DNS.Rcode = dnsutils.DNSRcodeServFail
		sfRecord.NetworkInfo.Protocol = UDP
		sfRecord.NetworkInfo.Family = IPv4
		sfRecord.DNS.Length = 123
		sfRecord.DNSTap.Latency = 0.05

		g.Record(&sfRecord)

		// Generate records for a different stream id
		noErrorRecord.DNSTap.Identity = "other_collector"
		g.Record(&noErrorRecord)

		// call ComputeMetrics for the second time, to calculate per-second metrics
		g.ComputeEventsPerSecond()
		mf := getMetrics(g, t)

		ensureMetricValue(t, mf, "dnscollector_bytes_total", labels, 369)
		ensureMetricValue(t, mf, "dnscollector_received_bytes_total", labels, 123)
		ensureMetricValue(t, mf, "dnscollector_sent_bytes_total", labels, 246)

		ensureMetricValue(t, mf, "dnscollector_throughput_ops", labels, 2)

		ensureMetricValue(t, mf, "dnscollector_total_tlds_lru", labels, 1)
		ensureMetricValue(t, mf, "dnscollector_total_requesters_lru", labels, 1)
		ensureMetricValue(t, mf, "dnscollector_total_domains_lru", labels, 1)
		ensureMetricValue(t, mf, "dnscollector_total_noerror_domains_lru", labels, 1)
		ensureMetricValue(t, mf, "dnscollector_total_nonexistent_domains_lru", labels, 1)
		ensureMetricValue(t, mf, "dnscollector_total_servfail_domains_lru", labels, 1)

		ensureMetricValue(t, mf, "dnscollector_dnsmessages_total", labels, 3)
		ensureMetricValue(t, mf, "dnscollector_queries_total", labels, 1)
		ensureMetricValue(t, mf, "dnscollector_replies_total", labels, 2)
		ensureMetricValue(t, mf, "dnscollector_flag_aa_total", labels, 1)

		labels["domain"] = "dns.collector"
		ensureMetricValue(t, mf, "dnscollector_top_domains", labels, 3)
		ensureMetricValue(t, mf, "dnscollector_top_noerror_domains", labels, 1)
		ensureMetricValue(t, mf, "dnscollector_top_nonexistent_domains", labels, 1)
		ensureMetricValue(t, mf, "dnscollector_top_servfail_domains", labels, 1)

		delete(labels, "domain")
		labels["query_type"] = "A"
		ensureMetricValue(t, mf, "dnscollector_qtypes_total", labels, 3)
		delete(labels, "query_type")
		labels["net_transport"] = "UDP"
		ensureMetricValue(t, mf, "dnscollector_ipprotocol_total", labels, 3)
		delete(labels, "net_transport")
		labels["net_family"] = "IPv4"
		ensureMetricValue(t, mf, "dnscollector_ipversion_total", labels, 3)
		delete(labels, "net_family")

		// check histogram
		ensureMetricValue(t, mf, "dnscollector_latencies", labels, 3)
	}
}

// Test that EPS (Events Per Second) Counters increment correctly
func TestPrometheus_EPS_Counters(t *testing.T) {
	config := pkgconfig.GetDefaultConfig()
	g := NewPrometheus(config, logger.New(false), "test")

	// record one dns message to simulate some incoming data
	noErrorRecord := dnsutils.GetFakeDNSMessage()
	noErrorRecord.DNS.Type = dnsutils.DNSQuery
	g.Record(&noErrorRecord)
	// Zero second elapsed, initialize EPS
	g.ComputeEventsPerSecond()
	mf := getMetrics(g, t)
	ensureMetricValue(t, mf, "dnscollector_throughput_ops", map[string]string{"stream_id": "collector"}, 0)

	// Simulate processing two more messages, that will be two events per second
	// after next ComputeEventsPerSecond call
	g.Record(&noErrorRecord)
	g.Record(&noErrorRecord)
	g.ComputeEventsPerSecond()
	mf = getMetrics(g, t)
	ensureMetricValue(t, mf, "dnscollector_throughput_ops", map[string]string{"stream_id": "collector"}, 2)
	ensureMetricValue(t, mf, "dnscollector_throughput_ops_max", map[string]string{"stream_id": "collector"}, 2)

	// During next 'second' we see only 1 event. EPS counter changes, EPS Max counter keeps its value
	g.Record(&noErrorRecord)
	g.ComputeEventsPerSecond()

	mf = getMetrics(g, t)
	ensureMetricValue(t, mf, "dnscollector_throughput_ops", map[string]string{"stream_id": "collector"}, 1)
	ensureMetricValue(t, mf, "dnscollector_throughput_ops_max", map[string]string{"stream_id": "collector"}, 2)

}

func TestPrometheus_BuildInfo(t *testing.T) {
	config := pkgconfig.GetDefaultConfig()

	g := NewPrometheus(config, logger.New(false), "test")

	mf := getMetrics(g, t)

	fmt.Println(mf)
	if !ensureMetricValue(t, mf, "dnscollector_build_info", map[string]string{}, 1) {
		t.Errorf("Cannot validate build info!")
	}

}

func TestPrometheus_ConfirmDifferentResolvers(t *testing.T) {
	config := pkgconfig.GetDefaultConfig()
	config.Loggers.Prometheus.LabelsList = []string{"resolver"}
	g := NewPrometheus(config, logger.New(false), "test")
	noErrorRecord := dnsutils.GetFakeDNSMessage()
	noErrorRecord.DNS.Length = 123
	noErrorRecord.NetworkInfo.ResponseIP = "1.2.3.4"
	g.Record(&noErrorRecord)
	noErrorRecord.DNS.Length = 999
	noErrorRecord.NetworkInfo.ResponseIP = "10.10.10.10"
	g.Record(&noErrorRecord)
	mf := getMetrics(g, t)

	ensureMetricValue(t, mf, "dnscollector_bytes_total", map[string]string{"resolver": "1.2.3.4"}, 123)
	ensureMetricValue(t, mf, "dnscollector_bytes_total", map[string]string{"resolver": "10.10.10.10"}, 999)
}

func TestPrometheus_Etldplusone(t *testing.T) {
	config := pkgconfig.GetDefaultConfig()
	config.Loggers.Prometheus.LabelsList = []string{"stream_id"}
	config.Loggers.Prometheus.TLDsMetricsEnabled = true
	g := NewPrometheus(config, logger.New(false), "test")

	noErrorRecord := dnsutils.GetFakeDNSMessage()
	noErrorRecord.DNS.Type = dnsutils.DNSQuery
	noErrorRecord.PublicSuffix = &dnsutils.TransformPublicSuffix{
		QnamePublicSuffix:        "co.uk",
		QnameEffectiveTLDPlusOne: "domain.co.uk",
	}
	noErrorRecord.DNS.Flags.AA = true
	noErrorRecord.DNSTap.Latency = 0.05
	noErrorRecord.NetworkInfo.Protocol = UDP
	noErrorRecord.NetworkInfo.Family = IPv4
	noErrorRecord.DNS.Length = 123

	g.Record(&noErrorRecord)
	// The next would be a different TLD+1
	noErrorRecord.PublicSuffix.QnameEffectiveTLDPlusOne = "anotherdomain.co.uk"
	g.Record(&noErrorRecord)

	mf := getMetrics(g, t)
	ensureMetricValue(t, mf, "dnscollector_total_etlds_plusone_lru", map[string]string{"stream_id": "collector"}, 2)
	ensureMetricValue(t, mf, "dnscollector_top_etlds_plusone", map[string]string{"stream_id": "collector", "suffix": "anotherdomain.co.uk"}, 1)
}

func TestPrometheus_Suspicious(t *testing.T) {
	config := pkgconfig.GetDefaultConfig()
	config.Loggers.Prometheus.LabelsList = []string{"stream_id"}
	config.Loggers.Prometheus.SuspiciousMetricsEnabled = true
	g := NewPrometheus(config, logger.New(false), "test")

	dm := dnsutils.GetFakeDNSMessage()
	dm.DNS.Qname = "malicious.com"
	dm.Suspicious = &dnsutils.TransformSuspicious{Score: 1.0}

	g.Record(&dm)

	mf := getMetrics(g, t)
	ensureMetricValue(t, mf, "dnscollector_total_suspicious_lru", map[string]string{"stream_id": "collector"}, 1)
	ensureMetricValue(t, mf, "dnscollector_top_suspicious", map[string]string{"stream_id": "collector", "domain": "malicious.com"}, 1)
}

func ensureMetricValue(t *testing.T, mf map[string]*dto.MetricFamily, name string, labels map[string]string, value float64) bool {
	m, found := mf[name]
	if !found {
		t.Errorf("Not found metric %v", name)
		return false
	}
	// Match labels
	for _, metric := range m.Metric {
		unmatched := len(labels)
	LBL:
		for _, lp := range metric.GetLabel() {
			if val, ok := labels[*lp.Name]; ok {
				if val == *lp.Value {
					unmatched--
				} else {
					break LBL
				}
			}
		}
		// check if we found the metric we wanted
		if unmatched == 0 {
			var pv float64
			switch m.GetType() {
			case dto.MetricType_COUNTER:
				pv = metric.GetCounter().GetValue()
				if pv == value {
					return true
				}
			case dto.MetricType_GAUGE:
				pv = metric.GetGauge().GetValue()
				if pv == value {
					return true
				}
			case dto.MetricType_HISTOGRAM:
				pv = float64(*metric.GetHistogram().SampleCount)
				if pv == value {
					return true
				}
			}
			t.Errorf("Metric %v, expected=%v, got=%v", name, value, pv)
		}
	}
	t.Errorf("Not found metric with label %v{%v}", name, labels)
	return false
}

func getMetrics(prom *Prometheus, t *testing.T) map[string]*dto.MetricFamily {
	// Gather metrics directly from the in-memory Prometheus registry to avoid
	// parsing the HTTP exposition format (which can depend on global validation
	// scheme state and cause panics in tests).
	mfs, err := prom.promRegistry.Gather()
	if err != nil {
		t.Fatalf("Error gathering prom metrics: %v", err)
	}

	mf := make(map[string]*dto.MetricFamily)
	for _, f := range mfs {
		if f == nil || f.Name == nil {
			continue
		}
		mf[f.GetName()] = f
	}
	return mf
}

func TestPrometheus_QnameInvalidChars(t *testing.T) {
	config := pkgconfig.GetDefaultConfig()
	// config.Loggers.Prometheus.HistogramMetricsEnabled = true
	g := NewPrometheus(config, logger.New(false), "test")

	// prepare qname
	qnameInvalid := "lb._dns-sd._udp.\xd0\xdfP\x01"
	qnameValidUTF8 := strings.ToValidUTF8(qnameInvalid, "�")

	// record one dns message to simulate some incoming data
	dm := dnsutils.GetFakeDNSMessage()
	dm.DNS.Qname = qnameInvalid
	g.Record(&dm)

	// record one dns message to simulate some incoming data
	dmNx := dnsutils.GetFakeDNSMessage()
	dmNx.DNS.Qname = qnameInvalid
	dmNx.DNS.Rcode = "NXDOMAIN"
	g.Record(&dmNx)

	// record one dns message to simulate some incoming data
	dmSf := dnsutils.GetFakeDNSMessage()
	dmSf.DNS.Qname = qnameInvalid
	dmSf.DNS.Rcode = "SERVFAIL"
	g.Record(&dmSf)

	mf := getMetrics(g, t)
	if !ensureMetricValue(t, mf, "dnscollector_top_domains", map[string]string{"domain": qnameValidUTF8}, 3) {
		t.Errorf("Cannot validate dnscollector_top_domains!")
	}
	if !ensureMetricValue(t, mf, "dnscollector_top_noerror_domains", map[string]string{"domain": qnameValidUTF8}, 1) {
		t.Errorf("Cannot validate dnscollector_top_noerror_domains!")
	}
	if !ensureMetricValue(t, mf, "dnscollector_top_nonexistent_domains", map[string]string{"domain": qnameValidUTF8}, 1) {
		t.Errorf("Cannot validate dnscollector_top_nonexistent_domains!")
	}
	if !ensureMetricValue(t, mf, "dnscollector_top_servfail_domains", map[string]string{"domain": qnameValidUTF8}, 1) {
		t.Errorf("Cannot validate dnscollector_top_servfail_domains!")
	}
}

func TestPrometheus_AllCounters(t *testing.T) {
	config := pkgconfig.GetDefaultConfig()
	g := NewPrometheus(config, logger.New(false), "test")

	// Message 1: Query with flags TC, AA, Malformed
	dm1 := dnsutils.GetFakeDNSMessage()
	dm1.DNS.Type = dnsutils.DNSQuery
	dm1.DNS.Length = 100
	dm1.DNS.Qtype = "A"
	dm1.DNS.Rcode = "NOERROR"
	dm1.NetworkInfo.Family = "IPv4"
	dm1.NetworkInfo.Protocol = "UDP"
	dm1.DNSTap.Operation = "CLIENT_QUERY"
	dm1.DNS.Flags.TC = true
	dm1.DNS.Flags.AA = true
	dm1.DNS.MalformedPacket = true
	g.Record(&dm1)

	// Message 2: Reply with flags RA, AD, Fragmented, Reassembled
	dm2 := dnsutils.GetFakeDNSMessage()
	dm2.DNS.Type = dnsutils.DNSReply
	dm2.DNS.Length = 200
	dm2.DNS.Qtype = "AAAA"
	dm2.DNS.Rcode = "NXDOMAIN"
	dm2.NetworkInfo.Family = "IPv6"
	dm2.NetworkInfo.Protocol = "TCP"
	dm2.DNSTap.Operation = "CLIENT_RESPONSE"
	dm2.DNS.Flags.RA = true
	dm2.DNS.Flags.AD = true
	dm2.NetworkInfo.IPDefragmented = true
	dm2.NetworkInfo.TCPReassembled = true
	g.Record(&dm2)

	mf := getMetrics(g, t)
	labels := map[string]string{"stream_id": "collector"}

	ensureMetricValue(t, mf, "dnscollector_dnsmessages_total", labels, 2)
	ensureMetricValue(t, mf, "dnscollector_queries_total", labels, 1)
	ensureMetricValue(t, mf, "dnscollector_replies_total", labels, 1)
	ensureMetricValue(t, mf, "dnscollector_bytes_total", labels, 300)
	ensureMetricValue(t, mf, "dnscollector_received_bytes_total", labels, 100)
	ensureMetricValue(t, mf, "dnscollector_sent_bytes_total", labels, 200)

	ensureMetricValue(t, mf, "dnscollector_flag_tc_total", labels, 1)
	ensureMetricValue(t, mf, "dnscollector_flag_aa_total", labels, 1)
	ensureMetricValue(t, mf, "dnscollector_flag_ra_total", labels, 1)
	ensureMetricValue(t, mf, "dnscollector_flag_ad_total", labels, 1)
	ensureMetricValue(t, mf, "dnscollector_malformed_total", labels, 1)
	ensureMetricValue(t, mf, "dnscollector_fragmented_total", labels, 1)
	ensureMetricValue(t, mf, "dnscollector_reassembled_total", labels, 1)

	ensureMetricValue(t, mf, "dnscollector_qtypes_total", map[string]string{"stream_id": "collector", "query_type": "A"}, 1)
	ensureMetricValue(t, mf, "dnscollector_qtypes_total", map[string]string{"stream_id": "collector", "query_type": "AAAA"}, 1)
	ensureMetricValue(t, mf, "dnscollector_rcodes_total", map[string]string{"stream_id": "collector", "return_code": "NOERROR"}, 1)
	ensureMetricValue(t, mf, "dnscollector_rcodes_total", map[string]string{"stream_id": "collector", "return_code": "NXDOMAIN"}, 1)
	ensureMetricValue(t, mf, "dnscollector_ipversion_total", map[string]string{"stream_id": "collector", "net_family": "IPv4"}, 1)
	ensureMetricValue(t, mf, "dnscollector_ipversion_total", map[string]string{"stream_id": "collector", "net_family": "IPv6"}, 1)
	ensureMetricValue(t, mf, "dnscollector_ipprotocol_total", map[string]string{"stream_id": "collector", "net_transport": "UDP"}, 1)
	ensureMetricValue(t, mf, "dnscollector_ipprotocol_total", map[string]string{"stream_id": "collector", "net_transport": "TCP"}, 1)
	ensureMetricValue(t, mf, "dnscollector_operations_total", map[string]string{"stream_id": "collector", "operation": "CLIENT_QUERY"}, 1)
	ensureMetricValue(t, mf, "dnscollector_operations_total", map[string]string{"stream_id": "collector", "operation": "CLIENT_RESPONSE"}, 1)
}

func TestPrometheus_ConcurrentRecord(t *testing.T) {
	config := pkgconfig.GetDefaultConfig()
	g := NewPrometheus(config, logger.New(false), "test")

	// Initialize EPS state with a first message + compute
	dmInit := dnsutils.GetFakeDNSMessage()
	g.Record(&dmInit)
	g.ComputeEventsPerSecond()

	const numGoroutines = 10
	const messagesPerGoroutine = 500

	done := make(chan bool, numGoroutines)
	for i := 0; i < numGoroutines; i++ {
		go func() {
			for j := 0; j < messagesPerGoroutine; j++ {
				dm := dnsutils.GetFakeDNSMessage()
				dm.DNS.Type = dnsutils.DNSQuery
				dm.DNS.Length = 10
				dm.DNS.Qtype = "A"
				dm.DNS.Rcode = "NOERROR"
				dm.NetworkInfo.Family = "IPv4"
				dm.NetworkInfo.Protocol = "UDP"
				dm.DNSTap.Operation = "CLIENT_QUERY"
				g.Record(&dm)
			}
			done <- true
		}()
	}

	for i := 0; i < numGoroutines; i++ {
		<-done
	}

	g.ComputeEventsPerSecond()

	mf := getMetrics(g, t)
	labels := map[string]string{"stream_id": "collector"}

	expectedTotal := float64(numGoroutines*messagesPerGoroutine + 1)
	ensureMetricValue(t, mf, "dnscollector_dnsmessages_total", labels, expectedTotal)
	ensureMetricValue(t, mf, "dnscollector_queries_total", labels, expectedTotal)
	ensureMetricValue(t, mf, "dnscollector_throughput_ops", labels, float64(numGoroutines*messagesPerGoroutine))
}
