package workers

import (
	"strconv"
	"testing"

	"github.com/dmachard/go-dnscollector/v2/dnsutils"
	"github.com/dmachard/go-dnscollector/v2/pkgconfig"
	"github.com/dmachard/go-logger"
	"github.com/prometheus/client_golang/prometheus"
)

func Benchmark_Prometheus_NewCounterSet_Default(b *testing.B) {
	config := pkgconfig.GetDefaultConfig()
	w := NewPrometheus(config, logger.New(false), "test")

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		labels := prometheus.Labels{"stream_id": "stream_" + strconv.Itoa(i)}
		_ = newPrometheusCounterSet(w, labels)
	}
}

func Benchmark_Prometheus_NewCounterSet_DisabledMetrics(b *testing.B) {
	config := pkgconfig.GetDefaultConfig()
	config.Loggers.Prometheus.RequestersMetricsEnabled = false
	config.Loggers.Prometheus.DomainsMetricsEnabled = false
	config.Loggers.Prometheus.NoErrorMetricsEnabled = false
	config.Loggers.Prometheus.ServfailMetricsEnabled = false
	config.Loggers.Prometheus.NonExistentMetricsEnabled = false
	config.Loggers.Prometheus.TimeoutMetricsEnabled = false

	w := NewPrometheus(config, logger.New(false), "test")

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		labels := prometheus.Labels{"stream_id": "stream_" + strconv.Itoa(i)}
		_ = newPrometheusCounterSet(w, labels)
	}
}

func Benchmark_Prometheus_Record(b *testing.B) {
	config := pkgconfig.GetDefaultConfig()
	w := NewPrometheus(config, logger.New(false), "test")

	dm := dnsutils.GetFakeDNSMessage()
	dm.DNS.Type = dnsutils.DNSQuery
	dm.DNS.Qname = "example.com"
	dm.DNS.Rcode = dnsutils.DNSRcodeNoError
	dm.NetworkInfo.QueryIP = "192.0.2.1"
	dm.NetworkInfo.Family = IPv4
	dm.NetworkInfo.Protocol = UDP

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		w.Record(&dm)
	}
}

func Benchmark_Prometheus_Record_Parallel(b *testing.B) {
	config := pkgconfig.GetDefaultConfig()
	w := NewPrometheus(config, logger.New(false), "test")

	b.ReportAllocs()
	b.ResetTimer()

	b.RunParallel(func(pb *testing.PB) {
		dm := dnsutils.GetFakeDNSMessage()
		dm.DNS.Type = dnsutils.DNSQuery
		dm.DNS.Qname = "example.com"
		dm.DNS.Rcode = dnsutils.DNSRcodeNoError
		dm.NetworkInfo.QueryIP = "192.0.2.1"
		dm.NetworkInfo.Family = IPv4
		dm.NetworkInfo.Protocol = UDP

		for pb.Next() {
			w.Record(&dm)
		}
	})
}

func Benchmark_Prometheus_Record_DisabledMetrics_Parallel(b *testing.B) {
	config := pkgconfig.GetDefaultConfig()
	config.Loggers.Prometheus.RequestersMetricsEnabled = false
	config.Loggers.Prometheus.DomainsMetricsEnabled = false
	config.Loggers.Prometheus.NoErrorMetricsEnabled = false
	config.Loggers.Prometheus.ServfailMetricsEnabled = false
	config.Loggers.Prometheus.NonExistentMetricsEnabled = false
	config.Loggers.Prometheus.TimeoutMetricsEnabled = false

	w := NewPrometheus(config, logger.New(false), "test")

	b.ReportAllocs()
	b.ResetTimer()

	b.RunParallel(func(pb *testing.PB) {
		dm := dnsutils.GetFakeDNSMessage()
		dm.DNS.Type = dnsutils.DNSQuery
		dm.DNS.Qname = "example.com"
		dm.DNS.Rcode = dnsutils.DNSRcodeNoError
		dm.NetworkInfo.QueryIP = "192.0.2.1"
		dm.NetworkInfo.Family = IPv4
		dm.NetworkInfo.Protocol = UDP

		for pb.Next() {
			w.Record(&dm)
		}
	})
}

func Benchmark_Prometheus_ComputeEventsPerSecond(b *testing.B) {
	config := pkgconfig.GetDefaultConfig()
	w := NewPrometheus(config, logger.New(false), "test")

	dm := dnsutils.GetFakeDNSMessage()
	dm.DNS.Type = dnsutils.DNSQuery
	dm.DNS.Qname = "example.com"
	dm.DNS.Rcode = dnsutils.DNSRcodeNoError
	dm.NetworkInfo.QueryIP = "192.0.2.1"
	dm.NetworkInfo.Family = IPv4
	dm.NetworkInfo.Protocol = UDP

	for i := 0; i < 1000; i++ {
		w.Record(&dm)
	}

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		w.ComputeEventsPerSecond()
	}
}

func Benchmark_Prometheus_Collect(b *testing.B) {
	config := pkgconfig.GetDefaultConfig()
	w := NewPrometheus(config, logger.New(false), "test")

	dm := dnsutils.GetFakeDNSMessage()
	dm.DNS.Type = dnsutils.DNSQuery
	dm.DNS.Qname = "example.com"
	dm.DNS.Rcode = dnsutils.DNSRcodeNoError
	dm.NetworkInfo.QueryIP = "192.0.2.1"
	dm.NetworkInfo.Family = IPv4
	dm.NetworkInfo.Protocol = UDP

	for i := 0; i < 1000; i++ {
		w.Record(&dm)
	}

	metricChan := make(chan prometheus.Metric, 5000)

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		for _, cs := range w.counters.GetAllCounterSets() {
			cs.Collect(metricChan)
		}
		// drain channel
		for len(metricChan) > 0 {
			<-metricChan
		}
	}
}
