package workers

import (
	"testing"

	"github.com/dmachard/go-dnscollector/v2/pkgconfig"
	"github.com/dmachard/go-logger"
)

func TestRegistry_LoggersCount(t *testing.T) {
	loggers := GetRegisteredLoggers()
	if len(loggers) < 21 {
		t.Errorf("expected at least 21 registered loggers, got %d", len(loggers))
	}

	expectedLoggers := []string{
		"restapi", "prometheus", "stdout", "logfile", "dnstap",
		"tcpclient", "syslog", "fluentd", "influxdb", "lokiclient",
		"statsd", "nsq", "elasticsearch", "scalyr", "redispub",
		"kafkaproducer", "falco", "clickhouse", "devnull",
		"opentelemetry", "mqtt",
	}

	for _, name := range expectedLoggers {
		if reg, exists := loggers[name]; !exists {
			t.Errorf("expected logger %q to be registered", name)
		} else if reg.Factory == nil {
			t.Errorf("logger %q has nil factory", name)
		} else if reg.IsEnabled == nil {
			t.Errorf("logger %q has nil IsEnabled check", name)
		}
	}
}

func TestRegistry_CollectorsCount(t *testing.T) {
	collectors := GetRegisteredCollectors()
	if len(collectors) < 10 {
		t.Errorf("expected at least 10 registered collectors, got %d", len(collectors))
	}

	expectedCollectors := []string{
		"dnsmessage", "dnstap", "dnstap-proxifier", "afpacket-sniffer",
		"xdp-sniffer", "tail", "powerdns", "file-ingestor", "tzsp", "webhook",
	}

	for _, name := range expectedCollectors {
		if reg, exists := collectors[name]; !exists {
			t.Errorf("expected collector %q to be registered", name)
		} else if reg.Factory == nil {
			t.Errorf("collector %q has nil factory", name)
		} else if reg.IsEnabled == nil {
			t.Errorf("collector %q has nil IsEnabled check", name)
		}
	}
}

func TestRegistry_CustomRegistration(t *testing.T) {
	dummyCalled := false
	RegisterLogger("dummy-test-logger", func(c *pkgconfig.Config) bool {
		return true
	}, func(c *pkgconfig.Config, l *logger.Logger, s string) Worker {
		dummyCalled = true
		return nil
	})

	loggers := GetRegisteredLoggers()
	reg, ok := loggers["dummy-test-logger"]
	if !ok {
		t.Fatalf("custom logger not found in registry")
	}

	if !reg.IsEnabled(nil) {
		t.Errorf("custom logger IsEnabled returned false")
	}

	_ = reg.Factory(nil, nil, "test")
	if !dummyCalled {
		t.Errorf("custom logger factory was not invoked")
	}
}
