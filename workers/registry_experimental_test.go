//go:build experimental

package workers

import "testing"

func TestRegistry_OpenTelemetryRegistered(t *testing.T) {
	loggers := GetRegisteredLoggers()
	reg, exists := loggers["opentelemetry"]
	if !exists {
		t.Fatalf("expected logger 'opentelemetry' to be registered when experimental tag is set")
	}
	if reg.Factory == nil {
		t.Errorf("logger 'opentelemetry' has nil factory")
	}
	if reg.IsEnabled == nil {
		t.Errorf("logger 'opentelemetry' has nil IsEnabled check")
	}
}
