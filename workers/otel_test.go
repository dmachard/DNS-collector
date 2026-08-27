package workers

import (
	"testing"

	"github.com/dmachard/go-dnscollector/v3/pkg/config"
	"github.com/dmachard/go-logger"
	"github.com/stretchr/testify/assert"
)

func TestOpenTelemetry_InitTracerProvider(t *testing.T) {
	cfg := config.GetDefaultConfig()
	cfg.Loggers.OpenTelemetryClient.Enable = true
	cfg.Loggers.OpenTelemetryClient.OtelEndpoint = "localhost:4317"

	logger := logger.New(false) // Disable verbose logging for tests
	client := NewOpenTelemetryClient(cfg, logger, "test-client")

	// Initialize tracer provider
	tracer := client.getTracer("test-service")

	// Assert tracer is not nil
	assert.NotNil(t, tracer, "Tracer should not be nil")
}
