//go:build experimental

package workers

import (
	"bytes"
	"sync"
	"testing"
	"time"

	"github.com/dmachard/go-dnscollector/v3/dnsutils"
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

func TestOpenTelemetry_LeafHandler_SharedMessage(t *testing.T) {
	cfg := config.GetDefaultConfig()
	cfg.Loggers.OpenTelemetryClient.Enable = true
	cfg.Loggers.OpenTelemetryClient.OtelEndpoint = "localhost:4317"

	client := NewOpenTelemetryClient(cfg, logger.New(false), "test-client")
	tracer := client.getTracer("test-service")

	dm := dnsutils.GetFakeDNSMessage()
	dm.PowerDNS = &dnsutils.CollectorPowerDNS{RequestorID: "req-1"}
	dm.DNSTap.Operation = "CLIENT_QUERY"
	dm.OpenTelemetry = nil

	var requestorSpans sync.Map
	var messageSpans sync.Map

	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		client.handleClientQuery(&requestorSpans, &messageSpans, tracer, &dm, time.Now())
	}()

	go func() {
		defer wg.Done()
		var buf bytes.Buffer
		dm.EncodeJSON(&buf)
	}()

	wg.Wait()

	if dm.OpenTelemetry != nil {
		t.Errorf("expected dm.OpenTelemetry to remain nil when leaf, got %+v", dm.OpenTelemetry)
	}
}

func TestOpenTelemetry_ForwardedRoutes_SharedMessageClone(t *testing.T) {
	kept := GetWorkerForTest(config.DefaultBufferSize)

	cfg := config.GetDefaultConfig()
	cfg.Loggers.OpenTelemetryClient.Enable = true
	cfg.Loggers.OpenTelemetryClient.OtelEndpoint = "localhost:4317"

	client := NewOpenTelemetryClient(cfg, logger.New(false), "test-client")
	client.SetDefaultRoutes([]Worker{kept})

	go client.StartCollect()

	dm := dnsutils.AcquireDNSMessage()
	dm.Init()
	dm.DNSTap.Timestamp = time.Now().UnixNano()
	dm.DNSTap.Identity = "shared-otel-test"
	dm.DNSTap.Operation = "CLIENT_QUERY"
	dm.PowerDNS = &dnsutils.CollectorPowerDNS{RequestorID: "req-1", MessageID: "msg-1"}
	dm.OpenTelemetry = nil

	// Retain +1 to simulate fan-out (shared with sibling worker)
	dm.Retain(1)

	var wg sync.WaitGroup
	wg.Add(1)
	stopRead := make(chan struct{})

	// Sibling worker concurrently reading original dm
	go func() {
		defer wg.Done()
		var buf bytes.Buffer
		for {
			select {
			case <-stopRead:
				return
			default:
				buf.Reset()
				dm.EncodeJSON(&buf)
				if dm.OpenTelemetry != nil {
					t.Errorf("original dm.OpenTelemetry was mutated concurrently by otel!")
					return
				}
			}
		}
	}()

	b := dnsutils.AcquireDNSMessageBatch(1)
	b.Messages = append(b.Messages, dm)
	client.GetInputChannel() <- b

	batchOut := <-kept.GetInputChannel()
	close(stopRead)
	wg.Wait()

	if len(batchOut.Messages) == 0 {
		t.Fatalf("expected message in forwarded batch")
	}
	dmOut := batchOut.Messages[0]

	if dmOut.OpenTelemetry == nil {
		t.Fatalf("expected dmOut.OpenTelemetry to be set on forwarded clone")
	}
	if len(dmOut.OpenTelemetry.TraceID) == 0 {
		t.Errorf("expected non-empty TraceID on forwarded clone")
	}

	if dm.OpenTelemetry != nil {
		t.Errorf("original dm.OpenTelemetry should remain nil, got %+v", dm.OpenTelemetry)
	}

	batchOut.Release()
	dm.Release()
	client.Stop()
}
