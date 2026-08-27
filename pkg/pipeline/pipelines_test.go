package pipeline

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/dmachard/go-dnscollector/v3/pkg/config"
	"github.com/dmachard/go-dnscollector/v3/pkg/telemetry"
	"github.com/dmachard/go-dnscollector/v3/workers"
	"github.com/dmachard/go-logger"
)

func TestPipelines_IsEnabled(t *testing.T) {
	// Create a mock configuration for testing
	cfg := &config.Config{}
	cfg.Pipelines = []config.ConfigPipelines{{Name: "validroute"}}

	if !IsPipelinesEnabled(cfg) {
		t.Errorf("pipelines should be enabled!")
	}
}

func TestPipelines_IsRouteExist(t *testing.T) {
	// Create a mock configuration for testing
	cfg := &config.Config{}
	cfg.Pipelines = []config.ConfigPipelines{
		{Name: "validroute"},
	}

	// Case where the route exists
	existingRoute := "validroute"
	err := IsRouteExist(existingRoute, cfg)
	if err != nil {
		t.Errorf("For the existing route %s, an unexpected error was returned: %v", existingRoute, err)
	}

	// Case where the route does not exist
	nonExistingRoute := "nonexistent-route"
	err = IsRouteExist(nonExistingRoute, cfg)
	if err == nil {
		t.Errorf("For the non-existing route %s, an expected error was not returned. Received error: %v", nonExistingRoute, err)
	}
	if !errors.Is(err, ErrRouteNotFound) {
		t.Errorf("Expected ErrRouteNotFound, got: %v", err)
	}
	var routeNotFoundErr *RouteNotFoundError
	if !errors.As(err, &routeNotFoundErr) {
		t.Errorf("Expected RouteNotFoundError type assertion, got: %v", err)
	}
}

func TestPipelines_StanzaNameIsUniq(t *testing.T) {
	// Create a mock configuration for testing
	cfg := &config.Config{}
	cfg.Pipelines = []config.ConfigPipelines{
		{Name: "unique-stanza"},
		{Name: "duplicate-stanza"},
		{Name: "duplicate-stanza"},
	}

	// Case where the stanza name is unique
	uniqueStanzaName := "unique-stanza"
	err := StanzaNameIsUniq(uniqueStanzaName, cfg)
	if err != nil {
		t.Errorf("For the unique stanza name %s, an unexpected error was returned: %v", uniqueStanzaName, err)
	}

	// Case where the stanza name is not unique
	duplicateStanzaName := "duplicate-stanza"
	err = StanzaNameIsUniq(duplicateStanzaName, cfg)
	if err == nil {
		t.Errorf("For the duplicate stanza name %s, an expected error was not returned. Received error: %v", duplicateStanzaName, err)
	}
	if !errors.Is(err, ErrDuplicateStanza) {
		t.Errorf("Expected ErrDuplicateStanza, got: %v", err)
	}
	var dupErr *DuplicateStanzaError
	if !errors.As(err, &dupErr) {
		t.Errorf("Expected DuplicateStanzaError, got: %v", err)
	}
}

func TestPipelines_NoRoutesDefined(t *testing.T) {
	// Create a mock configuration for testing
	cfg := &config.Config{}
	cfg.Pipelines = []config.ConfigPipelines{
		{Name: "stanzaA", RoutingPolicy: config.PipelinesRouting{Forward: []string{}, Dropped: []string{}}},
		{Name: "stanzaB", RoutingPolicy: config.PipelinesRouting{Forward: []string{}, Dropped: []string{}}},
	}

	mapLoggers := make(map[string]workers.Worker)
	mapCollectors := make(map[string]workers.Worker)

	metrics := telemetry.NewPrometheusCollector(cfg)
	err := InitPipelines(mapLoggers, mapCollectors, cfg, logger.New(false), metrics)
	if err == nil {
		t.Errorf("Want err, got nil")
	}
	if !errors.Is(err, ErrNoRoutesDefined) {
		t.Errorf("Expected ErrNoRoutesDefined, got: %v", err)
	}
}

func TestPipelines_RoutingLoop(t *testing.T) {
	// Create a mock configuration for testing
	cfg := config.GetDefaultConfig()
	cfg.Pipelines = []config.ConfigPipelines{
		{
			Name: "stanzaA",
			Params: map[string]interface{}{
				"dnstap": map[string]interface{}{"enable": true},
			},
			RoutingPolicy: config.PipelinesRouting{Forward: []string{"stanzaA"}, Dropped: []string{}},
		},
	}

	mapLoggers := make(map[string]workers.Worker)
	mapCollectors := make(map[string]workers.Worker)

	metrics := telemetry.NewPrometheusCollector(cfg)
	err := InitPipelines(mapLoggers, mapCollectors, cfg, logger.New(false), metrics)
	if err == nil {
		t.Errorf("Want err, got nil")
	}
	if !errors.Is(err, ErrRoutingLoop) {
		t.Errorf("Expected ErrRoutingLoop, got: %v", err)
	}
	var loopErr *RoutingLoopError
	if !errors.As(err, &loopErr) {
		t.Errorf("Expected RoutingLoopError, got: %v", err)
	}
}

func TestPipelines_StopPipelines(t *testing.T) {
	cfg := config.GetDefaultConfig()
	log := logger.New(false)

	c1 := workers.NewGenericWorker(cfg, log, "col1", "", 10, config.WorkerMonitorDisabled)
	l1 := workers.NewGenericWorker(cfg, log, "log1", "", 10, config.WorkerMonitorDisabled)

	go c1.StartCollect()
	go l1.StartCollect()

	mapCollectors := map[string]workers.Worker{"col1": c1}
	mapLoggers := map[string]workers.Worker{"log1": l1}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	StopPipelines(ctx, mapCollectors, mapLoggers, log)

	if c1.Context().Err() == nil {
		t.Errorf("collector context should be cancelled")
	}
	if l1.Context().Err() == nil {
		t.Errorf("logger context should be cancelled")
	}
}

func TestPipelines_GetStanzaConfig_CollectorAndTransformer(t *testing.T) {
	cfg := config.GetDefaultConfig()
	stanza := config.ConfigPipelines{
		Name: "tap",
		Params: map[string]interface{}{
			"dnstap": map[string]interface{}{
				"listen-ip":   "127.0.0.1",
				"listen-port": 6000,
			},
		},
		Transforms: map[string]interface{}{
			"normalize": map[string]interface{}{
				"qname-lowercase": true,
			},
		},
	}

	subcfg, err := GetStanzaConfig(cfg, stanza)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !subcfg.Collectors.Dnstap.Enable {
		t.Errorf("expected Dnstap.Enable to be true")
	}
	if subcfg.Collectors.Dnstap.ListenIP != "127.0.0.1" {
		t.Errorf("expected ListenIP '127.0.0.1', got %s", subcfg.Collectors.Dnstap.ListenIP)
	}
	if subcfg.Collectors.Dnstap.ListenPort != 6000 {
		t.Errorf("expected ListenPort 6000, got %d", subcfg.Collectors.Dnstap.ListenPort)
	}
	if !subcfg.IngoingTransformers.Normalize.Enable {
		t.Errorf("expected Normalize.Enable to be true")
	}
	if !subcfg.IngoingTransformers.Normalize.QnameLowerCase {
		t.Errorf("expected QnameLowerCase to be true")
	}
}

func TestPipelines_GetStanzaConfig_Logger(t *testing.T) {
	cfg := config.GetDefaultConfig()
	stanza := config.ConfigPipelines{
		Name: "prom",
		Params: map[string]interface{}{
			"prometheus": map[string]interface{}{
				"listen-ip":   "0.0.0.0",
				"listen-port": 8080,
			},
		},
	}

	subcfg, err := GetStanzaConfig(cfg, stanza)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !subcfg.Loggers.Prometheus.Enable {
		t.Errorf("expected Prometheus.Enable to be true")
	}
	if subcfg.Loggers.Prometheus.ListenIP != "0.0.0.0" {
		t.Errorf("expected ListenIP '0.0.0.0', got %s", subcfg.Loggers.Prometheus.ListenIP)
	}
	if subcfg.Loggers.Prometheus.ListenPort != 8080 {
		t.Errorf("expected ListenPort 8080, got %d", subcfg.Loggers.Prometheus.ListenPort)
	}
}

func TestPipelines_GetStanzaConfig_UnknownWorker(t *testing.T) {
	cfg := config.GetDefaultConfig()
	stanza := config.ConfigPipelines{
		Name: "invalid-stanza",
		Params: map[string]interface{}{
			"unknown-worker": map[string]interface{}{"enable": true},
		},
	}

	_, err := GetStanzaConfig(cfg, stanza)
	if err == nil {
		t.Fatalf("expected error for unknown worker, got nil")
	}
	if !errors.Is(err, ErrStanzaConfig) {
		t.Errorf("expected ErrStanzaConfig, got: %v", err)
	}
	var cfgErr *StanzaConfigError
	if !errors.As(err, &cfgErr) {
		t.Errorf("expected StanzaConfigError type, got: %v", err)
	}
}

func TestPipelines_CreateRouting_StanzaNotFound(t *testing.T) {
	stanza := config.ConfigPipelines{
		Name: "nonexistent",
		RoutingPolicy: config.PipelinesRouting{
			Forward: []string{"target"},
		},
	}
	mapLoggers := make(map[string]workers.Worker)
	mapCollectors := make(map[string]workers.Worker)

	err := CreateRouting(stanza, mapCollectors, mapLoggers, logger.New(false))
	if err == nil {
		t.Fatalf("expected error, got nil")
	}
	if !errors.Is(err, ErrStanzaNotFound) {
		t.Errorf("expected ErrStanzaNotFound, got: %v", err)
	}
}

func TestPipelines_CreateRouting_UnsupportedDefaultRouting(t *testing.T) {
	stanza := config.ConfigPipelines{
		Name: "stanzaA",
		RoutingPolicy: config.PipelinesRouting{
			Forward: []string{"stanzaB"},
		},
	}
	wA := workers.GetWorkerForTest(10)
	wB := &workers.GenericWorker{} // No input channel

	mapCollectors := map[string]workers.Worker{
		"stanzaA": wA,
		"stanzaB": wB,
	}
	mapLoggers := make(map[string]workers.Worker)

	err := CreateRouting(stanza, mapCollectors, mapLoggers, logger.New(false))
	if err == nil {
		t.Fatalf("expected error, got nil")
	}
	if !errors.Is(err, workers.ErrDefaultRoutingNotSupported) {
		t.Errorf("expected ErrDefaultRoutingNotSupported, got: %v", err)
	}
	var routingErr *workers.DefaultRoutingError
	if !errors.As(err, &routingErr) {
		t.Errorf("expected DefaultRoutingError, got: %v", err)
	}
}

func TestPipelines_MultipleErrors_Joined(t *testing.T) {
	cfg := config.GetDefaultConfig()
	cfg.Pipelines = []config.ConfigPipelines{
		{
			Name: "tap",
			Params: map[string]interface{}{
				"dnstap": map[string]interface{}{"enable": true},
			},
			RoutingPolicy: config.PipelinesRouting{
				Forward: []string{"nonexistent1", "nonexistent2"},
			},
		},
		{
			Name: "tap", // Duplicate stanza name
			Params: map[string]interface{}{
				"dnstap": map[string]interface{}{"enable": true},
			},
			RoutingPolicy: config.PipelinesRouting{
				Forward: []string{"nonexistent3"},
			},
		},
	}

	mapLoggers := make(map[string]workers.Worker)
	mapCollectors := make(map[string]workers.Worker)
	metrics := telemetry.NewPrometheusCollector(cfg)

	err := InitPipelines(mapLoggers, mapCollectors, cfg, logger.New(false), metrics)
	if err == nil {
		t.Fatalf("expected multiple errors, got nil")
	}

	// Verify that errors.Join preserved both error categories
	if !errors.Is(err, ErrDuplicateStanza) {
		t.Errorf("expected joined error to contain ErrDuplicateStanza, got: %v", err)
	}
	if !errors.Is(err, ErrRouteNotFound) {
		t.Errorf("expected joined error to contain ErrRouteNotFound, got: %v", err)
	}

	// Verify that error message contains details from both errors
	errStr := err.Error()
	if !strings.Contains(errStr, "duplicated") || !strings.Contains(errStr, "nonexistent") {
		t.Errorf("expected comprehensive multi-error message, got: %s", errStr)
	}
}
