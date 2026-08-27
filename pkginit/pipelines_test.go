package pkginit

import (
	"errors"
	"strings"
	"testing"

	"github.com/dmachard/go-dnscollector/v2/pkgconfig"
	"github.com/dmachard/go-dnscollector/v2/telemetry"
	"github.com/dmachard/go-dnscollector/v2/workers"
	"github.com/dmachard/go-logger"
)

func TestPipelines_IsEnabled(t *testing.T) {
	// Create a mock configuration for testing
	config := &pkgconfig.Config{}
	config.Pipelines = []pkgconfig.ConfigPipelines{{Name: "validroute"}}

	if !IsPipelinesEnabled(config) {
		t.Errorf("pipelines should be enabled!")
	}
}

func TestPipelines_IsRouteExist(t *testing.T) {
	// Create a mock configuration for testing
	config := &pkgconfig.Config{}
	config.Pipelines = []pkgconfig.ConfigPipelines{
		{Name: "validroute"},
	}

	// Case where the route exists
	existingRoute := "validroute"
	err := IsRouteExist(existingRoute, config)
	if err != nil {
		t.Errorf("For the existing route %s, an unexpected error was returned: %v", existingRoute, err)
	}

	// Case where the route does not exist
	nonExistingRoute := "nonexistent-route"
	err = IsRouteExist(nonExistingRoute, config)
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
	config := &pkgconfig.Config{}
	config.Pipelines = []pkgconfig.ConfigPipelines{
		{Name: "unique-stanza"},
		{Name: "duplicate-stanza"},
		{Name: "duplicate-stanza"},
	}

	// Case where the stanza name is unique
	uniqueStanzaName := "unique-stanza"
	err := StanzaNameIsUniq(uniqueStanzaName, config)
	if err != nil {
		t.Errorf("For the unique stanza name %s, an unexpected error was returned: %v", uniqueStanzaName, err)
	}

	// Case where the stanza name is not unique
	duplicateStanzaName := "duplicate-stanza"
	err = StanzaNameIsUniq(duplicateStanzaName, config)
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
	config := &pkgconfig.Config{}
	config.Pipelines = []pkgconfig.ConfigPipelines{
		{Name: "stanzaA", RoutingPolicy: pkgconfig.PipelinesRouting{Forward: []string{}, Dropped: []string{}}},
		{Name: "stanzaB", RoutingPolicy: pkgconfig.PipelinesRouting{Forward: []string{}, Dropped: []string{}}},
	}

	mapLoggers := make(map[string]workers.Worker)
	mapCollectors := make(map[string]workers.Worker)

	metrics := telemetry.NewPrometheusCollector(config)
	err := InitPipelines(mapLoggers, mapCollectors, config, logger.New(false), metrics)
	if err == nil {
		t.Errorf("Want err, got nil")
	}
	if !errors.Is(err, ErrNoRoutesDefined) {
		t.Errorf("Expected ErrNoRoutesDefined, got: %v", err)
	}
}

func TestPipelines_RoutingLoop(t *testing.T) {
	// Create a mock configuration for testing
	config := pkgconfig.GetDefaultConfig()
	config.Pipelines = []pkgconfig.ConfigPipelines{
		{
			Name: "stanzaA",
			Params: map[string]interface{}{
				"dnstap": map[string]interface{}{"enable": true},
			},
			RoutingPolicy: pkgconfig.PipelinesRouting{Forward: []string{"stanzaA"}, Dropped: []string{}},
		},
	}

	mapLoggers := make(map[string]workers.Worker)
	mapCollectors := make(map[string]workers.Worker)

	metrics := telemetry.NewPrometheusCollector(config)
	err := InitPipelines(mapLoggers, mapCollectors, config, logger.New(false), metrics)
	if err == nil {
		t.Errorf("Want err, got nil")
	} else if !strings.Contains(err.Error(), "routing error loop") {
		t.Errorf("Unexpected error: %s", err.Error())
	}
	if !errors.Is(err, ErrRoutingLoop) {
		t.Errorf("Expected ErrRoutingLoop, got: %v", err)
	}
	var loopErr *RoutingLoopError
	if !errors.As(err, &loopErr) {
		t.Errorf("Expected RoutingLoopError, got: %v", err)
	}
}

func TestPipelines_GetStanzaConfig_UnknownWorker(t *testing.T) {
	config := pkgconfig.GetDefaultConfig()
	stanza := pkgconfig.ConfigPipelines{
		Name: "invalid-stanza",
		Params: map[string]interface{}{
			"unknown-worker": map[string]interface{}{"enable": true},
		},
	}

	_, err := GetStanzaConfig(config, stanza)
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
	stanza := pkgconfig.ConfigPipelines{
		Name: "nonexistent",
		RoutingPolicy: pkgconfig.PipelinesRouting{
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
	stanza := pkgconfig.ConfigPipelines{
		Name: "stanzaA",
		RoutingPolicy: pkgconfig.PipelinesRouting{
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
