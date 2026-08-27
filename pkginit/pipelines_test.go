package pkginit

import (
	"context"
	"strings"
	"testing"
	"time"

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
	} else if err.Error() != "no routes are defined" {
		t.Errorf("Unexpected error: %s", err.Error())
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
}

func TestPipelines_StopPipelines(t *testing.T) {
	cfg := pkgconfig.GetDefaultConfig()
	log := logger.New(false)

	c1 := workers.NewGenericWorker(cfg, log, "col1", "", 10, pkgconfig.WorkerMonitorDisabled)
	l1 := workers.NewGenericWorker(cfg, log, "log1", "", 10, pkgconfig.WorkerMonitorDisabled)

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
