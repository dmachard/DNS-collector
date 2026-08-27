package workers

import (
	"errors"
	"testing"

	"github.com/dmachard/go-dnscollector/v3/dnsutils"
)

func TestWorkerErrors_IsAndAs(t *testing.T) {
	// Test DefaultRoutingError
	routErr := &DefaultRoutingError{StanzaName: "stanzaX", Reason: "no input channel"}
	if !errors.Is(routErr, ErrDefaultRoutingNotSupported) {
		t.Errorf("expected ErrDefaultRoutingNotSupported, got: %v", routErr)
	}
	var targetRoutErr *DefaultRoutingError
	if !errors.As(routErr, &targetRoutErr) {
		t.Errorf("expected *DefaultRoutingError, got: %v", routErr)
	}
}

func TestGetRoutes_ZeroPanic(t *testing.T) {
	wValid := GetWorkerForTest(10)
	wWithoutInput := &GenericWorker{name: "no-input"}
	routes := []Worker{nil, wWithoutInput, wValid}

	channels, names := GetRoutes(routes)
	if len(channels) != 1 {
		t.Errorf("expected 1 channel, got %d", len(channels))
	}
	if len(names) != 1 || names[0] != wValid.GetName() {
		t.Errorf("expected [%s], got %v", wValid.GetName(), names)
	}
}

func TestPrometheusCatalogue_ZeroPanic(t *testing.T) {
	// Test GetAllCounterSets with unexpected element type (should not panic)
	container := &PromCounterCatalogueContainer{
		stats: map[string]PrometheusCountersCatalogue{
			"bad": nil,
		},
	}
	sets := container.GetAllCounterSets()
	if len(sets) != 0 {
		t.Errorf("expected 0 sets, got %d", len(sets))
	}

	// Test GetCountersSet with nil selector (should return nil and not panic)
	containerNilSelector := &PromCounterCatalogueContainer{
		selector: nil,
	}
	res := containerNilSelector.GetCountersSet(&dnsutils.DNSMessage{})
	if res != nil {
		t.Errorf("expected nil result for nil selector, got %v", res)
	}
}
