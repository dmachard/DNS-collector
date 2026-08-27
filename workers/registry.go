package workers

import (
	"sync"

	"github.com/dmachard/go-dnscollector/v3/pkg/config"
	"github.com/dmachard/go-logger"
)

// WorkerFactory represents a constructor function to create a new Worker instance.
type WorkerFactory func(config *config.Config, logger *logger.Logger, stanzaName string) Worker

// EnabledCheck represents a function to check if a specific worker is enabled in the config.
type EnabledCheck func(config *config.Config) bool

// Registration holds the factory and enablement predicate for a worker component.
type Registration struct {
	Name      string
	IsEnabled EnabledCheck
	Factory   WorkerFactory
}

var (
	registryMu        sync.RWMutex
	collectorRegistry = make(map[string]Registration)
	loggerRegistry    = make(map[string]Registration)
)

// RegisterCollector registers a new collector worker factory with its enablement check.
func RegisterCollector(name string, isEnabled EnabledCheck, factory WorkerFactory) {
	registryMu.Lock()
	defer registryMu.Unlock()
	collectorRegistry[name] = Registration{
		Name:      name,
		IsEnabled: isEnabled,
		Factory:   factory,
	}
}

// RegisterLogger registers a new logger worker factory with its enablement check.
func RegisterLogger(name string, isEnabled EnabledCheck, factory WorkerFactory) {
	registryMu.Lock()
	defer registryMu.Unlock()
	loggerRegistry[name] = Registration{
		Name:      name,
		IsEnabled: isEnabled,
		Factory:   factory,
	}
}

// GetRegisteredCollectors returns a copy of all registered collector definitions.
func GetRegisteredCollectors() map[string]Registration {
	registryMu.RLock()
	defer registryMu.RUnlock()
	res := make(map[string]Registration, len(collectorRegistry))
	for k, v := range collectorRegistry {
		res[k] = v
	}
	return res
}

// GetRegisteredLoggers returns a copy of all registered logger definitions.
func GetRegisteredLoggers() map[string]Registration {
	registryMu.RLock()
	defer registryMu.RUnlock()
	res := make(map[string]Registration, len(loggerRegistry))
	for k, v := range loggerRegistry {
		res[k] = v
	}
	return res
}
