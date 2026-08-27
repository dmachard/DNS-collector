package pipeline

import (
	"context"
	"errors"
	"fmt"

	"github.com/dmachard/go-dnscollector/v3/pkg/config"
	"github.com/dmachard/go-dnscollector/v3/pkg/telemetry"
	"github.com/dmachard/go-dnscollector/v3/workers"
	"github.com/dmachard/go-logger"
	"gopkg.in/yaml.v2"
)

func registerWorker(m map[string]workers.Worker, name string, enabled bool, factory func() workers.Worker, metrics *telemetry.PrometheusCollector) {
	if !enabled {
		return
	}
	w := factory()
	w.SetMetrics(metrics)
	m[name] = w
}

func IsPipelinesEnabled(cfg *config.Config) bool {
	return len(cfg.Pipelines) > 0
}

func GetStanzaConfig(mainConfig *config.Config, item config.ConfigPipelines) (*config.Config, error) {
	cfgMap := make(map[string]interface{})
	section := "collectors"

	// Enable the provided collector or loggers
	for k, p := range item.Params {
		// is a logger or collector ?
		if !mainConfig.Loggers.IsExists(k) && !mainConfig.Collectors.IsExists(k) {
			return nil, &StanzaConfigError{
				Message: fmt.Sprintf("stanza '%s' references unknown collector or logger '%s'", item.Name, k),
			}
		}
		if mainConfig.Loggers.IsExists(k) {
			section = "loggers"
		}
		if p == nil {
			item.Params[k] = make(map[string]interface{})
		}
		item.Params[k].(map[string]interface{})["enable"] = true

		// ignore other keys
		break
	}

	// prepare a new config
	subcfg := &config.Config{}
	subcfg.SetDefault()

	cfgMap[section] = item.Params
	cfgMap[section+"-transformers"] = make(map[string]interface{})

	// add transformers
	for k, v := range item.Transforms {
		if transformerConfig, ok := v.(map[string]interface{}); ok {
			transformerConfig["enable"] = true
			cfgMap[section+"-transformers"].(map[string]interface{})[k] = transformerConfig
		} else {
			cfgMap[section+"-transformers"].(map[string]interface{})[k] = v
		}
	}

	// copy global config
	subcfg.Global = mainConfig.Global

	yamlcfg, _ := yaml.Marshal(cfgMap)
	if err := yaml.Unmarshal(yamlcfg, subcfg); err != nil {
		return nil, &YAMLConfigError{
			Section: section,
			Err:     err,
		}
	}

	return subcfg, nil
}

func StanzaNameIsUniq(name string, cfg *config.Config) error {
	stanzaCounter := 0
	for _, stanza := range cfg.Pipelines {
		if name == stanza.Name {
			stanzaCounter += 1
		}
	}

	if stanzaCounter > 1 {
		return &DuplicateStanzaError{Name: name}
	}
	return nil
}

func IsRouteExist(target string, cfg *config.Config) error {
	for _, stanza := range cfg.Pipelines {
		if target == stanza.Name {
			return nil
		}
	}
	return &RouteNotFoundError{Name: target}
}

func CreateRouting(stanza config.ConfigPipelines, mapCollectors map[string]workers.Worker, mapLoggers map[string]workers.Worker, logger *logger.Logger) error {
	var currentStanza workers.Worker
	if collector, ok := mapCollectors[stanza.Name]; ok {
		currentStanza = collector
	}
	if logWorker, ok := mapLoggers[stanza.Name]; ok {
		currentStanza = logWorker
	}
	if currentStanza == nil {
		return &StanzaNotFoundError{Name: stanza.Name}
	}

	// forward routing
	for _, route := range stanza.RoutingPolicy.Forward {
		if route == stanza.Name {
			return &RoutingLoopError{From: stanza.Name, To: route}
		}
		if collector, ok := mapCollectors[route]; ok {
			if collector.GetInputChannel() == nil {
				return &workers.DefaultRoutingError{
					StanzaName: route,
					Reason:     "worker does not accept incoming messages",
				}
			}
			currentStanza.AddDefaultRoute(collector)
			logger.Info("main - routing (policy=forward) stanza=[%s] to stanza=[%s]", stanza.Name, route)
		} else if logWorker, ok := mapLoggers[route]; ok {
			if logWorker.GetInputChannel() == nil {
				return &workers.DefaultRoutingError{
					StanzaName: route,
					Reason:     "worker does not accept incoming messages",
				}
			}
			currentStanza.AddDefaultRoute(logWorker)
			logger.Info("main - routing (policy=forward) stanza=[%s] to stanza=[%s]", stanza.Name, route)
		} else {
			return &RouteNotFoundError{Name: route, From: stanza.Name}
		}
	}

	// dropped routing
	for _, route := range stanza.RoutingPolicy.Dropped {
		if collector, ok := mapCollectors[route]; ok {
			if collector.GetInputChannel() == nil {
				return &workers.DefaultRoutingError{
					StanzaName: route,
					Reason:     "worker does not accept incoming messages",
				}
			}
			currentStanza.AddDroppedRoute(collector)
			logger.Info("main - routing (policy=dropped) stanza=[%s] to stanza=[%s]", stanza.Name, route)
		} else if logWorker, ok := mapLoggers[route]; ok {
			if logWorker.GetInputChannel() == nil {
				return &workers.DefaultRoutingError{
					StanzaName: route,
					Reason:     "worker does not accept incoming messages",
				}
			}
			currentStanza.AddDroppedRoute(logWorker)
			logger.Info("main - routing (policy=dropped) stanza=[%s] to stanza=[%s]", stanza.Name, route)
		} else {
			return &RouteNotFoundError{Name: route, From: stanza.Name}
		}
	}
	return nil
}

func CreateStanza(stanzaName string, cfg *config.Config, mapCollectors map[string]workers.Worker, mapLoggers map[string]workers.Worker, logger *logger.Logger, metrics *telemetry.PrometheusCollector) {
	for _, reg := range workers.GetRegisteredLoggers() {
		registerWorker(mapLoggers, stanzaName, reg.IsEnabled(cfg), func() workers.Worker {
			return reg.Factory(cfg, logger, stanzaName)
		}, metrics)
	}

	for _, reg := range workers.GetRegisteredCollectors() {
		registerWorker(mapCollectors, stanzaName, reg.IsEnabled(cfg), func() workers.Worker {
			return reg.Factory(cfg, logger, stanzaName)
		}, metrics)
	}
}

func InitPipelines(mapLoggers map[string]workers.Worker, mapCollectors map[string]workers.Worker, cfg *config.Config, logger *logger.Logger, telemetry *telemetry.PrometheusCollector) error {
	var errs []error
	seenStanzas := make(map[string]bool)
	duplicateReported := make(map[string]bool)
	routesDefined := false

	// 1. Check duplicate stanzas and route definitions
	for _, stanza := range cfg.Pipelines {
		if seenStanzas[stanza.Name] {
			if !duplicateReported[stanza.Name] {
				errs = append(errs, &DuplicateStanzaError{Name: stanza.Name})
				duplicateReported[stanza.Name] = true
			}
		}
		seenStanzas[stanza.Name] = true

		if len(stanza.RoutingPolicy.Forward) > 0 || len(stanza.RoutingPolicy.Dropped) > 0 {
			routesDefined = true
		}
	}

	// 2. Check if all target routes exist
	for _, stanza := range cfg.Pipelines {
		for _, route := range stanza.RoutingPolicy.Forward {
			if err := IsRouteExist(route, cfg); err != nil {
				errs = append(errs, &RouteNotFoundError{Name: route, From: stanza.Name})
			}
		}
		for _, route := range stanza.RoutingPolicy.Dropped {
			if err := IsRouteExist(route, cfg); err != nil {
				errs = append(errs, &RouteNotFoundError{Name: route, From: stanza.Name})
			}
		}
	}

	if len(errs) > 0 {
		return errors.Join(errs...)
	}

	if !routesDefined {
		return ErrNoRoutesDefined
	}

	// 3. Read and instantiate each stanza
	var stanzaErrs []error
	for _, stanza := range cfg.Pipelines {
		stanzaConfig, err := GetStanzaConfig(cfg, stanza)
		if err != nil {
			stanzaErrs = append(stanzaErrs, err)
			continue
		}
		CreateStanza(stanza.Name, stanzaConfig, mapCollectors, mapLoggers, logger, telemetry)
	}

	if len(stanzaErrs) > 0 {
		return errors.Join(stanzaErrs...)
	}

	// 4. Create routing connections between instantiated stanzas
	var routingErrs []error
	for _, stanza := range cfg.Pipelines {
		if mapCollectors[stanza.Name] != nil || mapLoggers[stanza.Name] != nil {
			if err := CreateRouting(stanza, mapCollectors, mapLoggers, logger); err != nil {
				routingErrs = append(routingErrs, err)
			}
		} else {
			routingErrs = append(routingErrs, &StanzaNotFoundError{Name: stanza.Name})
		}
	}

	if len(routingErrs) > 0 {
		return errors.Join(routingErrs...)
	}

	return nil
}

func ReloadPipelines(mapLoggers map[string]workers.Worker, mapCollectors map[string]workers.Worker, cfg *config.Config, logger *logger.Logger) {
	for _, stanza := range cfg.Pipelines {
		newCfg, err := GetStanzaConfig(cfg, stanza)
		if err != nil {
			logger.Error("main - reload config error for stanza=%s: %v", stanza.Name, err)
			continue
		}
		if _, ok := mapLoggers[stanza.Name]; ok {
			mapLoggers[stanza.Name].ReloadConfig(newCfg)
		} else if _, ok := mapCollectors[stanza.Name]; ok {
			mapCollectors[stanza.Name].ReloadConfig(newCfg)
		} else {
			logger.Info("main - reload config stanza=%v doest not exist", stanza.Name)
		}
	}
}

// StopPipelines gracefully terminates collectors first (stopping incoming traffic),
// then terminates loggers (allowing remaining buffered logs to flush), bounded by ctx.
func StopPipelines(ctx context.Context, mapCollectors map[string]workers.Worker, mapLoggers map[string]workers.Worker, log *logger.Logger) {
	if log != nil {
		log.Info("stopping ingress collectors...")
	}
	collectorList := make([]workers.Worker, 0, len(mapCollectors))
	for _, c := range mapCollectors {
		collectorList = append(collectorList, c)
	}
	workers.StopWorkersParallel(ctx, collectorList, log)

	if log != nil {
		log.Info("stopping egress loggers...")
	}
	loggerList := make([]workers.Worker, 0, len(mapLoggers))
	for _, l := range mapLoggers {
		loggerList = append(loggerList, l)
	}
	workers.StopWorkersParallel(ctx, loggerList, log)
}
