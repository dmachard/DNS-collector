package pkginit

import (
	"context"
	"fmt"

	"github.com/dmachard/go-dnscollector/v2/pkgconfig"
	"github.com/dmachard/go-dnscollector/v2/telemetry"
	"github.com/dmachard/go-dnscollector/v2/workers"
	"github.com/dmachard/go-logger"
	"github.com/pkg/errors"
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

func IsPipelinesEnabled(config *pkgconfig.Config) bool {
	return len(config.Pipelines) > 0
}

func GetStanzaConfig(config *pkgconfig.Config, item pkgconfig.ConfigPipelines) *pkgconfig.Config {

	cfg := make(map[string]interface{})
	section := "collectors"

	// Enable the provided collector or loggers
	for k, p := range item.Params {
		// is a logger or collector ?
		if !config.Loggers.IsExists(k) && !config.Collectors.IsExists(k) {
			panic(fmt.Sprintln("main - get stanza config error"))
		}
		if config.Loggers.IsExists(k) {
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
	subcfg := &pkgconfig.Config{}
	subcfg.SetDefault()

	cfg[section] = item.Params
	cfg[section+"-transformers"] = make(map[string]interface{})

	// add transformers
	for k, v := range item.Transforms {
		if transformerConfig, ok := v.(map[string]interface{}); ok {
			transformerConfig["enable"] = true
			cfg[section+"-transformers"].(map[string]interface{})[k] = transformerConfig
		} else {
			cfg[section+"-transformers"].(map[string]interface{})[k] = v
		}
	}

	// copy global config
	subcfg.Global = config.Global

	yamlcfg, _ := yaml.Marshal(cfg)
	if err := yaml.Unmarshal(yamlcfg, subcfg); err != nil {
		panic(fmt.Sprintf("main - yaml logger config error: %v", err))
	}

	return subcfg
}

func StanzaNameIsUniq(name string, config *pkgconfig.Config) (ret error) {
	stanzaCounter := 0
	for _, stanza := range config.Pipelines {
		if name == stanza.Name {
			stanzaCounter += 1
		}
	}

	if stanzaCounter > 1 {
		return fmt.Errorf("stanza=%s already exists", name)
	}
	return nil
}

func IsRouteExist(target string, config *pkgconfig.Config) (ret error) {
	for _, stanza := range config.Pipelines {
		if target == stanza.Name {
			return nil
		}
	}
	return fmt.Errorf("route=%s doest not exist", target)
}

func CreateRouting(stanza pkgconfig.ConfigPipelines, mapCollectors map[string]workers.Worker, mapLoggers map[string]workers.Worker, logger *logger.Logger) error {
	var currentStanza workers.Worker
	if collector, ok := mapCollectors[stanza.Name]; ok {
		currentStanza = collector
	}
	if logger, ok := mapLoggers[stanza.Name]; ok {
		currentStanza = logger
	}

	// forward routing
	for _, route := range stanza.RoutingPolicy.Forward {
		if route == stanza.Name {
			return fmt.Errorf("main - routing error loop with stanza=%s to stanza=%s", stanza.Name, route)
		}
		if _, ok := mapCollectors[route]; ok {
			currentStanza.AddDefaultRoute(mapCollectors[route])
			logger.Info("main - routing (policy=forward) stanza=[%s] to stanza=[%s]", stanza.Name, route)
		} else if _, ok := mapLoggers[route]; ok {
			currentStanza.AddDefaultRoute(mapLoggers[route])
			logger.Info("main - routing (policy=forward) stanza=[%s] to stanza=[%s]", stanza.Name, route)
		} else {
			return fmt.Errorf("main - forward routing error from stanza=%s to stanza=%s doest not exist", stanza.Name, route)
		}
	}

	// dropped routing
	for _, route := range stanza.RoutingPolicy.Dropped {
		if _, ok := mapCollectors[route]; ok {
			currentStanza.AddDroppedRoute(mapCollectors[route])
			logger.Info("main - routing (policy=dropped) stanza=[%s] to stanza=[%s]", stanza.Name, route)
		} else if _, ok := mapLoggers[route]; ok {
			currentStanza.AddDroppedRoute(mapLoggers[route])
			logger.Info("main - routing (policy=dropped) stanza=[%s] to stanza=[%s]", stanza.Name, route)
		} else {
			return fmt.Errorf("main - routing error with dropped messages from stanza=%s to stanza=%s doest not exist", stanza.Name, route)
		}
	}
	return nil
}

func CreateStanza(stanzaName string, config *pkgconfig.Config, mapCollectors map[string]workers.Worker, mapLoggers map[string]workers.Worker, logger *logger.Logger, metrics *telemetry.PrometheusCollector) {
	for _, reg := range workers.GetRegisteredLoggers() {
		registerWorker(mapLoggers, stanzaName, reg.IsEnabled(config), func() workers.Worker {
			return reg.Factory(config, logger, stanzaName)
		}, metrics)
	}

	for _, reg := range workers.GetRegisteredCollectors() {
		registerWorker(mapCollectors, stanzaName, reg.IsEnabled(config), func() workers.Worker {
			return reg.Factory(config, logger, stanzaName)
		}, metrics)
	}
}

func InitPipelines(mapLoggers map[string]workers.Worker, mapCollectors map[string]workers.Worker, config *pkgconfig.Config, logger *logger.Logger, telemetry *telemetry.PrometheusCollector) error {
	// check if the name of each stanza is uniq
	routesDefined := false
	for _, stanza := range config.Pipelines {
		if err := StanzaNameIsUniq(stanza.Name, config); err != nil {
			return errors.Errorf("stanza with name=[%s] is duplicated", stanza.Name)
		}
		if len(stanza.RoutingPolicy.Forward) > 0 || len(stanza.RoutingPolicy.Dropped) > 0 {
			routesDefined = true
		}
	}

	if !routesDefined {
		return errors.Errorf("no routes are defined")
	}

	// check if all routes exists before continue
	for _, stanza := range config.Pipelines {
		for _, route := range stanza.RoutingPolicy.Forward {
			if err := IsRouteExist(route, config); err != nil {
				return errors.Errorf("stanza=[%s] forward route=[%s] doest not exist", stanza.Name, route)
			}
		}
		for _, route := range stanza.RoutingPolicy.Dropped {
			if err := IsRouteExist(route, config); err != nil {
				return errors.Errorf("stanza=[%s] dropped route=[%s] doest not exist", stanza.Name, route)
			}
		}
	}

	// read each stanza and init
	for _, stanza := range config.Pipelines {
		stanzaConfig := GetStanzaConfig(config, stanza)
		CreateStanza(stanza.Name, stanzaConfig, mapCollectors, mapLoggers, logger, telemetry)

	}

	// create routing
	for _, stanza := range config.Pipelines {
		if mapCollectors[stanza.Name] != nil || mapLoggers[stanza.Name] != nil {
			if err := CreateRouting(stanza, mapCollectors, mapLoggers, logger); err != nil {
				return errors.Wrap(err, "routing")
			}
		} else {
			return errors.Errorf("routing - stanza=[%v] doest not exist", stanza.Name)
		}
	}

	return nil
}

func ReloadPipelines(mapLoggers map[string]workers.Worker, mapCollectors map[string]workers.Worker, config *pkgconfig.Config, logger *logger.Logger) {
	for _, stanza := range config.Pipelines {
		newCfg := GetStanzaConfig(config, stanza)
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
