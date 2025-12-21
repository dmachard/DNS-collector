package pkginit

import (
	"fmt"

	"github.com/dmachard/go-dnscollector/pkgconfig"
	"github.com/dmachard/go-dnscollector/telemetry"
	"github.com/dmachard/go-dnscollector/workers"
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
		v.(map[string]interface{})["enable"] = true
		cfg[section+"-transformers"].(map[string]interface{})[k] = v
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
	loggers := []struct {
		enabled bool
		create  func() workers.Worker
	}{
		{config.Loggers.RestAPI.Enable, func() workers.Worker {
			return workers.NewRestAPI(config, logger, stanzaName)
		}},
		{config.Loggers.Prometheus.Enable, func() workers.Worker {
			return workers.NewPrometheus(config, logger, stanzaName)
		}},
		{config.Loggers.Stdout.Enable, func() workers.Worker {
			return workers.NewStdOut(config, logger, stanzaName)
		}},
		{config.Loggers.LogFile.Enable, func() workers.Worker {
			return workers.NewLogFile(config, logger, stanzaName)
		}},
		{config.Loggers.DNSTap.Enable, func() workers.Worker {
			return workers.NewDnstapSender(config, logger, stanzaName)
		}},
		{config.Loggers.TCPClient.Enable, func() workers.Worker {
			return workers.NewTCPClient(config, logger, stanzaName)
		}},
		{config.Loggers.Syslog.Enable, func() workers.Worker {
			return workers.NewSyslog(config, logger, stanzaName)
		}},
		{config.Loggers.Fluentd.Enable, func() workers.Worker {
			return workers.NewFluentdClient(config, logger, stanzaName)
		}},
		{config.Loggers.InfluxDB.Enable, func() workers.Worker {
			return workers.NewInfluxDBClient(config, logger, stanzaName)
		}},
		{config.Loggers.LokiClient.Enable, func() workers.Worker {
			return workers.NewLokiClient(config, logger, stanzaName)
		}},
		{config.Loggers.Statsd.Enable, func() workers.Worker {
			return workers.NewStatsdClient(config, logger, stanzaName)
		}},
		{config.Loggers.Nsq.Enable, func() workers.Worker {
			return workers.NewNsqClient(config, logger, stanzaName)
		}},
		{config.Loggers.ElasticSearchClient.Enable, func() workers.Worker {
			return workers.NewElasticSearchClient(config, logger, stanzaName)
		}},
		{config.Loggers.ScalyrClient.Enable, func() workers.Worker {
			return workers.NewScalyrClient(config, logger, stanzaName)
		}},
		{config.Loggers.RedisPub.Enable, func() workers.Worker {
			return workers.NewRedisPub(config, logger, stanzaName)
		}},
		{config.Loggers.KafkaProducer.Enable, func() workers.Worker {
			return workers.NewKafkaProducer(config, logger, stanzaName)
		}},
		{config.Loggers.FalcoClient.Enable, func() workers.Worker {
			return workers.NewFalcoClient(config, logger, stanzaName)
		}},
		{config.Loggers.ClickhouseClient.Enable, func() workers.Worker {
			return workers.NewClickhouseClient(config, logger, stanzaName)
		}},
		{config.Loggers.DevNull.Enable, func() workers.Worker {
			return workers.NewDevNull(config, logger, stanzaName)
		}},
		{config.Loggers.OpenTelemetryClient.Enable, func() workers.Worker {
			return workers.NewOpenTelemetryClient(config, logger, stanzaName)
		}},
		{config.Loggers.MQTT.Enable, func() workers.Worker {
			return workers.NewMQTT(config, logger, stanzaName)
		}},
	}

	for _, l := range loggers {
		registerWorker(mapLoggers, stanzaName, l.enabled, l.create, metrics)
	}

	collectors := []struct {
		enabled bool
		create  func() workers.Worker
	}{
		{config.Collectors.DNSMessage.Enable, func() workers.Worker {
			return workers.NewDNSMessage(nil, config, logger, stanzaName)
		}},
		{config.Collectors.Dnstap.Enable, func() workers.Worker {
			return workers.NewDnstapServer(nil, config, logger, stanzaName)
		}},
		{config.Collectors.DnstapProxifier.Enable, func() workers.Worker {
			return workers.NewDnstapProxifier(nil, config, logger, stanzaName)
		}},
		{config.Collectors.AfpacketLiveCapture.Enable, func() workers.Worker {
			return workers.NewAfpacketSniffer(nil, config, logger, stanzaName)
		}},
		{config.Collectors.XdpLiveCapture.Enable, func() workers.Worker {
			return workers.NewXDPSniffer(nil, config, logger, stanzaName)
		}},
		{config.Collectors.Tail.Enable, func() workers.Worker {
			return workers.NewTail(nil, config, logger, stanzaName)
		}},
		{config.Collectors.PowerDNS.Enable, func() workers.Worker {
			return workers.NewPdnsServer(nil, config, logger, stanzaName)
		}},
		{config.Collectors.FileIngestor.Enable, func() workers.Worker {
			return workers.NewFileIngestor(nil, config, logger, stanzaName)
		}},
		{config.Collectors.Tzsp.Enable, func() workers.Worker {
			return workers.NewTZSP(nil, config, logger, stanzaName)
		}},
		{config.Collectors.Webhook.Enable, func() workers.Worker {
			return workers.NewWebhook(nil, config, logger, stanzaName)
		}},
	}

	for _, c := range collectors {
		registerWorker(mapCollectors, stanzaName, c.enabled, c.create, metrics)
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
