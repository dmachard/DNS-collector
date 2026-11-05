package config

import (
	"fmt"

	"github.com/pkg/errors"
)

type ConfigPipelines struct {
	Name          string                 `yaml:"name"`
	Transforms    map[string]interface{} `yaml:"transforms"`
	Params        map[string]interface{} `yaml:",inline"`
	RoutingPolicy PipelinesRouting       `yaml:"routing-policy"`
}

func (c *ConfigPipelines) IsValid(userCfg map[string]interface{}) error {
	if _, ok := userCfg["name"]; !ok {
		return errors.Errorf("name key is required")
	}
	delete(userCfg, "name")

	if val, ok := userCfg["transforms"]; ok {
		transformsMap, isMap := val.(map[string]interface{})
		if !isMap {
			return errors.Errorf("transform - expected map, got %T", val)
		}
		cfg := ConfigTransformers{}
		if err := cfg.IsValid(transformsMap); err != nil {
			return errors.Errorf("transform - %s", err)
		}
		delete(userCfg, "transforms")
	}

	if val, ok := userCfg["routing-policy"]; ok {
		routingMap, isMap := val.(map[string]interface{})
		if !isMap {
			return errors.Errorf("routing-policy - expected map, got %T", val)
		}
		cfg := PipelinesRouting{}
		if err := cfg.IsValid(routingMap); err != nil {
			return errors.Errorf("routing-policy - %s", err)
		}
		delete(userCfg, "routing-policy")
	}

	wc := ConfigCollectors{}
	wl := ConfigLoggers{}

	for workerName := range userCfg {
		collectorExist := wc.IsExists(workerName)
		loggerExist := wl.IsExists(workerName)
		if !collectorExist && !loggerExist {
			return errors.Errorf("invalid worker type - %s", workerName)
		}

		if collectorExist {
			if err := wc.IsValid(userCfg); err != nil {
				return errors.Errorf("%s", err)
			}
		}
		if loggerExist {
			if err := wl.IsValid(userCfg); err != nil {
				return errors.Errorf("%s", err)
			}
		}
	}

	return nil
}

type PipelinesRouting struct {
	Forward []string `yaml:"forward,flow"`
	Dropped []string `yaml:"dropped,flow"`
}

func (c *PipelinesRouting) IsValid(userCfg map[string]interface{}) error {
	for k := range userCfg {
		if k != "forward" && k != "dropped" {
			return fmt.Errorf("invalid key '%s'", k)
		}
	}
	return nil
}
