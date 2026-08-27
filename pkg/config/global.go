package config

import (
	"reflect"
	"strconv"

	"github.com/creasty/defaults"
	"github.com/pkg/errors"
)

type GlobalTrace struct {
	Verbose      bool   `yaml:"verbose" default:"false"`
	LogMalformed bool   `yaml:"log-malformed" default:"false"`
	Filename     string `yaml:"filename" default:""`
	MaxSize      int    `yaml:"max-size" default:"10"`
	MaxBackups   int    `yaml:"max-backups" default:"10"`
}

type GlobalWorker struct {
	InternalMonitor      int `yaml:"interval-monitor" default:"10"`
	ChannelBufferSize    int `yaml:"buffer-size" default:"512"`
	BatchSize            int `yaml:"batch-size" default:"64"`
	BatchFlushIntervalMs int `yaml:"flush-interval-ms" default:"10"`
}

type GlobalTelemetry struct {
	Enabled         bool   `yaml:"enabled" default:"false"`
	WebPath         string `yaml:"web-path" default:"/metrics"`
	WebListen       string `yaml:"web-listen" default:":9165"`
	SockPath        string `yaml:"sock-path" default:""`
	SockMode        string `yaml:"sock-mode" default:"0660"`
	PromPrefix      string `yaml:"prometheus-prefix" default:"dnscollector_exporter"`
	TLSSupport      bool   `yaml:"tls-support" default:"false"`
	TLSCertFile     string `yaml:"tls-cert-file" default:""`
	TLSKeyFile      string `yaml:"tls-key-file" default:""`
	ClientCAFile    string `yaml:"client-ca-file" default:""`
	BasicAuthEnable bool   `yaml:"basic-auth-enable" default:"false"`
	BasicAuthLogin  string `yaml:"basic-auth-login" default:"admin"`
	BasicAuthPwd    string `yaml:"basic-auth-pwd" default:"changeme"`
}

type GlobalFramestream struct {
	ControlFrameMaxLength uint32 `yaml:"control-frame-max-length" default:"4064"`
	DataFrameMaxLength    uint32 `yaml:"data-frame-max-length" default:"65536"`
	HandshakeTimeout      int    `yaml:"handshake-timeout" default:"5"`
	ContentType           string `yaml:"content-type" default:"protobuf:dnstap.Dnstap"`
}

type ConfigGlobal struct {
	TextFormat          string            `yaml:"text-format" default:"timestamp identity operation rcode queryip queryport family protocol length-unit qname qtype latency"`
	TextFormatDelimiter string            `yaml:"text-format-delimiter" default:" "`
	TextFormatBoundary  string            `yaml:"text-format-boundary" default:"\""`
	TextJinja           string            `yaml:"text-jinja" default:""`
	Trace               GlobalTrace       `yaml:"trace"`
	ServerIdentity      string            `yaml:"server-identity" default:""`
	PidFile             string            `yaml:"pid-file" default:""`
	Worker              GlobalWorker      `yaml:"worker"`
	Telemetry           GlobalTelemetry   `yaml:"telemetry"`
	Framestream         GlobalFramestream `yaml:"framestream"`
	TransformersOrder   []string          `yaml:"transformers-order" default:"[]"`
}

func (c *ConfigGlobal) SetDefault() {
	defaults.Set(c)
}

func (c *ConfigGlobal) Check(userCfg map[string]interface{}) error {
	if err := CheckConfigWithTags(reflect.ValueOf(*c), userCfg); err != nil {
		return err
	}

	// Telemetry unix-socket constraints. Read from userCfg (the parsed YAML), not
	// the struct: Check runs against a defaults-only ConfigGlobal, so the user's
	// values live only in the map.
	if tel, ok := userCfg["telemetry"].(map[string]interface{}); ok {
		if sockPath, _ := tel["sock-path"].(string); sockPath != "" {
			if tlsSupport, _ := tel["tls-support"].(bool); tlsSupport {
				return errors.Errorf("telemetry: tls-support is not supported with sock-path, remove tls-support or use web-listen")
			}
			if sockMode, ok := tel["sock-mode"].(string); ok && sockMode != "" {
				if _, err := strconv.ParseUint(sockMode, 8, 32); err != nil {
					return errors.Errorf("telemetry: invalid sock-mode %q: %s", sockMode, err)
				}
			}
		}
	}

	return nil
}
