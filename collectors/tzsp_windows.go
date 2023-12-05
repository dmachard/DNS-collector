//go:build windows
// +build windows

package collectors

import (
	"github.com/dmachard/go-dnscollector/dnsutils"
	"github.com/dmachard/go-dnscollector/pkgconfig"
	"github.com/dmachard/go-logger"
)

type TZSPSniffer struct {
	done    chan bool
	exit    chan bool
	loggers []dnsutils.Worker
	config  *pkgconfig.Config
	logger  *logger.Logger
	name    string
}

// workaround for macos, not yet supported
func NewTZSP(loggers []dnsutils.Worker, config *pkgconfig.Config, logger *logger.Logger, name string) *AfpacketSniffer {
	logger.Info("[%s] tzsp collector - enabled", name)
	s := &AfpacketSniffer{
		done:    make(chan bool),
		exit:    make(chan bool),
		config:  config,
		loggers: loggers,
		logger:  logger,
		name:    name,
	}
	s.ReadConfig()
	return s
}

func (c *TZSPSniffer) GetName() string { return c.name }

func (c *TZSPSniffer) SetLoggers(loggers []dnsutils.Worker) {
	c.loggers = loggers
}

func (c *TZSPSniffer) LogInfo(msg string, v ...interface{}) {
	c.logger.Info("["+c.name+"] tzsp collector - "+msg, v...)
}

func (c *TZSPSniffer) LogError(msg string, v ...interface{}) {
	c.logger.Error("["+c.name+"] tzsp collector - "+msg, v...)
}

func (c *TZSPSniffer) Loggers() []chan dnsutils.DNSMessage {
	channels := []chan dnsutils.DNSMessage{}
	for _, p := range c.loggers {
		channels = append(channels, p.Channel())
	}
	return channels
}

func (c *TZSPSniffer) ReadConfig() {}

func (c *TZSPSniffer) ReloadConfig(config *pkgconfig.Config) {}

func (c *TZSPSniffer) Channel() chan dnsutils.DNSMessage {
	return nil
}

func (c *TZSPSniffer) Stop() {
	c.LogInfo("stopping...")

	// exit to close properly
	c.exit <- true

	// read done channel and block until run is terminated
	<-c.done
	close(c.done)
}

func (c *TZSPSniffer) Run() {
	c.LogInfo("run terminated")
	c.done <- true
}
