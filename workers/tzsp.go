//go:build windows || freebsd || darwin

package workers

import (
	"github.com/dmachard/go-dnscollector/v3/pkg/config"
	"github.com/dmachard/go-logger"
)

type TZSPSniffer struct {
	*GenericWorker
}

func NewTZSP(next []Worker, cfg *config.Config, logger *logger.Logger, name string) *TZSPSniffer {
	w := &TZSPSniffer{GenericWorker: NewGenericWorker(cfg, logger, name, "tzsp", config.DefaultBufferSize, config.DefaultMonitor)}
	w.SetDefaultRoutes(next)
	w.ReadConfig()
	return w
}

func (w *TZSPSniffer) StartCollect() {
	w.LogError("running collector failed...OS not supported!")
	defer w.CollectDone()
}

func init() {
	RegisterCollector("tzsp", func(c *config.Config) bool { return c.Collectors.Tzsp.Enable }, func(c *config.Config, l *logger.Logger, s string) Worker {
		return NewTZSP(nil, c, l, s)
	})
}
