//go:build windows

package workers

import (
	"github.com/dmachard/go-dnscollector/v2/pkg/config"
	"github.com/dmachard/go-logger"
)

type XDPSniffer struct {
	*GenericWorker
}

func NewXDPSniffer(next []Worker, cfg *config.Config, logger *logger.Logger, name string) *XDPSniffer {
	bufSize := cfg.Global.Worker.ChannelBufferSize
	w := &XDPSniffer{GenericWorker: NewGenericWorker(cfg, logger, name, "xdp sniffer", bufSize, config.DefaultMonitor)}
	w.SetDefaultRoutes(next)
	w.ReadConfig()
	return w
}

func (w *XDPSniffer) StartCollect() {
	w.LogError("running collector failed...OS not supported!")
	defer w.CollectDone()
}

func init() {
	RegisterCollector("xdp-sniffer", func(c *config.Config) bool { return c.Collectors.XdpLiveCapture.Enable }, func(c *config.Config, l *logger.Logger, s string) Worker {
		return NewXDPSniffer(nil, c, l, s)
	})
}
