//go:build windows || darwin || freebsd

package workers

import (
	"github.com/dmachard/go-dnscollector/v3/pkg/config"
	"github.com/dmachard/go-logger"
)

type AfpacketSniffer struct {
	*GenericWorker
}

func NewAfpacketSniffer(next []Worker, cfg *config.Config, logger *logger.Logger, name string) *AfpacketSniffer {
	bufSize := cfg.Global.Worker.ChannelBufferSize
	w := &AfpacketSniffer{GenericWorker: NewGenericWorker(cfg, logger, name, "AFPACKET sniffer", bufSize, config.DefaultMonitor)}
	w.SetDefaultRoutes(next)
	w.ReadConfig()
	return w
}

func (w *AfpacketSniffer) StartCollect() {
	w.LogError("running collector failed...OS not supported!")
	defer w.CollectDone()
}

func init() {
	RegisterCollector("afpacket-sniffer", func(c *config.Config) bool { return c.Collectors.AfpacketLiveCapture.Enable }, func(c *config.Config, l *logger.Logger, s string) Worker {
		return NewAfpacketSniffer(nil, c, l, s)
	})
}
