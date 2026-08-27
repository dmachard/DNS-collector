package workers

import (
	"github.com/dmachard/go-dnscollector/v2/dnsutils"
	"github.com/dmachard/go-dnscollector/v2/pkg/config"
	"github.com/dmachard/go-logger"
)

type DevNull struct {
	*GenericWorker
}

func NewDevNull(cfg *config.Config, console *logger.Logger, name string) *DevNull {
	bufSize := cfg.Global.Worker.ChannelBufferSize
	s := &DevNull{GenericWorker: NewGenericWorker(cfg, console, name, "devnull", bufSize, config.DefaultMonitor)}
	s.ReadConfig()
	return s
}

func (w *DevNull) StartCollect() {
	w.LogInfo("starting data collection")
	defer w.CollectDone()

	w.RunBatchLoop(func(batch *dnsutils.DNSMessageBatch) {
		for range batch.Messages {
			w.CountIngressTraffic()
		}
		batch.Release()
	})
}

func init() {
	RegisterLogger("devnull", func(c *config.Config) bool { return c.Loggers.DevNull.Enable }, func(c *config.Config, l *logger.Logger, s string) Worker {
		return NewDevNull(c, l, s)
	})
}
