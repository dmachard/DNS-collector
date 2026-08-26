package workers

import (
	"github.com/dmachard/go-dnscollector/v2/dnsutils"
	"github.com/dmachard/go-dnscollector/v2/pkgconfig"
	"github.com/dmachard/go-logger"
)

type DevNull struct {
	*GenericWorker
}

func NewDevNull(config *pkgconfig.Config, console *logger.Logger, name string) *DevNull {
	bufSize := config.Global.Worker.ChannelBufferSize
	s := &DevNull{GenericWorker: NewGenericWorker(config, console, name, "devnull", bufSize, pkgconfig.DefaultMonitor)}
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
	RegisterLogger("devnull", func(c *pkgconfig.Config) bool { return c.Loggers.DevNull.Enable }, func(c *pkgconfig.Config, l *logger.Logger, s string) Worker {
		return NewDevNull(c, l, s)
	})
}
