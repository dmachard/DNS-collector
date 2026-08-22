package workers

import (
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

	// loop to process incoming messages
	for {
		select {
		case <-w.OnStop():
			return

		case dm, opened := <-w.GetInputChannel():
			if !opened {
				w.LogInfo("run: input channel closed!")
				return
			}

			// count global messages
			w.CountIngressTraffic()
			dm.Release()

		}
	}
}
