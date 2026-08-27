package workers

import (
	"bytes"
	"encoding/json"
	"net/http"
	"time"

	"github.com/dmachard/go-dnscollector/v2/dnsutils"
	"github.com/dmachard/go-dnscollector/v2/pkg/config"
	"github.com/dmachard/go-dnscollector/v2/transformers"
	"github.com/dmachard/go-logger"
)

type FalcoClient struct {
	*GenericWorker
}

func NewFalcoClient(cfg *config.Config, console *logger.Logger, name string) *FalcoClient {
	bufSize := cfg.Global.Worker.ChannelBufferSize
	w := &FalcoClient{GenericWorker: NewGenericWorker(cfg, console, name, "falco", bufSize, config.DefaultMonitor)}
	w.ReadConfig()
	return w
}

func (w *FalcoClient) StartCollect() {
	w.LogInfo("starting data collection")
	defer w.CollectDone()

	// prepare next channels
	defaultRoutes, defaultNames := GetRoutes(w.GetDefaultRoutes())
	droppedRoutes, droppedNames := GetRoutes(w.GetDroppedRoutes())

	// prepare transforms
	subprocessors := transformers.NewTransforms(&w.GetConfig().OutgoingTransformers, w.GetLogger(), w.GetName(), w.GetOutputChannelAsList(), 0)

	// goroutine to process transformed dns messages
	go w.StartLogging()

	for {
		select {
		case <-w.OnStop():
			w.StopLogger()
			subprocessors.Reset()
			return

		// new config provided?
		case cfg := <-w.NewConfig():
			w.SetConfig(cfg)
			w.ReadConfig()
			subprocessors.ReloadConfig(&cfg.OutgoingTransformers)

		case batch, opened := <-w.GetInputChannel():
			if !opened {
				w.LogInfo("input channel closed!")
				return
			}
			outBatch := dnsutils.AcquireDNSMessageBatch(len(batch.Messages))
			for _, dm := range batch.Messages {
				// count global messages
				w.CountIngressTraffic()

				// apply transforms, init dns message with additional parts if necessary
				transformResult, err := subprocessors.ProcessMessage(dm)
				if err != nil {
					w.LogError(err.Error())
				}
				if transformResult == transformers.ReturnDrop {
					w.SendDroppedTo(droppedRoutes, droppedNames, dm)
					continue
				}
				dm.Retain(1)
				outBatch.Messages = append(outBatch.Messages, dm)
			}
			w.SendToOutputAndForwardBatch(defaultRoutes, defaultNames, outBatch)
			batch.Release()
		}
	}
}

func (w *FalcoClient) StartLogging() {
	w.LogInfo("logging has started")
	defer w.LoggingDone()

	buffer := new(bytes.Buffer)

	for {
		select {
		case <-w.OnLoggerStopped():
			return

		// incoming dns message to process
		case batch, opened := <-w.GetOutputChannel():
			if !opened {
				w.LogInfo("output channel closed!")
				return
			}
			for _, dm := range batch.Messages {
				// encode
				json.NewEncoder(buffer).Encode(dm)

				req, _ := http.NewRequest("POST", w.GetConfig().Loggers.FalcoClient.URL, buffer)
				req.Header.Set("Content-Type", "application/json")
				client := &http.Client{
					Timeout: 5 * time.Second,
				}
				_, err := client.Do(req)
				if err != nil {
					w.LogError(err.Error())
				}

				// finally reset the buffer for next iter
				buffer.Reset()
			}
			batch.Release()
		}
	}
}

func init() {
	RegisterLogger("falco", func(c *config.Config) bool { return c.Loggers.FalcoClient.Enable }, func(c *config.Config, l *logger.Logger, s string) Worker {
		return NewFalcoClient(c, l, s)
	})
}
