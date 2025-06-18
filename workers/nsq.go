package workers

import (
	"encoding/json"
	"strconv"

	"github.com/dmachard/go-dnscollector/pkgconfig"
	"github.com/dmachard/go-logger"
	"github.com/nsqio/go-nsq"
)

type NSQProducer interface {
	Publish(topic string, body []byte) error
	Stop()
}

type NsqClient struct {
	*GenericWorker
	nsqProducer NSQProducer
	newProducer func() (NSQProducer, error)
}

func NewNsqClient(config *pkgconfig.Config, console *logger.Logger, name string) *NsqClient {
	bufferSize := config.Loggers.Nsq.ChannelBufferSize
	if bufferSize == 0 {
		bufferSize = config.Global.Worker.ChannelBufferSize
	}

	s := &NsqClient{
		GenericWorker: NewGenericWorker(config, console, name, "nsq", bufferSize, pkgconfig.DefaultMonitor),
	}

	s.newProducer = s.defaultNewProducer
	s.ReadConfig()
	return s
}

func (w *NsqClient) defaultNewProducer() (NSQProducer, error) {
	nsqconf := w.GetConfig().Loggers.Nsq
	addr := nsqconf.Host + ":" + strconv.Itoa(nsqconf.Port)
	config := nsq.NewConfig()
	return nsq.NewProducer(addr, config)
}

func (w *NsqClient) StartCollect() {
	w.LogInfo("starting data collection")
	defer w.CollectDone()

	go w.StartLogging()

	for {
		select {
		case <-w.OnStop():
			w.StopLogger()
			return

		case msg, opened := <-w.GetInputChannel():
			if !opened {
				w.LogInfo("input channel closed!")
				return
			}

			w.GetOutputChannel() <- msg
		}
	}
}

func (w *NsqClient) StartLogging() {
	w.LogInfo("logging has started")
	defer w.LoggingDone()

	nsqconf := w.GetConfig().Loggers.Nsq
	topic := nsqconf.Topic

	producer, err := w.newProducer()
	if err != nil {
		w.LogError("failed to start NSQ producer: %v", err)
		return
	}
	w.nsqProducer = producer

	for {
		select {
		case <-w.OnLoggerStopped():
			w.Disconnect()
			return

		case msg, opened := <-w.GetOutputChannel():
			if !opened {
				w.LogInfo("output channel closed!")
				return
			}

			encoded, err := json.Marshal(msg)
			if err != nil {
				w.LogError("json encoding error: %v", err)
				continue
			}

			err = w.nsqProducer.Publish(topic, encoded)
			if err != nil {
				w.LogError("failed to publish to NSQ: %v", err)
			}
		}
	}
}

func (w *NsqClient) Disconnect() {
	if w.nsqProducer != nil {
		w.LogInfo("Disconnecting...")
		w.nsqProducer.Stop()
	}
}
