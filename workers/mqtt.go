package workers

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/dmachard/go-dnscollector/v3/dnsutils"
	"github.com/dmachard/go-dnscollector/v3/pkg/config"
	"github.com/dmachard/go-dnscollector/v3/transformers"
	"github.com/dmachard/go-logger"
	"github.com/dmachard/go-netutils"
	mqtt "github.com/eclipse/paho.mqtt.golang"
)

const (
	mqttProtocolAuto = "auto"
)

type MQTT struct {
	*GenericWorker
	textFormat               []string
	textFormatter            *dnsutils.TextFormatter
	mqttClient               mqtt.Client
	mqttReady, mqttReconnect chan bool
	writerReady              bool
	stopReconnect            chan bool
}

func NewMQTT(cfg *config.Config, logger *logger.Logger, name string) *MQTT {
	bufSize := cfg.Global.Worker.ChannelBufferSize
	w := &MQTT{
		GenericWorker: NewGenericWorker(cfg, logger, name, "mqtt", bufSize, config.DefaultMonitor),
		mqttReady:     make(chan bool),
		mqttReconnect: make(chan bool),
		stopReconnect: make(chan bool),
	}
	w.ReadConfig()
	return w
}

func (w *MQTT) ReadConfig() {
	if len(w.GetConfig().Loggers.MQTT.TextFormat) > 0 {
		w.textFormat = strings.Fields(w.GetConfig().Loggers.MQTT.TextFormat)
	} else {
		w.textFormat = strings.Fields(w.GetConfig().Global.TextFormat)
	}

	var errFormatter error
	w.textFormatter, errFormatter = dnsutils.NewTextFormatter(w.textFormat, w.GetConfig().Global.TextFormatDelimiter, w.GetConfig().Global.TextFormatBoundary)
	if errFormatter != nil {
		w.LogFatal(config.PrefixLogWorker + "invalid text format: " + errFormatter.Error())
	}

	if !netutils.IsValidTLS(w.GetConfig().Loggers.MQTT.TLSMinVersion) {
		w.LogFatal(config.PrefixLogWorker + "[" + w.GetName() + "]mqtt - invalid tls min version")
	}

	if w.GetConfig().Loggers.MQTT.QOS > 2 {
		w.LogFatal(config.PrefixLogWorker + "[" + w.GetName() + "]mqtt - invalid qos value, must be 0, 1, or 2")
	}

	protocolVersion := strings.ToLower(w.GetConfig().Loggers.MQTT.ProtocolVersion)
	if protocolVersion != "v3" && protocolVersion != "v5" && protocolVersion != mqttProtocolAuto {
		w.LogFatal(config.PrefixLogWorker + "[" + w.GetName() + "]mqtt - invalid protocol version, must be v3, v5, or auto")
	}
}

func (w *MQTT) Disconnect() {
	if w.mqttClient != nil && w.mqttClient.IsConnected() {
		w.LogInfo("disconnecting from mqtt broker")
		w.mqttClient.Disconnect(250)
	}
}

func (w *MQTT) ConnectToMQTT() {
	for {
		select {
		case <-w.stopReconnect:
			return
		default:
		}

		if w.mqttClient != nil && w.mqttClient.IsConnected() {
			w.mqttClient.Disconnect(250)
		}

		scheme := "tcp"
		if w.GetConfig().Loggers.MQTT.TLSSupport {
			scheme = "ssl"
		}
		brokerURL := fmt.Sprintf("%s://%s:%d",
			scheme,
			w.GetConfig().Loggers.MQTT.RemoteAddress,
			w.GetConfig().Loggers.MQTT.RemotePort)

		w.LogInfo("connecting to mqtt broker %s", brokerURL)

		opts := mqtt.NewClientOptions()
		opts.AddBroker(brokerURL)
		opts.SetClientID(fmt.Sprintf("dnscollector-%s-%d", w.GetName(), time.Now().Unix()))
		opts.SetConnectTimeout(time.Duration(w.GetConfig().Loggers.MQTT.ConnectTimeout) * time.Second)
		opts.SetAutoReconnect(false)
		opts.SetCleanSession(true)

		if w.GetConfig().Loggers.MQTT.Username != "" {
			opts.SetUsername(w.GetConfig().Loggers.MQTT.Username)
		}
		if w.GetConfig().Loggers.MQTT.Password != "" {
			opts.SetPassword(w.GetConfig().Loggers.MQTT.Password)
		}

		protocolVersion := strings.ToLower(w.GetConfig().Loggers.MQTT.ProtocolVersion)
		switch protocolVersion {
		case "v3":
			opts.SetProtocolVersion(3)
		case "v5":
			opts.SetProtocolVersion(5)
		case mqttProtocolAuto:
			opts.SetProtocolVersion(0)
		}

		if w.GetConfig().Loggers.MQTT.TLSSupport {
			tlsOptions := netutils.TLSOptions{
				InsecureSkipVerify: w.GetConfig().Loggers.MQTT.TLSInsecure,
				MinVersion:         w.GetConfig().Loggers.MQTT.TLSMinVersion,
				CAFile:             w.GetConfig().Loggers.MQTT.CAFile,
				CertFile:           w.GetConfig().Loggers.MQTT.CertFile,
				KeyFile:            w.GetConfig().Loggers.MQTT.KeyFile,
			}

			tlsConfig, err := netutils.TLSClientConfig(tlsOptions)
			if err != nil {
				w.LogError("tls config failed: %s", err)
				w.LogInfo("retry to connect in %d seconds", w.GetConfig().Loggers.MQTT.RetryInterval)
				time.Sleep(time.Duration(w.GetConfig().Loggers.MQTT.RetryInterval) * time.Second)
				continue
			}

			u, err := url.Parse(brokerURL)
			if err == nil && u.Hostname() != "" {
				tlsConfig.ServerName = u.Hostname()
			}

			opts.SetTLSConfig(tlsConfig)
		}

		opts.SetOnConnectHandler(func(client mqtt.Client) {
			w.LogInfo("mqtt broker connected")
			w.writerReady = true
			select {
			case w.mqttReady <- true:
			default:
			}
		})

		opts.SetConnectionLostHandler(func(client mqtt.Client, err error) {
			w.LogError("mqtt connection lost: %s", err)
			w.writerReady = false
			select {
			case w.mqttReconnect <- true:
			default:
			}
		})

		w.mqttClient = mqtt.NewClient(opts)

		token := w.mqttClient.Connect()
		if token.WaitTimeout(time.Duration(w.GetConfig().Loggers.MQTT.ConnectTimeout) * time.Second) {
			if token.Error() != nil {
				w.LogError("connection failed: %s", token.Error())
				w.LogInfo("retry to connect in %d seconds", w.GetConfig().Loggers.MQTT.RetryInterval)
				time.Sleep(time.Duration(w.GetConfig().Loggers.MQTT.RetryInterval) * time.Second)
				continue
			}
		} else {
			w.LogError("connection timeout")
			w.LogInfo("retry to connect in %d seconds", w.GetConfig().Loggers.MQTT.RetryInterval)
			time.Sleep(time.Duration(w.GetConfig().Loggers.MQTT.RetryInterval) * time.Second)
			continue
		}

		select {
		case w.mqttReady <- true:
		case <-w.stopReconnect:
			return
		}

		select {
		case <-w.mqttReconnect:
			w.LogInfo("reconnecting to mqtt broker...")
		case <-w.stopReconnect:
			return
		}
	}
}

func (w *MQTT) FlushBuffer(buf *[]*dnsutils.DNSMessage) {
	defer func() {
		for _, dm := range *buf {
			dm.Release()
		}
		*buf = nil
	}()

	buffer := new(bytes.Buffer)

	for _, dm := range *buf {
		buffer.Reset()

		var payload string
		switch w.GetConfig().Loggers.MQTT.Mode {
		case config.ModeText:
			// get buffer from pool
			buf := w.GetTextBuffer()

			// write the DNSMessage to the buffer
			var err error
			if w.textFormatter != nil {
				err = w.textFormatter.Format(dm, buf)
			} else {
				err = dm.ToTextLine(
					w.textFormat,
					w.GetConfig().Global.TextFormatDelimiter,
					w.GetConfig().Global.TextFormatBoundary,
					buf,
				)
			}
			if err != nil {
				w.CountEgressDiscarded()
				w.LogError("process mqtt: could not encode to text format: %s", err)
				w.PutTextBuffer(buf) // return buffer in case of error
				continue
			}

			// assign buffer content to MQTT payload
			payload = buf.String()
			// return buffer after use
			w.PutTextBuffer(buf)
		case config.ModeJSON:
			json.NewEncoder(buffer).Encode(dm)
			payload = buffer.String()
		case config.ModeFlatJSON:
			if dm.Relabeling != nil {
				flat, err := dm.Flatten()
				if err != nil {
					w.LogError("flattening DNS message failed: %e", err)
					w.CountEgressDiscarded()
					continue
				}
				json.NewEncoder(buffer).Encode(flat)
				payload = buffer.String()
			} else {
				buffer.Reset()
				dm.GetTimestampRFC3339()
				dm.EncodeFlatJSON(buffer)
				buffer.WriteByte('\n')
				payload = buffer.String()
			}
		}

		token := w.mqttClient.Publish(
			w.GetConfig().Loggers.MQTT.Topic,
			w.GetConfig().Loggers.MQTT.QOS,
			false,
			payload,
		)

		if !token.WaitTimeout(5 * time.Second) {
			w.LogError("publish timeout")
			w.writerReady = false
			<-w.mqttReconnect
			break
		}

		if token.Error() != nil {
			w.LogError("publish failed: %s", token.Error())
			w.writerReady = false
			<-w.mqttReconnect
			break
		}
	}
}

func (w *MQTT) StartCollect() {
	w.LogInfo("starting data collection")
	defer w.CollectDone()

	defaultRoutes, defaultNames := GetRoutes(w.GetDefaultRoutes())
	droppedRoutes, droppedNames := GetRoutes(w.GetDroppedRoutes())

	subprocessors := transformers.NewTransforms(&w.GetConfig().OutgoingTransformers, w.GetLogger(), w.GetName(), w.GetOutputChannelAsList(), 0)

	go w.StartLogging()

	for {
		select {
		case <-w.OnStop():
			w.StopLogger()
			subprocessors.Reset()
			close(w.stopReconnect)
			return

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
				w.CountIngressTraffic()

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

func (w *MQTT) StartLogging() {
	w.LogInfo("logging has started")
	defer w.LoggingDone()

	bufferDm := []*dnsutils.DNSMessage{}

	flushInterval := time.Duration(w.GetConfig().Loggers.MQTT.FlushInterval) * time.Second
	flushTimer := time.NewTimer(flushInterval)

	go w.ConnectToMQTT()

	for {
		select {
		case <-w.OnLoggerStopped():
			w.Disconnect()
			return

		case <-w.mqttReady:
			w.LogInfo("mqtt client connected with success")

		case batch, opened := <-w.GetOutputChannel():
			if !opened {
				w.LogInfo("output channel closed!")
				return
			}

			for _, dm := range batch.Messages {
				if !w.writerReady {
					w.CountEgressDiscarded()
					continue
				}

				dm.Retain(1)
				bufferDm = append(bufferDm, dm)

				if len(bufferDm) >= w.GetConfig().Loggers.MQTT.BufferSize {
					w.FlushBuffer(&bufferDm)
				}
			}
			batch.Release()

		case <-flushTimer.C:
			if !w.writerReady {
				for _, dm := range bufferDm {
					dm.Release()
				}
				bufferDm = nil
			}

			if len(bufferDm) > 0 {
				w.FlushBuffer(&bufferDm)
			}

			flushTimer.Reset(flushInterval)
		}
	}
}

func init() {
	RegisterLogger("mqtt", func(c *config.Config) bool { return c.Loggers.MQTT.Enable }, func(c *config.Config, l *logger.Logger, s string) Worker {
		return NewMQTT(c, l, s)
	})
}
