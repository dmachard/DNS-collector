package workers

import (
	"bytes"
	"context"
	"encoding/json"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/dmachard/go-dnscollector/v2/dnsutils"
	"github.com/dmachard/go-dnscollector/v2/pkg/config"
	"github.com/dmachard/go-dnscollector/v2/transformers"
	"github.com/dmachard/go-logger"
	"github.com/dmachard/go-netutils"
	"github.com/segmentio/kafka-go"
	"github.com/segmentio/kafka-go/sasl/plain"
	"github.com/segmentio/kafka-go/sasl/scram"
)

var supportedWriterCompressions = map[string]kafka.Compression{
	config.CompressGzip:   kafka.Gzip,
	config.CompressLz4:    kafka.Lz4,
	config.CompressSnappy: kafka.Snappy,
	config.CompressZstd:   kafka.Zstd,
	config.CompressNone:   0,
}

var supportedBalancers = map[string]kafka.Balancer{
	"round-robin":    &kafka.RoundRobin{},
	"least-bytes":    &kafka.LeastBytes{},
	"hash":           &kafka.Hash{},
	"reference-hash": &kafka.ReferenceHash{},
	"crc32":          &kafka.CRC32Balancer{},
}

type fixedPartitionBalancer int

func (b fixedPartitionBalancer) Balance(msg kafka.Message, partitions ...int) int {
	target := int(b)
	for _, p := range partitions {
		if p == target {
			return target
		}
	}
	if len(partitions) > 0 {
		return partitions[0]
	}
	return target
}

type KafkaProducer struct {
	*GenericWorker
	textFormat    []string
	textFormatter *dnsutils.TextFormatter
	writer        *kafka.Writer
	writerMutex   sync.RWMutex
}

func NewKafkaProducer(cfg *config.Config, logger *logger.Logger, name string) *KafkaProducer {
	bufSize := cfg.Global.Worker.ChannelBufferSize
	w := &KafkaProducer{
		GenericWorker: NewGenericWorker(cfg, logger, name, "kafka", bufSize, config.DefaultMonitor),
	}
	w.ReadConfig()
	w.writer = w.createWriter()
	return w
}

func (w *KafkaProducer) ReadConfig() {
	kafkaConfig := w.GetConfig().Loggers.KafkaProducer
	if len(kafkaConfig.TextFormat) > 0 {
		w.textFormat = strings.Fields(kafkaConfig.TextFormat)
	} else {
		w.textFormat = strings.Fields(w.GetConfig().Global.TextFormat)
	}

	var errFormatter error
	w.textFormatter, errFormatter = dnsutils.NewTextFormatter(w.textFormat, w.GetConfig().Global.TextFormatDelimiter, w.GetConfig().Global.TextFormatBoundary)
	if errFormatter != nil {
		w.LogFatal(config.PrefixLogWorker + "invalid text format: " + errFormatter.Error())
	}

	if _, ok := supportedWriterCompressions[kafkaConfig.Compression]; !ok {
		w.LogFatal(config.PrefixLogWorker+"["+w.GetName()+"] kafka - invalid compress mode: ", kafkaConfig.Compression)
	}

	if kafkaConfig.Partition == nil && len(kafkaConfig.Balancer) > 0 {
		if _, ok := supportedBalancers[kafkaConfig.Balancer]; !ok {
			w.LogFatal(config.PrefixLogWorker+"["+w.GetName()+"] kafka - invalid balancer: ", kafkaConfig.Balancer)
		}
	}
}

func (w *KafkaProducer) createWriter() *kafka.Writer {
	kafkaConfig := w.GetConfig().Loggers.KafkaProducer

	rawAddresses := strings.Split(kafkaConfig.RemoteAddress, ",")
	addresses := make([]string, 0, len(rawAddresses))
	for _, addr := range rawAddresses {
		addr = strings.TrimSpace(addr)
		if addr == "" {
			continue
		}
		if !strings.Contains(addr, ":") {
			addr = net.JoinHostPort(addr, strconv.Itoa(kafkaConfig.RemotePort))
		}
		addresses = append(addresses, addr)
	}

	transport := &kafka.Transport{
		DialTimeout: time.Duration(kafkaConfig.ConnectTimeout) * time.Second,
		IdleTimeout: 30 * time.Second,
		ClientID:    kafkaConfig.ClientID,
	}

	// TLS Support
	if kafkaConfig.TLSSupport {
		tlsOptions := netutils.TLSOptions{
			InsecureSkipVerify: kafkaConfig.TLSInsecure,
			MinVersion:         kafkaConfig.TLSMinVersion,
			CAFile:             kafkaConfig.CAFile,
			CertFile:           kafkaConfig.CertFile,
			KeyFile:            kafkaConfig.KeyFile,
		}

		tlsConfig, err := netutils.TLSClientConfig(tlsOptions)
		if err != nil {
			w.LogFatal("logger=kafka - tls config failed:", err)
		}
		transport.TLS = tlsConfig
	}

	// SASL Support
	if kafkaConfig.SaslSupport {
		username, password := kafkaConfig.SaslUsername, kafkaConfig.SaslPassword

		switch kafkaConfig.SaslMechanism {
		case config.SASLMechanismPlain:
			transport.SASL = plain.Mechanism{Username: username, Password: password}
		case config.SASLMechanismSha512, config.SASLMechanismSha256:
			algo := scram.SHA512
			if kafkaConfig.SaslMechanism == config.SASLMechanismSha256 {
				algo = scram.SHA256
			}
			mechanism, err := scram.Mechanism(algo, username, password)
			if err != nil {
				w.LogFatal("logger=kafka - sasl scram failed:", err)
			}
			transport.SASL = mechanism
		}
	}

	var balancer kafka.Balancer = &kafka.RoundRobin{}
	if kafkaConfig.Partition != nil {
		balancer = fixedPartitionBalancer(*kafkaConfig.Partition)
	} else if b, ok := supportedBalancers[kafkaConfig.Balancer]; ok {
		balancer = b
	}

	compression := kafka.Compression(0)
	if comp, ok := supportedWriterCompressions[kafkaConfig.Compression]; ok {
		compression = comp
	}

	writer := &kafka.Writer{
		Addr:                   kafka.TCP(addresses...),
		Topic:                  kafkaConfig.Topic,
		Balancer:               balancer,
		Compression:            compression,
		Transport:              transport,
		RequiredAcks:           kafka.RequireOne,
		WriteTimeout:           time.Duration(kafkaConfig.ConnectTimeout) * time.Second,
		MaxAttempts:            3,
		AllowAutoTopicCreation: true,
		BatchSize:              1,
		BatchTimeout:           10 * time.Millisecond,
	}

	return writer
}

func (w *KafkaProducer) Disconnect() {
	w.writerMutex.Lock()
	defer w.writerMutex.Unlock()

	if w.writer != nil {
		w.LogInfo("closing kafka writer")
		if err := w.writer.Close(); err != nil {
			w.LogError("error closing kafka writer: %v", err)
		}
	}
}

func (w *KafkaProducer) FlushBuffer(buf *[]*dnsutils.DNSMessage) {
	defer func() {
		for _, dm := range *buf {
			dm.Release()
		}
		*buf = nil
	}()

	if len(*buf) == 0 {
		return
	}

	kafkaConfig := w.GetConfig().Loggers.KafkaProducer
	globalConfig := w.GetConfig().Global

	msgs := make([]kafka.Message, 0, len(*buf))
	buffer := new(bytes.Buffer)

	for _, dm := range *buf {
		var strDm string
		switch kafkaConfig.Mode {
		case config.ModeText:
			textBuf := w.GetTextBuffer()
			var err error
			if w.textFormatter != nil {
				err = w.textFormatter.Format(dm, textBuf)
			} else {
				err = dm.ToTextLine(
					w.textFormat,
					globalConfig.TextFormatDelimiter,
					globalConfig.TextFormatBoundary,
					textBuf,
				)
			}
			if err != nil {
				w.CountEgressDiscarded()
				w.LogError("could not encode to text format: %s", err)
				w.PutTextBuffer(textBuf)
				continue
			}

			strDm = textBuf.String()
			w.PutTextBuffer(textBuf)
		case config.ModeJSON:
			json.NewEncoder(buffer).Encode(dm)
			strDm = buffer.String()
			buffer.Reset()
		case config.ModeFlatJSON:
			if dm.Relabeling != nil {
				flat, err := dm.Flatten()
				if err != nil {
					w.LogError("flattening DNS message failed: %e", err)
				}
				json.NewEncoder(buffer).Encode(flat)
				strDm = buffer.String()
				buffer.Reset()
			} else {
				dm.GetTimestampRFC3339()
				dm.EncodeFlatJSON(buffer)
				buffer.WriteByte('\n')
				strDm = buffer.String()
				buffer.Reset()
			}
		}

		msg := kafka.Message{
			Key:   []byte(dm.DNSTap.Identity),
			Value: []byte(strDm),
		}
		if kafkaConfig.Partition != nil {
			msg.Partition = *kafkaConfig.Partition
		}

		msgs = append(msgs, msg)
	}

	if len(msgs) == 0 {
		return
	}

	w.writerMutex.RLock()
	writer := w.writer
	w.writerMutex.RUnlock()

	if writer == nil {
		w.LogError("kafka writer is not initialized")
		for range msgs {
			w.CountEgressDiscarded()
		}
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(kafkaConfig.ConnectTimeout)*time.Second)
	defer cancel()

	err := writer.WriteMessages(ctx, msgs...)
	if err != nil {
		w.LogError("kafka write failed: %v", err)
		for range msgs {
			w.CountEgressDiscarded()
		}
	}
}

func (w *KafkaProducer) StartCollect() {
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
			return

		case cfg := <-w.NewConfig():
			w.SetConfig(cfg)
			w.ReadConfig()
			subprocessors.ReloadConfig(&cfg.OutgoingTransformers)

			w.writerMutex.Lock()
			if w.writer != nil {
				w.writer.Close()
			}
			w.writer = w.createWriter()
			w.writerMutex.Unlock()

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

func (w *KafkaProducer) StartLogging() {
	w.LogInfo("logging has started")
	defer w.LoggingDone()

	bufferDm := []*dnsutils.DNSMessage{}
	flushInterval := time.Duration(w.GetConfig().Loggers.KafkaProducer.FlushInterval) * time.Second
	flushTimer := time.NewTimer(flushInterval)

	for {
		select {
		case <-w.OnLoggerStopped():
			w.Disconnect()
			return

		case batch, opened := <-w.GetOutputChannel():
			if !opened {
				w.LogInfo("output channel closed!")
				return
			}

			for _, dm := range batch.Messages {
				dm.Retain(1)
				bufferDm = append(bufferDm, dm)

				if len(bufferDm) >= w.GetConfig().Loggers.KafkaProducer.BatchSize {
					w.FlushBuffer(&bufferDm)
				}
			}
			batch.Release()

		case <-flushTimer.C:
			if len(bufferDm) > 0 {
				w.FlushBuffer(&bufferDm)
			}
			flushTimer.Reset(flushInterval)
		}
	}
}

func init() {
	RegisterLogger("kafkaproducer", func(c *config.Config) bool { return c.Loggers.KafkaProducer.Enable }, func(c *config.Config, l *logger.Logger, s string) Worker {
		return NewKafkaProducer(c, l, s)
	})
}
