package workers

import (
	"bytes"
	"context"
	"encoding/json"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/dmachard/go-dnscollector/dnsutils"
	"github.com/dmachard/go-dnscollector/pkgconfig"
	"github.com/dmachard/go-dnscollector/transformers"
	"github.com/dmachard/go-logger"
	"github.com/dmachard/go-netutils"
	"github.com/segmentio/kafka-go"
	"github.com/segmentio/kafka-go/compress"
	"github.com/segmentio/kafka-go/sasl/plain"
	"github.com/segmentio/kafka-go/sasl/scram"
)

type KafkaProducer struct {
	*GenericWorker
	textFormat         []string
	kafkaConnected     bool
	compressCodec      compress.Codec
	kafkaConns         map[int]*kafka.Conn // Map to store connections by partition
	lastPartitionIndex *int
	triggerReconnect   chan bool
	connMutex          sync.RWMutex
	reconnecting       bool
	reconnectMutex     sync.Mutex
}

func NewKafkaProducer(config *pkgconfig.Config, logger *logger.Logger, name string) *KafkaProducer {
	bufSize := config.Global.Worker.ChannelBufferSize
	if config.Loggers.KafkaProducer.ChannelBufferSize > 0 {
		bufSize = config.Loggers.KafkaProducer.ChannelBufferSize
	}
	w := &KafkaProducer{
		GenericWorker: NewGenericWorker(config, logger, name, "kafka", bufSize, pkgconfig.DefaultMonitor),
		// kafkaReady:     make(chan bool),
		// kafkaReconnect: make(chan bool),
		kafkaConns:       make(map[int]*kafka.Conn),
		triggerReconnect: make(chan bool, 1),
	}
	w.ReadConfig()
	return w
}

func (w *KafkaProducer) ReadConfig() {
	if len(w.GetConfig().Loggers.KafkaProducer.TextFormat) > 0 {
		w.textFormat = strings.Fields(w.GetConfig().Loggers.KafkaProducer.TextFormat)
	} else {
		w.textFormat = strings.Fields(w.GetConfig().Global.TextFormat)
	}

	if w.GetConfig().Loggers.KafkaProducer.Compression != pkgconfig.CompressNone {
		switch w.GetConfig().Loggers.KafkaProducer.Compression {
		case pkgconfig.CompressGzip:
			w.compressCodec = &compress.GzipCodec
		case pkgconfig.CompressLz4:
			w.compressCodec = &compress.Lz4Codec
		case pkgconfig.CompressSnappy:
			w.compressCodec = &compress.SnappyCodec
		case pkgconfig.CompressZstd:
			w.compressCodec = &compress.ZstdCodec
		case pkgconfig.CompressNone:
			w.compressCodec = nil
		default:
			w.LogFatal(pkgconfig.PrefixLogWorker+"["+w.GetName()+"] kafka - invalid compress mode: ", w.GetConfig().Loggers.KafkaProducer.Compression)
		}
	}
}

func (w *KafkaProducer) Disconnect() {
	w.connMutex.Lock()
	defer w.connMutex.Unlock()

	for _, conn := range w.kafkaConns {
		if conn != nil {
			w.LogInfo("closing connection per partition")
			conn.Close()
		}
	}
	w.kafkaConns = make(map[int]*kafka.Conn) // Clear the map
}

func (w *KafkaProducer) createDialer() *kafka.Dialer {
	dialer := &kafka.Dialer{
		Timeout:   time.Duration(w.GetConfig().Loggers.KafkaProducer.ConnectTimeout) * time.Second,
		DualStack: true,
	}

	// TLS Support
	if w.GetConfig().Loggers.KafkaProducer.TLSSupport {
		tlsOptions := netutils.TLSOptions{
			InsecureSkipVerify: w.GetConfig().Loggers.KafkaProducer.TLSInsecure,
			MinVersion:         w.GetConfig().Loggers.KafkaProducer.TLSMinVersion,
			CAFile:             w.GetConfig().Loggers.KafkaProducer.CAFile,
			CertFile:           w.GetConfig().Loggers.KafkaProducer.CertFile,
			KeyFile:            w.GetConfig().Loggers.KafkaProducer.KeyFile,
		}

		tlsConfig, err := netutils.TLSClientConfig(tlsOptions)
		if err != nil {
			w.LogFatal("logger=kafka - tls config failed:", err)
		}
		dialer.TLS = tlsConfig
	}

	// SASL Support
	if w.GetConfig().Loggers.KafkaProducer.SaslSupport {
		switch w.GetConfig().Loggers.KafkaProducer.SaslMechanism {
		case pkgconfig.SASLMechanismPlain:
			mechanism := plain.Mechanism{
				Username: w.GetConfig().Loggers.KafkaProducer.SaslUsername,
				Password: w.GetConfig().Loggers.KafkaProducer.SaslPassword,
			}
			dialer.SASLMechanism = mechanism
		case pkgconfig.SASLMechanismScram:
			mechanism, err := scram.Mechanism(
				scram.SHA512,
				w.GetConfig().Loggers.KafkaProducer.SaslUsername,
				w.GetConfig().Loggers.KafkaProducer.SaslPassword,
			)
			if err != nil {
				panic(err)
			}
			dialer.SASLMechanism = mechanism
		}
	}

	return dialer
}

func (w *KafkaProducer) ConnectToKafka(ctx context.Context) {
	topic := w.GetConfig().Loggers.KafkaProducer.Topic
	partition := w.GetConfig().Loggers.KafkaProducer.Partition

	// Backoff exponentiel : 1s, 2s, 4s, 8s, 16s, 30s (max)
	backoff := 1 * time.Second
	maxBackoff := 30 * time.Second

	// list of brokers to dial to
	brokers := strings.Split(w.GetConfig().Loggers.KafkaProducer.RemoteAddress, ",")
	port := w.GetConfig().Loggers.KafkaProducer.RemotePort

	for {
		select {
		case <-ctx.Done():
			w.LogInfo("kafka connection goroutine stopped")
			return
		default:
		}

		w.Disconnect()

		if partition == nil {
			w.LogInfo("connecting to kafka brokers=%v port=%d topic=%s (all partitions)", brokers, port, topic)
		} else {
			w.LogInfo("connecting to kafka brokers=%v port=%d topic=%s partition=%d", brokers, port, topic, *partition)
		}

		// prepare dialer
		dialer := w.createDialer()

		// connections established ?
		connected := false
		if partition == nil {
			connected = w.connectAllPartitions(ctx, dialer, brokers, port, topic)
		} else {
			connected = w.connectSinglePartition(ctx, dialer, brokers, port, topic, *partition)
		}

		if connected {
			w.LogInfo("successfully connected to kafka")
			w.connMutex.Lock()
			w.kafkaConnected = true
			w.connMutex.Unlock()

			w.reconnectMutex.Lock()
			w.reconnecting = false
			w.reconnectMutex.Unlock()
			return
		}

		// Retry
		w.LogInfo("failed to connect, retrying in %v", backoff)
		select {
		case <-ctx.Done():
			return
		case <-time.After(backoff):
			// double backoff time
			backoff *= 2
			if backoff > maxBackoff {
				backoff = maxBackoff
			}
		}
	}
}

func (w *KafkaProducer) connectAllPartitions(ctx context.Context, dialer *kafka.Dialer, brokers []string, port int, topic string) bool {
	// find partitions from brokers
	var partitions []kafka.Partition
	var bootstrapAddr string

	for _, broker := range brokers {
		addr := broker + ":" + strconv.Itoa(port)
		w.LogInfo("[bootstrap] looking up partitions on %s", addr)

		var err error
		partitions, err = dialer.LookupPartitions(ctx, "tcp", addr, topic)
		if err != nil {
			w.LogError("[bootstrap] failed to lookup partitions on %s: %s", addr, err)
			continue
		}

		bootstrapAddr = addr
		break
	}

	if bootstrapAddr == "" {
		w.LogError("failed to lookup partitions from any broker")
		return false
	}

	w.LogInfo("[bootstrap] found %d partitions from %s", len(partitions), bootstrapAddr)

	// connect to all partitions
	w.connMutex.Lock()
	defer w.connMutex.Unlock()

	failedPartitions := []int{}
	for _, p := range partitions {
		conn, err := dialer.DialLeader(ctx, "tcp", bootstrapAddr, p.Topic, p.ID)
		if err != nil {
			w.LogError("[partition=%d] failed to connect: %s", p.ID, err)
			failedPartitions = append(failedPartitions, p.ID)
			continue
		}
		w.kafkaConns[p.ID] = conn
		w.LogInfo("[partition=%d] connected successfully", p.ID)
	}

	// check if any partition failed
	if len(failedPartitions) > 0 {
		w.LogError("failed to connect to partitions: %v", failedPartitions)
		// cleanup
		for _, conn := range w.kafkaConns {
			conn.Close()
		}
		w.kafkaConns = make(map[int]*kafka.Conn)
		return false
	}

	return true
}

func (w *KafkaProducer) connectSinglePartition(ctx context.Context, dialer *kafka.Dialer, brokers []string, port int, topic string, partition int) bool {
	w.connMutex.Lock()
	defer w.connMutex.Unlock()

	for _, broker := range brokers {
		addr := broker + ":" + strconv.Itoa(port)
		conn, err := dialer.DialLeader(ctx, "tcp", addr, topic, partition)
		if err != nil {
			w.LogError("failed to connect to partition %d on %s: %s", partition, addr, err)
			continue
		}

		w.kafkaConns[partition] = conn
		w.LogInfo("[partition=%d] connected successfully to %s", partition, addr)
		return true
	}

	return false
}

func (w *KafkaProducer) FlushBuffer(buf *[]dnsutils.DNSMessage) {
	w.connMutex.RLock()
	connected := w.kafkaConnected
	w.connMutex.RUnlock()

	if !connected {
		*buf = nil
		return
	}

	msgs := []kafka.Message{}
	buffer := new(bytes.Buffer)

	for _, dm := range *buf {
		var strDm string
		switch w.GetConfig().Loggers.KafkaProducer.Mode {
		case pkgconfig.ModeText:
			strDm = dm.String(w.textFormat, w.GetConfig().Global.TextFormatDelimiter, w.GetConfig().Global.TextFormatBoundary)
		case pkgconfig.ModeJSON:
			json.NewEncoder(buffer).Encode(dm)
			strDm = buffer.String()
			buffer.Reset()
		case pkgconfig.ModeFlatJSON:
			flat, err := dm.Flatten()
			if err != nil {
				w.LogError("flattening DNS message failed: %e", err)
			}
			json.NewEncoder(buffer).Encode(flat)
			strDm = buffer.String()
			buffer.Reset()
		}

		msgs = append(msgs, kafka.Message{
			Key:   []byte(dm.DNSTap.Identity),
			Value: []byte(strDm),
		})
	}

	w.connMutex.RLock()
	defer w.connMutex.RUnlock()

	partition := w.GetConfig().Loggers.KafkaProducer.Partition
	var err error

	if partition == nil {
		// Round-robin between partitions
		if w.lastPartitionIndex == nil {
			w.lastPartitionIndex = new(int)
		}
		numPartitions := len(w.kafkaConns)
		if numPartitions == 0 {
			w.LogError("no kafka connections available")
			w.connMutex.RUnlock()
			w.connMutex.Lock()
			w.kafkaConnected = false
			w.connMutex.Unlock()
			w.connMutex.RLock()

			// Trigger reconnection
			select {
			case w.triggerReconnect <- true:
			default:
			}
			return
		}

		conn := w.kafkaConns[*w.lastPartitionIndex]
		if w.GetConfig().Loggers.KafkaProducer.Compression == pkgconfig.CompressNone {
			_, err = conn.WriteMessages(msgs...)
		} else {
			_, err = conn.WriteCompressedMessages(w.compressCodec, msgs...)
		}

		if err != nil {
			w.LogError("[partition=%d] write failed: %v", *w.lastPartitionIndex, err.Error())
			w.connMutex.RUnlock()
			w.connMutex.Lock()
			w.kafkaConnected = false
			w.connMutex.Unlock()
			w.connMutex.RLock()

			// Trigger reconnection
			select {
			case w.triggerReconnect <- true:
			default:
			}

			return
		}

		*w.lastPartitionIndex = (*w.lastPartitionIndex + 1) % numPartitions
	} else {
		// specific partition
		conn, exists := w.kafkaConns[*partition]
		if !exists {
			w.LogError("[partition=%d] connection not available", *partition)
			w.connMutex.RUnlock()
			w.connMutex.Lock()
			w.kafkaConnected = false
			w.connMutex.Unlock()
			w.connMutex.RLock()

			// Trigger reconnection
			select {
			case w.triggerReconnect <- true:
			default:
			}

			return
		}

		if w.GetConfig().Loggers.KafkaProducer.Compression == pkgconfig.CompressNone {
			_, err = conn.WriteMessages(msgs...)
		} else {
			_, err = conn.WriteCompressedMessages(w.compressCodec, msgs...)
		}

		if err != nil {
			w.LogError("[partition=%d] write failed: %v", *partition, err.Error())
			w.connMutex.RUnlock()
			w.connMutex.Lock()
			w.kafkaConnected = false
			w.connMutex.Unlock()
			w.connMutex.RLock()

			// Trigger reconnection
			select {
			case w.triggerReconnect <- true:
			default:
			}

			return
		}
	}

	*buf = nil
}

func (w *KafkaProducer) StartCollect() {
	w.LogInfo("starting data collection")
	defer w.CollectDone()

	// prepare next channels
	defaultRoutes, defaultNames := GetRoutes(w.GetDefaultRoutes())
	droppedRoutes, droppedNames := GetRoutes(w.GetDroppedRoutes())

	// prepare transforms
	subprocessors := transformers.NewTransforms(&w.GetConfig().OutgoingTransformers, w.GetLogger(), w.GetName(), w.GetOutputChannelAsList(), 0)

	// goroutine to process transformed dns messages
	go w.StartLogging()

	// loop to process incoming messages
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

		case dm, opened := <-w.GetInputChannel():
			if !opened {
				w.LogInfo("input channel closed!")
				return
			}
			// count global messages
			w.CountIngressTraffic()

			// apply transforms, init dns message with additional parts if necessary
			transformResult, err := subprocessors.ProcessMessage(&dm)
			if err != nil {
				w.LogError(err.Error())
			}
			if transformResult == transformers.ReturnDrop {
				w.SendDroppedTo(droppedRoutes, droppedNames, dm)
				continue
			}

			// send to output channel
			w.CountEgressTraffic()
			w.GetOutputChannel() <- dm

			// send to next ?
			w.SendForwardedTo(defaultRoutes, defaultNames, dm)
		}
	}
}

func (w *KafkaProducer) StartLogging() {
	w.LogInfo("logging has started")
	defer w.LoggingDone()

	ctx, cancelKafka := context.WithCancel(context.Background())
	defer cancelKafka()

	// init buffer
	bufferDm := []dnsutils.DNSMessage{}

	// init flush timer for buffer
	flushInterval := time.Duration(w.GetConfig().Loggers.KafkaProducer.FlushInterval) * time.Second
	flushTimer := time.NewTimer(flushInterval)

	// initiate connection to kafka
	go w.ConnectToKafka(ctx)

	for {
		select {
		case <-w.OnLoggerStopped():
			// closing kafka connection if exist
			w.Disconnect()
			return

		case <-w.triggerReconnect:
			// check if we are still connected
			w.reconnectMutex.Lock()
			alreadyReconnecting := w.reconnecting
			if !alreadyReconnecting {
				w.reconnecting = true
			}
			w.reconnectMutex.Unlock()

			// if not, start reconnection routine
			if alreadyReconnecting {
				continue
			}

			w.connMutex.RLock()
			connected := w.kafkaConnected
			w.connMutex.RUnlock()

			if !connected {
				w.LogWarning("write error detected, attempting reconnection")
				go w.ConnectToKafka(ctx)
			} else {
				// reset reconnecting flag
				w.reconnectMutex.Lock()
				w.reconnecting = false
				w.reconnectMutex.Unlock()
			}

		// incoming dns message to process
		case dm, opened := <-w.GetOutputChannel():
			if !opened {
				w.LogInfo("output channel closed!")
				return
			}

			w.connMutex.RLock()
			connected := w.kafkaConnected
			w.connMutex.RUnlock()

			// drop dns message if the connection is not ready to avoid memory leak or
			// to block the channel
			if !connected {
				continue
			}

			// append dns message to buffer
			bufferDm = append(bufferDm, dm)

			// buffer is full ?
			if len(bufferDm) >= w.GetConfig().Loggers.KafkaProducer.BatchSize {
				w.FlushBuffer(&bufferDm)
			}

		// flush the buffer
		case <-flushTimer.C:
			if len(bufferDm) > 0 {
				w.FlushBuffer(&bufferDm)
			}

			// restart timer
			flushTimer.Reset(flushInterval)
		}
	}
}
