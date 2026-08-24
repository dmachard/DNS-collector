package workers

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"encoding/json"
	"errors"
	"io"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/dmachard/go-dnscollector/v2/dnsutils"
	"github.com/dmachard/go-dnscollector/v2/pkgconfig"
	"github.com/dmachard/go-dnscollector/v2/transformers"
	"github.com/dmachard/go-logger"
	"github.com/dmachard/go-netutils"
)

type RedisPub struct {
	*GenericWorker
	stopRead, doneRead                 chan bool
	textFormat                         []string
	textFormatter                      *dnsutils.TextFormatter
	transport                          string
	transportWriter                    *bufio.Writer
	transportConn                      net.Conn
	transportReady, transportReconnect chan bool
	writerReady                        bool
	mu                                 sync.Mutex
}

func NewRedisPub(config *pkgconfig.Config, logger *logger.Logger, name string) *RedisPub {
	bufSize := config.Global.Worker.ChannelBufferSize
	w := &RedisPub{GenericWorker: NewGenericWorker(config, logger, name, "redispub", bufSize, pkgconfig.DefaultMonitor)}
	w.stopRead = make(chan bool)
	w.doneRead = make(chan bool)
	w.transportReady = make(chan bool)
	w.transportReconnect = make(chan bool)
	w.ReadConfig()
	return w
}

func (w *RedisPub) ReadConfig() {
	w.transport = w.GetConfig().Loggers.RedisPub.Transport

	if len(w.GetConfig().Loggers.RedisPub.TextFormat) > 0 {
		w.textFormat = strings.Fields(w.GetConfig().Loggers.RedisPub.TextFormat)
	} else {
		w.textFormat = strings.Fields(w.GetConfig().Global.TextFormat)
	}

	var errFormatter error
	w.textFormatter, errFormatter = dnsutils.NewTextFormatter(w.textFormat, w.GetConfig().Global.TextFormatDelimiter, w.GetConfig().Global.TextFormatBoundary)
	if errFormatter != nil {
		w.LogFatal(pkgconfig.PrefixLogWorker + "invalid text format: " + errFormatter.Error())
	}
}

func (w *RedisPub) getTransportConn() net.Conn {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.transportConn
}

func (w *RedisPub) setTransportConn(conn net.Conn) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.transportConn = conn
}

func (w *RedisPub) Disconnect() {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.transportConn != nil {
		w.LogInfo("closing redispub connection")
		conn := w.transportConn
		w.transportConn = nil
		conn.Close()
	}
}

func (w *RedisPub) triggerReconnect() {
	select {
	case w.transportReconnect <- true:
	default:
	}
}

func (w *RedisPub) ReadFromConnection() {
	buffer := make([]byte, 4096)

	conn := w.getTransportConn()
	if conn == nil {
		return
	}

	go func() {
		for {
			_, err := conn.Read(buffer)
			if err != nil {
				if errors.Is(err, io.EOF) || errors.Is(err, net.ErrClosed) {
					w.LogInfo("read from connection terminated")
					w.triggerReconnect()
					break
				}
				w.LogError("Error on reading: %s", err.Error())
				w.triggerReconnect()
			}
			// We just discard the data
		}
	}()

	// block goroutine until receive true event in stopRead channel
	<-w.stopRead
	w.doneRead <- true

	w.LogInfo("read goroutine terminated")
}

func (w *RedisPub) ConnectToRemote() {
	for {
		w.mu.Lock()
		if w.transportConn != nil {
			conn := w.transportConn
			w.transportConn = nil
			w.mu.Unlock()
			conn.Close()
		} else {
			w.mu.Unlock()
		}

		address := w.GetConfig().Loggers.RedisPub.RemoteAddress + ":" + strconv.Itoa(w.GetConfig().Loggers.RedisPub.RemotePort)
		connTimeout := time.Duration(w.GetConfig().Loggers.RedisPub.ConnectTimeout) * time.Second

		var conn net.Conn
		var err error

		switch w.transport {
		case netutils.SocketUnix:
			address = w.GetConfig().Loggers.RedisPub.RemoteAddress
			w.LogInfo("connecting to %s://%s", w.transport, address)
			conn, err = net.DialTimeout(w.transport, address, connTimeout)

		case netutils.SocketTCP:
			w.LogInfo("connecting to %s://%s", w.transport, address)
			conn, err = net.DialTimeout(w.transport, address, connTimeout)

		case netutils.SocketTLS:
			w.LogInfo("connecting to %s://%s", w.transport, address)

			var tlsConfig *tls.Config

			tlsOptions := netutils.TLSOptions{
				InsecureSkipVerify: w.GetConfig().Loggers.RedisPub.TLSInsecure,
				MinVersion:         w.GetConfig().Loggers.RedisPub.TLSMinVersion,
				CAFile:             w.GetConfig().Loggers.RedisPub.CAFile,
				CertFile:           w.GetConfig().Loggers.RedisPub.CertFile,
				KeyFile:            w.GetConfig().Loggers.RedisPub.KeyFile,
			}

			tlsConfig, err = netutils.TLSClientConfig(tlsOptions)
			if err == nil {
				dialer := &net.Dialer{Timeout: connTimeout}
				conn, err = tls.DialWithDialer(dialer, netutils.SocketTCP, address, tlsConfig)
			}

		default:
			w.LogFatal("logger=redispub - invalid transport:", w.transport)
		}

		// something is wrong during connection ?
		if err != nil {
			w.LogError("%s", err)
			w.LogInfo("retry to connect in %d seconds", w.GetConfig().Loggers.RedisPub.RetryInterval)
			time.Sleep(time.Duration(w.GetConfig().Loggers.RedisPub.RetryInterval) * time.Second)
			continue
		}

		w.setTransportConn(conn)

		// signal that the transport is ready. reconnects are triggered by the
		// main worker loop when the remote socket is closed or a write fails.
		w.transportReady <- true
		<-w.transportReconnect
	}
}

func (w *RedisPub) FlushBuffer(buf *[]*dnsutils.DNSMessage) {
	defer func() {
		for _, dm := range *buf {
			dm.Release()
		}
		*buf = nil
	}()

	// create escaping buffer
	escapeBuffer := new(bytes.Buffer)
	// create a new encoder that writes to the buffer
	encoder := json.NewEncoder(escapeBuffer)

	for _, dm := range *buf {
		escapeBuffer.Reset()

		cmd := "PUBLISH " + strconv.Quote(w.GetConfig().Loggers.RedisPub.RedisChannel) + " "
		w.transportWriter.WriteString(cmd)

		if w.GetConfig().Loggers.RedisPub.Mode == pkgconfig.ModeText {
			textBuf := w.GetTextBuffer()
			var err error
			if w.textFormatter != nil {
				err = w.textFormatter.Format(dm, textBuf)
			} else {
				err = dm.ToTextLine(
					w.textFormat,
					w.GetConfig().Global.TextFormatDelimiter,
					w.GetConfig().Global.TextFormatBoundary,
					textBuf,
				)
			}
			if err != nil {
				w.CountEgressDiscarded()
				w.LogError("could not encode to text format: %s", err)
				w.PutTextBuffer(textBuf)
				continue
			}

			// Write text line directly without extra quotes
			w.transportWriter.Write(textBuf.Bytes())
			w.transportWriter.WriteString(w.GetConfig().Loggers.RedisPub.PayloadDelimiter)

			w.PutTextBuffer(textBuf)
		}

		if w.GetConfig().Loggers.RedisPub.Mode == pkgconfig.ModeJSON {
			encoder.Encode(dm)
			w.transportWriter.WriteString(strconv.Quote(escapeBuffer.String()))
			w.transportWriter.WriteString(w.GetConfig().Loggers.RedisPub.PayloadDelimiter)
		}

		if w.GetConfig().Loggers.RedisPub.Mode == pkgconfig.ModeFlatJSON {
			if dm.Relabeling != nil {
				flat, err := dm.Flatten()
				if err != nil {
					w.LogError("flattening DNS message failed: %e", err)
					continue
				}
				encoder.Encode(flat)
			} else {
				escapeBuffer.Reset()
				dm.GetTimestampRFC3339()
				dm.EncodeFlatJSON(escapeBuffer)
			}
			w.transportWriter.WriteString(strconv.Quote(escapeBuffer.String()))
			w.transportWriter.WriteString(w.GetConfig().Loggers.RedisPub.PayloadDelimiter)
		}
	}

	if err := w.transportWriter.Flush(); err != nil {
		w.LogError("redis flush error: %s", err.Error())
		w.writerReady = false
		w.triggerReconnect()
	}
}

func (w *RedisPub) StartCollect() {
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

func (w *RedisPub) StartLogging() {
	w.LogInfo("logging has started")
	defer w.LoggingDone()

	// init buffer
	bufferDm := []*dnsutils.DNSMessage{}

	// init flush timer for buffer
	flushInterval := time.Duration(w.GetConfig().Loggers.RedisPub.FlushInterval) * time.Second
	flushTimer := time.NewTimer(flushInterval)

	// init remote conn
	go w.ConnectToRemote()

	for {
		select {
		case <-w.OnLoggerStopped():
			// closing remote connection if exist
			w.Disconnect()
			return

		case <-w.transportReady:
			w.LogInfo("transport connected with success")
			w.transportWriter = bufio.NewWriter(w.getTransportConn())
			w.writerReady = true
			// read from the connection until we stop
			go w.ReadFromConnection()

			// incoming dns message to process
		case <-w.transportReconnect:
			w.writerReady = false
			w.Disconnect()
			go w.ConnectToRemote()

		case batch, opened := <-w.GetOutputChannel():
			if !opened {
				w.LogInfo("output channel closed!")
				return
			}

			for _, dm := range batch.Messages {
				// drop dns message if the connection is not ready to avoid memory leak or
				// to block the channel
				if !w.writerReady {
					w.CountEgressDiscarded()
					continue
				}

				dm.Retain(1)
				// append dns message to buffer
				bufferDm = append(bufferDm, dm)

				// buffer is full ?
				if len(bufferDm) >= w.GetConfig().Loggers.RedisPub.BufferSize {
					w.FlushBuffer(&bufferDm)
				}
			}
			batch.Release()

		// flush the buffer
		case <-flushTimer.C:
			if !w.writerReady && len(bufferDm) > 0 {
				for _, dm := range bufferDm {
					w.CountEgressDiscarded()
					dm.Release()
				}
				bufferDm = nil
			}

			if len(bufferDm) > 0 {
				w.FlushBuffer(&bufferDm)
			}

			// restart timer
			flushTimer.Reset(flushInterval)

		}
	}
}
