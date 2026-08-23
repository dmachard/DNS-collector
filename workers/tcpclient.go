package workers

import (
	"bufio"
	"crypto/tls"
	"encoding/json"
	"errors"
	"io"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/dmachard/go-dnscollector/v2/dnsutils"
	"github.com/dmachard/go-dnscollector/v2/pkgconfig"
	"github.com/dmachard/go-dnscollector/v2/transformers"
	"github.com/dmachard/go-logger"
	"github.com/dmachard/go-netutils"
)

type TCPClient struct {
	*GenericWorker
	stopRead, doneRead                 chan bool
	textFormat                         []string
	textFormatter                      *dnsutils.TextFormatter
	transport                          string
	transportWriter                    *bufio.Writer
	transportConn                      net.Conn
	transportReady, transportReconnect chan bool
	writerReady                        bool
}

func NewTCPClient(config *pkgconfig.Config, logger *logger.Logger, name string) *TCPClient {
	bufSize := config.Global.Worker.ChannelBufferSize
	w := &TCPClient{GenericWorker: NewGenericWorker(config, logger, name, "tcpclient", bufSize, pkgconfig.DefaultMonitor)}
	w.transportReady = make(chan bool)
	w.transportReconnect = make(chan bool)
	w.stopRead = make(chan bool)
	w.doneRead = make(chan bool)
	w.ReadConfig()
	return w
}

func (w *TCPClient) ReadConfig() {
	w.transport = w.GetConfig().Loggers.TCPClient.Transport
	if len(w.GetConfig().Loggers.TCPClient.TextFormat) > 0 {
		w.textFormat = strings.Fields(w.GetConfig().Loggers.TCPClient.TextFormat)
	} else {
		w.textFormat = strings.Fields(w.GetConfig().Global.TextFormat)
	}

	var errFormatter error
	w.textFormatter, errFormatter = dnsutils.NewTextFormatter(w.textFormat, w.GetConfig().Global.TextFormatDelimiter, w.GetConfig().Global.TextFormatBoundary)
	if errFormatter != nil {
		w.LogFatal(pkgconfig.PrefixLogWorker + "invalid text format: " + errFormatter.Error())
	}
}

func (w *TCPClient) Disconnect() {
	if w.transportConn != nil {
		w.LogInfo("closing tcp connection")
		w.transportConn.Close()
	}
}

func (w *TCPClient) ReadFromConnection() {
	buffer := make([]byte, 4096)

	go func() {
		for {
			_, err := w.transportConn.Read(buffer)
			if err != nil {
				if errors.Is(err, io.EOF) || errors.Is(err, net.ErrClosed) {
					w.LogInfo("read from connection terminated")
					break
				}
				w.LogError("Error on reading: %s", err.Error())
			}
			// We just discard the data
		}
	}()

	// block goroutine until receive true event in stopRead channel
	<-w.stopRead
	w.doneRead <- true

	w.LogInfo("read goroutine terminated")
}

func (w *TCPClient) ConnectToRemote() {
	for {
		if w.transportConn != nil {
			w.transportConn.Close()
			w.transportConn = nil
		}

		address := w.GetConfig().Loggers.TCPClient.RemoteAddress + ":" + strconv.Itoa(w.GetConfig().Loggers.TCPClient.RemotePort)
		connTimeout := time.Duration(w.GetConfig().Loggers.TCPClient.ConnectTimeout) * time.Second

		// make the connection
		var conn net.Conn
		var err error

		switch w.transport {
		case netutils.SocketUnix:
			address = w.GetConfig().Loggers.TCPClient.RemoteAddress
			w.LogInfo("connecting to %s://%s", w.transport, address)
			conn, err = net.DialTimeout(w.transport, address, connTimeout)

		case netutils.SocketTCP:
			w.LogInfo("connecting to %s://%s", w.transport, address)
			conn, err = net.DialTimeout(w.transport, address, connTimeout)

		case netutils.SocketTLS:
			w.LogInfo("connecting to %s://%s", w.transport, address)

			var tlsConfig *tls.Config

			tlsOptions := netutils.TLSOptions{
				InsecureSkipVerify: w.GetConfig().Loggers.TCPClient.TLSInsecure,
				MinVersion:         w.GetConfig().Loggers.TCPClient.TLSMinVersion,
				CAFile:             w.GetConfig().Loggers.TCPClient.CAFile,
				CertFile:           w.GetConfig().Loggers.TCPClient.CertFile,
				KeyFile:            w.GetConfig().Loggers.TCPClient.KeyFile,
			}

			tlsConfig, err = netutils.TLSClientConfig(tlsOptions)
			if err == nil {
				dialer := &net.Dialer{Timeout: connTimeout}
				conn, err = tls.DialWithDialer(dialer, netutils.SocketTCP, address, tlsConfig)
			}
		default:
			w.LogFatal("invalid transport:", w.transport)
		}

		// something is wrong during connection ?
		if err != nil {
			w.LogError("%s", err)
			w.LogInfo("retry to connect in %d seconds", w.GetConfig().Loggers.TCPClient.RetryInterval)
			time.Sleep(time.Duration(w.GetConfig().Loggers.TCPClient.RetryInterval) * time.Second)
			continue
		}

		w.transportConn = conn

		// block until framestream is ready
		w.transportReady <- true

		// block until an error occurred, need to reconnect
		w.transportReconnect <- true
	}
}

func (w *TCPClient) FlushBuffer(buf *[]*dnsutils.DNSMessage) {
	defer func() {
		for _, dm := range *buf {
			dm.Release()
		}
		*buf = nil
	}()

	for _, dm := range *buf {
		if w.GetConfig().Loggers.TCPClient.Mode == pkgconfig.ModeText {
			textBuf := w.GetTextBuffer() // get buffer from pool
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

			w.transportWriter.Write(textBuf.Bytes()) // write buffer content
			w.PutTextBuffer(textBuf)                 // return buffer to pool

			w.transportWriter.WriteString(w.GetConfig().Loggers.TCPClient.PayloadDelimiter)
		}

		if w.GetConfig().Loggers.TCPClient.Mode == pkgconfig.ModeJSON {
			json.NewEncoder(w.transportWriter).Encode(dm)
			w.transportWriter.WriteString(w.GetConfig().Loggers.TCPClient.PayloadDelimiter)
		}

		if w.GetConfig().Loggers.TCPClient.Mode == pkgconfig.ModeFlatJSON {
			if dm.Relabeling != nil {
				flat, err := dm.Flatten()
				if err != nil {
					w.LogError("flattening DNS message failed: %e", err)
					continue
				}
				json.NewEncoder(w.transportWriter).Encode(flat)
			} else {
				textBuf := w.GetTextBuffer()
				textBuf.Reset()
				dm.GetTimestampRFC3339()
				dm.EncodeFlatJSON(textBuf)
				w.transportWriter.Write(textBuf.Bytes())
				w.PutTextBuffer(textBuf)
			}
			w.transportWriter.WriteString(w.GetConfig().Loggers.TCPClient.PayloadDelimiter)
		}

		// flush the transport buffer
		err := w.transportWriter.Flush()
		if err != nil {
			w.LogError("send frame error", err.Error())
			w.writerReady = false
			<-w.transportReconnect
			break
		}
	}
}

func (w *TCPClient) StartCollect() {
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

			w.stopRead <- true
			<-w.doneRead

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

				w.SendToOutputAndForward(defaultRoutes, defaultNames, dm)
			}
			batch.Release()
		}
	}
}

func (w *TCPClient) StartLogging() {
	w.LogInfo("logging has started")
	defer w.LoggingDone()

	// init buffer
	bufferDm := []*dnsutils.DNSMessage{}

	// init flush timer for buffer
	flushInterval := time.Duration(w.GetConfig().Loggers.TCPClient.FlushInterval) * time.Second
	flushTimer := time.NewTimer(flushInterval)

	// init remote conn
	go w.ConnectToRemote()

	w.LogInfo("ready to process")
	for {
		select {
		case <-w.OnLoggerStopped():
			// closing remote connection if exist
			w.Disconnect()
			return

		case <-w.transportReady:
			w.LogInfo("transport connected with success")
			w.transportWriter = bufio.NewWriter(w.transportConn)
			w.writerReady = true

			// read from the connection until we stop
			go w.ReadFromConnection()

		// incoming dns message to process
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
				if len(bufferDm) >= w.GetConfig().Loggers.TCPClient.BufferSize {
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
