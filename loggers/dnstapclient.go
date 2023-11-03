package loggers

import (
	"bufio"
	"crypto/tls"
	"net"
	"strconv"
	"time"

	"github.com/dmachard/go-dnscollector/dnsutils"
	"github.com/dmachard/go-dnscollector/transformers"
	"github.com/dmachard/go-framestream"
	"github.com/dmachard/go-logger"
)

type DnstapSender struct {
	stopProcess        chan bool
	doneProcess        chan bool
	stopRun            chan bool
	doneRun            chan bool
	inputChan          chan dnsutils.DnsMessage
	outputChan         chan dnsutils.DnsMessage
	config             *dnsutils.Config
	configChan         chan *dnsutils.Config
	logger             *logger.Logger
	fs                 *framestream.Fstrm
	fsReady            bool
	transport          string
	transportConn      net.Conn
	transportReady     chan bool
	transportReconnect chan bool
	name               string
}

func NewDnstapSender(config *dnsutils.Config, logger *logger.Logger, name string) *DnstapSender {
	logger.Info("[%s] logger=dnstap - enabled", name)
	s := &DnstapSender{
		stopProcess:        make(chan bool),
		doneProcess:        make(chan bool),
		stopRun:            make(chan bool),
		doneRun:            make(chan bool),
		inputChan:          make(chan dnsutils.DnsMessage, config.Loggers.Dnstap.ChannelBufferSize),
		outputChan:         make(chan dnsutils.DnsMessage, config.Loggers.Dnstap.ChannelBufferSize),
		transportReady:     make(chan bool),
		transportReconnect: make(chan bool),
		logger:             logger,
		config:             config,
		configChan:         make(chan *dnsutils.Config),
		name:               name,
	}

	s.ReadConfig()

	return s
}

func (c *DnstapSender) GetName() string { return c.name }

func (c *DnstapSender) SetLoggers(loggers []dnsutils.Worker) {}

func (o *DnstapSender) ReadConfig() {
	o.transport = o.config.Loggers.Dnstap.Transport

	// begin backward compatibility
	if o.config.Loggers.Dnstap.TlsSupport {
		o.transport = dnsutils.SOCKET_TLS
	}
	if len(o.config.Loggers.Dnstap.SockPath) > 0 {
		o.transport = dnsutils.SOCKET_UNIX
	}
	// end

	// get hostname or global one
	if o.config.Loggers.Dnstap.ServerId == "" {
		o.config.Loggers.Dnstap.ServerId = o.config.GetServerIdentity()
	}

	if !dnsutils.IsValidTLS(o.config.Loggers.Dnstap.TlsMinVersion) {
		o.logger.Fatal("logger=dnstap - invalid tls min version")
	}
}

func (o *DnstapSender) ReloadConfig(config *dnsutils.Config) {
	o.LogInfo("reload configuration!")
	o.configChan <- config
}

func (o *DnstapSender) LogInfo(msg string, v ...interface{}) {
	o.logger.Info("["+o.name+"] logger=dnstap - "+msg, v...)
}

func (o *DnstapSender) LogError(msg string, v ...interface{}) {
	o.logger.Error("["+o.name+"] logger=dnstap - "+msg, v...)
}

func (o *DnstapSender) Channel() chan dnsutils.DnsMessage {
	return o.inputChan
}

func (o *DnstapSender) Stop() {
	o.LogInfo("stopping to run...")
	o.stopRun <- true
	<-o.doneRun

	o.LogInfo("stopping to process...")
	o.stopProcess <- true
	<-o.doneProcess
}

func (o *DnstapSender) Disconnect() {
	if o.transportConn != nil {
		// reset framestream and ignore errors
		o.LogInfo("closing framestream")
		o.fs.ResetSender()

		// closing tcp
		o.LogInfo("closing tcp connection")
		o.transportConn.Close()
		o.LogInfo("closed")
	}
}

func (o *DnstapSender) ConnectToRemote() {
	for {
		if o.transportConn != nil {
			o.transportConn.Close()
			o.transportConn = nil
		}

		address := net.JoinHostPort(
			o.config.Loggers.Dnstap.RemoteAddress,
			strconv.Itoa(o.config.Loggers.Dnstap.RemotePort),
		)
		connTimeout := time.Duration(o.config.Loggers.Dnstap.ConnectTimeout) * time.Second

		// make the connection
		var conn net.Conn
		var err error

		switch o.transport {
		case dnsutils.SOCKET_UNIX:
			address = o.config.Loggers.Dnstap.RemoteAddress
			if len(o.config.Loggers.Dnstap.SockPath) > 0 {
				address = o.config.Loggers.Dnstap.SockPath
			}
			o.LogInfo("connecting to %s://%s", o.transport, address)
			conn, err = net.DialTimeout(o.transport, address, connTimeout)

		case dnsutils.SOCKET_TCP:
			o.LogInfo("connecting to %s://%s", o.transport, address)
			conn, err = net.DialTimeout(o.transport, address, connTimeout)

		case dnsutils.SOCKET_TLS:
			o.LogInfo("connecting to %s://%s", o.transport, address)

			var tlsConfig *tls.Config

			tlsOptions := dnsutils.TlsOptions{
				InsecureSkipVerify: o.config.Loggers.Dnstap.TlsInsecure,
				MinVersion:         o.config.Loggers.Dnstap.TlsMinVersion,
				CAFile:             o.config.Loggers.Dnstap.CAFile,
				CertFile:           o.config.Loggers.Dnstap.CertFile,
				KeyFile:            o.config.Loggers.Dnstap.KeyFile,
			}

			tlsConfig, err = dnsutils.TlsClientConfig(tlsOptions)
			if err == nil {
				dialer := &net.Dialer{Timeout: connTimeout}
				conn, err = tls.DialWithDialer(dialer, dnsutils.SOCKET_TCP, address, tlsConfig)
			}
		default:
			o.logger.Fatal("logger=dnstap - invalid transport:", o.transport)
		}

		// something is wrong during connection ?
		if err != nil {
			o.LogError("%s", err)
			o.LogInfo("retry to connect in %d seconds", o.config.Loggers.Dnstap.RetryInterval)
			time.Sleep(time.Duration(o.config.Loggers.Dnstap.RetryInterval) * time.Second)
			continue
		}

		o.transportConn = conn

		// block until framestream is ready
		o.transportReady <- true

		// block until an error occured, need to reconnect
		o.transportReconnect <- true
	}
}

func (o *DnstapSender) FlushBuffer(buf *[]dnsutils.DnsMessage) {

	var data []byte
	var err error
	frame := &framestream.Frame{}

	for _, dm := range *buf {
		// update identity ?
		if o.config.Loggers.Dnstap.OverwriteIdentity {
			dm.DnsTap.Identity = o.config.Loggers.Dnstap.ServerId
		}

		// encode dns message to dnstap protobuf binary
		data, err = dm.ToDnstap()
		if err != nil {
			o.LogError("failed to encode to DNStap protobuf: %s", err)
			continue
		}

		// send the frame
		frame.Write(data)
		if err := o.fs.SendFrame(frame); err != nil {
			o.LogError("send frame error %s", err)
			o.fsReady = false
			<-o.transportReconnect
			break
		}
	}

	// reset buffer
	*buf = nil
}

func (o *DnstapSender) Run() {
	o.LogInfo("running in background...")

	// prepare transforms
	listChannel := []chan dnsutils.DnsMessage{}
	listChannel = append(listChannel, o.outputChan)
	subprocessors := transformers.NewTransforms(&o.config.OutgoingTransformers, o.logger, o.name, listChannel, 0)

	// goroutine to process transformed dns messages
	go o.Process()

	// init remote conn
	go o.ConnectToRemote()

	// loop to process incoming messages
RUN_LOOP:
	for {
		select {
		case <-o.stopRun:
			// cleanup transformers
			subprocessors.Reset()

			o.doneRun <- true
			break RUN_LOOP

		case cfg, opened := <-o.configChan:
			if !opened {
				return
			}
			o.config = cfg
			o.ReadConfig()
			subprocessors.ReloadConfig(&cfg.OutgoingTransformers)

		case dm, opened := <-o.inputChan:
			if !opened {
				o.LogInfo("input channel closed!")
				return
			}

			// apply tranforms, init dns message with additionnals parts if necessary
			subprocessors.InitDnsMessageFormat(&dm)
			if subprocessors.ProcessMessage(&dm) == transformers.RETURN_DROP {
				continue
			}

			// send to output channel
			o.outputChan <- dm
		}
	}
	o.LogInfo("run terminated")
}

func (o *DnstapSender) Process() {
	// init buffer
	bufferDm := []dnsutils.DnsMessage{}

	// init flust timer for buffer
	flushInterval := time.Duration(o.config.Loggers.Dnstap.FlushInterval) * time.Second
	flushTimer := time.NewTimer(flushInterval)

	o.LogInfo("ready to process")
PROCESS_LOOP:
	for {
		select {
		case <-o.stopProcess:
			// closing remote connection if exist
			o.Disconnect()

			o.doneProcess <- true
			break PROCESS_LOOP

			// init framestream
		case <-o.transportReady:
			o.LogInfo("transport connected with success")
			// frame stream library
			r := bufio.NewReader(o.transportConn)
			w := bufio.NewWriter(o.transportConn)
			o.fs = framestream.NewFstrm(r, w, o.transportConn, 5*time.Second, []byte("protobuf:dnstap.Dnstap"), true)

			// init framestream protocol
			if err := o.fs.InitSender(); err != nil {
				o.LogError("sender protocol initialization error %s", err)
				o.fsReady = false
				o.transportConn.Close()
				<-o.transportReconnect
			} else {
				o.fsReady = true
				o.LogInfo("framestream initialized with success")
			}
		// incoming dns message to process
		case dm, opened := <-o.outputChan:
			if !opened {
				o.LogInfo("output channel closed!")
				return
			}

			// drop dns message if the connection is not ready to avoid memory leak or
			// to block the channel
			if !o.fsReady {
				continue
			}

			// append dns message to buffer
			bufferDm = append(bufferDm, dm)

			// buffer is full ?
			if len(bufferDm) >= o.config.Loggers.Dnstap.BufferSize {
				o.FlushBuffer(&bufferDm)
			}

		// flush the buffer
		case <-flushTimer.C:
			// force to flush the buffer
			if len(bufferDm) > 0 {
				o.FlushBuffer(&bufferDm)
			}

			// restart timer
			flushTimer.Reset(flushInterval)
		}
	}
	o.LogInfo("processing terminated")
}
