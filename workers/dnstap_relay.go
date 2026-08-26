package workers

import (
	"bufio"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/dmachard/go-dnscollector/v2/dnsutils"
	"github.com/dmachard/go-dnscollector/v2/pkgconfig"
	"github.com/dmachard/go-framestream"
	"github.com/dmachard/go-logger"
	"github.com/dmachard/go-netutils"
)

type DnstapProxifier struct {
	*GenericWorker
	connCounter uint64
}

func NewDnstapProxifier(next []Worker, config *pkgconfig.Config, logger *logger.Logger, name string) *DnstapProxifier {
	bufSize := config.Global.Worker.ChannelBufferSize
	s := &DnstapProxifier{GenericWorker: NewGenericWorker(config, logger, name, "dnstaprelay", bufSize, pkgconfig.DefaultMonitor)}
	s.SetDefaultRoutes(next)
	s.CheckConfig()
	return s
}

func (w *DnstapProxifier) CheckConfig() {
	if !netutils.IsValidTLS(w.GetConfig().Collectors.DnstapProxifier.TLSMinVersion) {
		w.LogFatal(pkgconfig.PrefixLogWorker + "[" + w.GetName() + "] dnstaprelay - invalid tls min version")
	}
}

func (w *DnstapProxifier) HandleFrame(recvFrom chan []byte, sendTo []chan *dnsutils.DNSMessageBatch) {
	defer w.LogInfo("frame handler terminated")

	for data := range recvFrom {
		dm := dnsutils.AcquireDNSMessage()
		dm.Init()

		// register payload
		dm.DNSTap.Payload = data

		b := dnsutils.AcquireDNSMessageBatch(1)
		b.Messages = append(b.Messages, dm)

		if len(sendTo) > 1 {
			b.Retain(int32(len(sendTo) - 1))
		}
		// forward to outputs
		for i := range sendTo {
			sendTo[i] <- b
		}
	}
}

func (w *DnstapProxifier) HandleConn(conn net.Conn, connID uint64, forceClose chan bool, wg *sync.WaitGroup) {
	// close connection on function exit
	defer func() {
		w.LogInfo("conn #%d - connection handler terminated", connID)
		conn.Close()
		wg.Done()
	}()

	// get peer address
	peer := conn.RemoteAddr().String()
	w.LogInfo("new connection from %s\n", peer)

	bufSize := w.config.Global.Worker.ChannelBufferSize

	recvChan := make(chan []byte, bufSize)
	defaultRoutes, _ := GetRoutes(w.GetDefaultRoutes())
	go w.HandleFrame(recvChan, defaultRoutes)

	// frame stream library
	fsReader := bufio.NewReader(conn)
	fsWriter := bufio.NewWriter(conn)
	handshakeTimeout := time.Duration(w.GetConfig().Global.Framestream.HandshakeTimeout) * time.Second
	contentType := []byte(w.GetConfig().Global.Framestream.ContentType)
	fs := framestream.NewFstrm(fsReader, fsWriter, conn, handshakeTimeout, contentType, true)
	fs.SetControlFrameMaxLength(w.GetConfig().Global.Framestream.ControlFrameMaxLength)
	fs.SetDataFrameMaxLength(w.GetConfig().Global.Framestream.DataFrameMaxLength)

	// init framestream receiver
	if err := fs.InitReceiver(); err != nil {
		w.LogError("error stream receiver initialization: %s", err)
		return
	} else {
		w.LogInfo("conn #%d - receiver framestream initialized (data-frame-max-length: %d, control-frame-max-length: %d)",
			connID,
			w.GetConfig().Global.Framestream.DataFrameMaxLength,
			w.GetConfig().Global.Framestream.ControlFrameMaxLength,
		)
	}

	// goroutine to close the connection properly
	cleanup := make(chan struct{})
	go func() {
		defer w.LogInfo("conn #%d - cleanup connection handler terminated", connID)

		for {
			select {
			case <-forceClose:
				w.LogInfo("conn #%d - force to cleanup the connection handler", connID)
				conn.Close()
				close(recvChan)
				return
			case <-cleanup:
				w.LogInfo("conn #%d - cleanup the connection handler", connID)
				close(recvChan)
				return
			}
		}
	}()

	// process incoming frame and send it to recv channel
	err := fs.ProcessFrame(recvChan)
	if err != nil {
		if netutils.IsClosedConnectionError(err) {
			w.LogInfo("conn #%d - connection closed with peer %s", connID, peer)
		} else {
			w.LogError("conn #%d - transport error: %s", connID, err)
		}

		close(cleanup)
	}
}

func (w *DnstapProxifier) StartCollect() {
	w.LogInfo("starting data collection")
	defer w.CollectDone()

	var connWG sync.WaitGroup
	connCleanup := make(chan bool)

	// start to listen
	listener, err := netutils.StartToListen(
		w.GetConfig().Collectors.DnstapProxifier.ListenIP, w.GetConfig().Collectors.DnstapProxifier.ListenPort,
		w.GetConfig().Collectors.DnstapProxifier.SockPath,
		w.GetConfig().Collectors.DnstapProxifier.TLSSupport, netutils.TLSVersion[w.GetConfig().Collectors.DnstapProxifier.TLSMinVersion],
		w.GetConfig().Collectors.DnstapProxifier.CertFile, w.GetConfig().Collectors.DnstapProxifier.KeyFile)
	if err != nil {
		w.LogFatal("collector dnstaprelay listening failed: ", err)
	}
	w.LogInfo("listening on %s", listener.Addr())

	// goroutine to Accept() and blocks waiting for new connection.
	acceptChan := make(chan net.Conn)
	netutils.AcceptConnections(listener, acceptChan)

	// main loop
	for {
		select {
		case <-w.OnStop():
			w.LogInfo("stop to listen...")
			listener.Close()

			w.LogInfo("closing connected peers...")
			close(connCleanup)
			connWG.Wait()
			return

		// save the new config
		case cfg := <-w.NewConfig():
			w.SetConfig(cfg)
			w.CheckConfig()

		case conn, opened := <-acceptChan:
			if !opened {
				return
			}

			// handle the connection
			connWG.Add(1)
			connID := atomic.AddUint64(&w.connCounter, 1)
			go w.HandleConn(conn, connID, connCleanup, &connWG)
		}
	}
}

func init() {
	RegisterCollector("dnstap-proxifier", func(c *pkgconfig.Config) bool { return c.Collectors.DnstapProxifier.Enable }, func(c *pkgconfig.Config, l *logger.Logger, s string) Worker {
		return NewDnstapProxifier(nil, c, l, s)
	})
}
