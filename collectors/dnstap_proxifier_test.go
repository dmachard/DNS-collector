package collectors

import (
	"bufio"
	"log"
	"net"
	"testing"
	"time"

	"github.com/dmachard/go-dnscollector/dnsutils"
	"github.com/dmachard/go-dnscollector/loggers"
	"github.com/dmachard/go-framestream"
	"github.com/dmachard/go-logger"
	"google.golang.org/protobuf/proto"
)

func TestDnstapProxifier_TcpSocket(t *testing.T) {
	g := loggers.NewFakeLogger()

	config := dnsutils.GetFakeConfig()
	config.Collectors.DnstapProxifier.ListenPort = 6100

	c := NewDnstapProxifier([]dnsutils.Worker{g}, config, logger.New(false), "test")
	if err := c.Listen(); err != nil {
		log.Fatal("collector dnstap relay tcp listening error: ", err)
	}
	go c.Run()

	conn, err := net.Dial(dnsutils.SOCKET_TCP, ":6100")
	if err != nil {
		t.Error("could not connect to TCP server: ", err)
	}
	defer conn.Close()

	r := bufio.NewReader(conn)
	w := bufio.NewWriter(conn)
	fs := framestream.NewFstrm(r, w, conn, 5*time.Second, []byte("protobuf:dnstap.Dnstap"), true)
	if err := fs.InitSender(); err != nil {
		t.Fatalf("framestream init error: %s", err)
	} else {
		frame := &framestream.Frame{}

		// get fake dns question
		dnsquery, err := GetFakeDns()
		if err != nil {
			t.Fatalf("dns question pack error")
		}

		// get fake dnstap message
		dt_query := GetFakeDnstap(dnsquery)

		// serialize to bytes
		data, err := proto.Marshal(dt_query)
		if err != nil {
			t.Fatalf("dnstap proto marshal error %s", err)
		}

		// send query
		frame.Write(data)
		if err := fs.SendFrame(frame); err != nil {
			t.Fatalf("send frame error %s", err)
		}
	}

	// waiting message in channel
	msg := <-g.Channel()
	if len(msg.DnsTap.Payload) == 0 {
		t.Errorf("DNStap payload is empty")
	}
}

func TestDnstapProxifier_UnixSocket(t *testing.T) {
	g := loggers.NewFakeLogger()
	config := dnsutils.GetFakeConfig()
	config.Collectors.DnstapProxifier.SockPath = "/tmp/dnscollector_relay.sock"
	c := NewDnstapProxifier([]dnsutils.Worker{g}, config, logger.New(false), "test")
	if err := c.Listen(); err != nil {
		log.Fatal("collector dnstap replay unix listening  error: ", err)
	}
	go c.Run()

	conn, err := net.Dial(dnsutils.SOCKET_UNIX, config.Collectors.DnstapProxifier.SockPath)
	if err != nil {
		t.Error("could not connect to unix socket: ", err)
	}
	defer conn.Close()

	r := bufio.NewReader(conn)
	w := bufio.NewWriter(conn)
	fs := framestream.NewFstrm(r, w, conn, 5*time.Second, []byte("protobuf:dnstap.Dnstap"), true)
	if err := fs.InitSender(); err != nil {
		t.Fatalf("framestream init error: %s", err)
	} else {
		frame := &framestream.Frame{}

		// get fake dns question
		dnsquery, err := GetFakeDns()
		if err != nil {
			t.Fatalf("dns question pack error")
		}

		// get fake dnstap message
		dt_query := GetFakeDnstap(dnsquery)

		// serialize to bytes
		data, err := proto.Marshal(dt_query)
		if err != nil {
			t.Fatalf("dnstap proto marshal error %s", err)
		}

		// send query
		frame.Write(data)
		if err := fs.SendFrame(frame); err != nil {
			t.Fatalf("send frame error %s", err)
		}
	}

	// waiting message in channel
	msg := <-g.Channel()
	if len(msg.DnsTap.Payload) == 0 {
		t.Errorf("DNStap payload is empty")
	}
}
