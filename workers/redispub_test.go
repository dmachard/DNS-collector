package workers

import (
	"bufio"
	"net"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/dmachard/go-dnscollector/v2/dnsutils"
	"github.com/dmachard/go-dnscollector/v2/pkgconfig"
	"github.com/dmachard/go-logger"
	"github.com/dmachard/go-netutils"
)

func Test_RedisPubReconnect(t *testing.T) {
	cfg := pkgconfig.GetDefaultConfig()
	cfg.Loggers.RedisPub.Transport = netutils.SocketTCP
	cfg.Loggers.RedisPub.FlushInterval = 1
	cfg.Loggers.RedisPub.BufferSize = 0
	cfg.Loggers.RedisPub.Mode = pkgconfig.ModeText
	cfg.Loggers.RedisPub.RedisChannel = "testons"
	cfg.Loggers.RedisPub.RemoteAddress = "127.0.0.1"

	listener, err := net.Listen(netutils.SocketTCP, "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	cfg.Loggers.RedisPub.RemotePort = listener.Addr().(*net.TCPAddr).Port

	g := NewRedisPub(cfg, logger.New(false), "test_reconnect")

	go g.StartCollect()
	defer g.Stop()

	conn1, err := listener.Accept()
	if err != nil {
		t.Fatal(err)
	}
	conn1.SetReadDeadline(time.Now().Add(5 * time.Second))

	dm1 := dnsutils.GetFakeDNSMessage()
	g.GetInputChannel() <- dnsutils.NewDNSMessageBatch(&dm1)

	reader1 := bufio.NewReader(conn1)
	if _, err := reader1.ReadString('\n'); err != nil {
		t.Fatalf("first redis payload not received: %v", err)
	}

	if err := conn1.Close(); err != nil {
		t.Fatalf("close first redis connection: %v", err)
	}

	conn2, err := listener.Accept()
	if err != nil {
		t.Fatal(err)
	}
	defer conn2.Close()
	conn2.SetReadDeadline(time.Now().Add(5 * time.Second))

	dm2 := dnsutils.GetFakeDNSMessage()
	dm2.DNS.Qname = "reconnect.example.com"
	g.GetInputChannel() <- dnsutils.NewDNSMessageBatch(&dm2)

	reader2 := bufio.NewReader(conn2)
	line, err := reader2.ReadString('\n')
	if err != nil {
		t.Fatalf("second redis payload not received after reconnect: %v", err)
	}
	if !strings.Contains(line, "reconnect.example.com") {
		t.Fatalf("reconnect payload missing qname: %s", line)
	}
}

func Test_RedisPubRun(t *testing.T) {
	testcases := []struct {
		mode    string
		pattern string
	}{
		{
			mode:    pkgconfig.ModeText,
			pattern: " dns.collector ",
		},
		{
			mode:    pkgconfig.ModeJSON,
			pattern: `\\\"qname\\\":\\\"dns.collector\\\"`,
		},
		{
			mode:    pkgconfig.ModeFlatJSON,
			pattern: `\\\"dns.qname\\\":\\\"dns.collector\\\"`,
		},
	}
	for _, tc := range testcases {
		t.Run(tc.mode, func(t *testing.T) {
			// init logger
			cfg := pkgconfig.GetDefaultConfig()
			cfg.Loggers.RedisPub.FlushInterval = 1
			cfg.Loggers.RedisPub.BufferSize = 0
			cfg.Loggers.RedisPub.Mode = tc.mode
			cfg.Loggers.RedisPub.RedisChannel = "testons"

			g := NewRedisPub(cfg, logger.New(false), "test")

			// fake json receiver
			fakeRcvr, err := net.Listen(netutils.SocketTCP, ":6379")
			if err != nil {
				t.Fatal(err)
			}
			defer fakeRcvr.Close()

			// start the logger
			go g.StartCollect()
			defer g.Stop()

			// accept conn from logger
			conn, err := fakeRcvr.Accept()
			if err != nil {
				return
			}
			defer conn.Close()

			_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))

			// wait connection on logger
			time.Sleep(time.Second)

			// send fake dns message to logger
			dm := dnsutils.GetFakeDNSMessage()
			g.GetInputChannel() <- dnsutils.NewDNSMessageBatch(&dm)

			// read data on server side and decode-it
			reader := bufio.NewReader(conn)
			line, err := reader.ReadString('\n')
			if err != nil {
				t.Error(err)
				return
			}

			pattern := regexp.MustCompile(tc.pattern)
			if !pattern.MatchString(line) {
				t.Errorf("redis error want %s, got: %s", tc.pattern, line)
			}

			pattern2 := regexp.MustCompile("PUBLISH \"testons\"")
			if !pattern2.MatchString(line) {
				t.Errorf("redis error want %s, got: %s", pattern2, line)
			}
		})
	}
}
