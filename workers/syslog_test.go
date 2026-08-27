package workers

import (
	"bufio"
	"net"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/dmachard/go-dnscollector/v2/dnsutils"
	"github.com/dmachard/go-dnscollector/v2/pkg/config"
	"github.com/dmachard/go-logger"
	"github.com/dmachard/go-netutils"
)

func Test_SyslogRunUdp(t *testing.T) {
	testcases := []struct {
		name       string
		transport  string
		mode       string
		formatter  string
		framer     string
		pattern    string
		listenAddr string
	}{
		{
			name:       "unix_format",
			transport:  netutils.SocketUDP,
			mode:       config.ModeText,
			formatter:  netutils.SocketUnix,
			framer:     "",
			pattern:    `<30>\D+ \d+ \d+:\d+:\d+.*`,
			listenAddr: ":4000",
		},
		{
			name:       "rfc3164_format",
			transport:  netutils.SocketUDP,
			mode:       config.ModeText,
			formatter:  "rfc3164",
			framer:     "",
			pattern:    `<30>\D+ \d+ \d+:\d+:\d+.*`,
			listenAddr: ":4000",
		},
		{
			name:       "rfc5424_format",
			transport:  netutils.SocketUDP,
			mode:       config.ModeText,
			formatter:  "rfc5424",
			framer:     "",
			pattern:    `<30>1 \d+-\d+-\d+.*`,
			listenAddr: ":4000",
		},
		{
			name:       "rfc5424_format_rfc5425_framer",
			transport:  netutils.SocketUDP,
			mode:       config.ModeText,
			formatter:  "rfc5424",
			framer:     "rfc5425",
			pattern:    `\d+ \<30\>1 \d+-\d+-\d+.*`,
			listenAddr: ":4000",
		},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			// init logger
			cfg := config.GetDefaultConfig()
			cfg.Loggers.Syslog.Transport = tc.transport
			cfg.Loggers.Syslog.RemoteAddress = tc.listenAddr
			cfg.Loggers.Syslog.Mode = tc.mode
			cfg.Loggers.Syslog.Formatter = tc.formatter
			cfg.Loggers.Syslog.Framer = tc.framer
			cfg.Loggers.Syslog.FlushInterval = 1
			cfg.Loggers.Syslog.BufferSize = 0

			g := NewSyslog(cfg, logger.New(false), "test")

			// fake json receiver
			fakeRcvr, err := net.ListenPacket(tc.transport, tc.listenAddr)
			if err != nil {
				t.Fatal(err)
			}
			defer fakeRcvr.Close()

			// start the logger
			go g.StartCollect()
			defer g.Stop()

			// send fake dns message to logger
			time.Sleep(time.Second)
			dm := dnsutils.GetFakeDNSMessage()
			g.GetInputChannel() <- dnsutils.NewDNSMessageBatch(&dm)

			// read data on fake server side
			buf := make([]byte, 4096)
			_ = fakeRcvr.SetReadDeadline(time.Now().Add(5 * time.Second))
			n, _, err := fakeRcvr.ReadFrom(buf)
			if err != nil {
				t.Errorf("error to read data: %s", err)
			}

			if n == 0 {
				t.Errorf("no data received")
			}

			re := regexp.MustCompile(tc.pattern)
			if !re.MatchString(string(buf)) {
				t.Errorf("syslog error want %s, got: %s", tc.pattern, string(buf))
			}
		})
	}
}

func Test_SyslogRunTcp(t *testing.T) {
	testcases := []struct {
		name       string
		transport  string
		mode       string
		formatter  string
		framer     string
		pattern    string
		listenAddr string
	}{
		{
			name:       "unix_format",
			transport:  netutils.SocketTCP,
			mode:       config.ModeText,
			formatter:  netutils.SocketUnix,
			framer:     "",
			pattern:    `<30>\D+ \d+ \d+:\d+:\d+.*`,
			listenAddr: ":4000",
		},
		{
			name:       "rfc3164_format",
			transport:  netutils.SocketTCP,
			mode:       config.ModeText,
			formatter:  "rfc3164",
			framer:     "",
			pattern:    `<30>\D+ \d+ \d+:\d+:\d+.*`,
			listenAddr: ":4000",
		},
		{
			name:       "rfc5424_format",
			transport:  netutils.SocketTCP,
			mode:       config.ModeText,
			formatter:  "rfc5424",
			framer:     "",
			pattern:    `<30>1 \d+-\d+-\d+.*`,
			listenAddr: ":4000",
		},
		{
			name:       "rfc5425_format_rfc5425_framer",
			transport:  netutils.SocketTCP,
			mode:       config.ModeText,
			formatter:  "rfc5424",
			framer:     "rfc5425",
			pattern:    `\d+ \<30\>1 \d+-\d+-\d+.*`,
			listenAddr: ":4000",
		},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			// init logger
			cfg := config.GetDefaultConfig()
			cfg.Loggers.Syslog.Transport = tc.transport
			cfg.Loggers.Syslog.RemoteAddress = tc.listenAddr
			cfg.Loggers.Syslog.Mode = tc.mode
			cfg.Loggers.Syslog.Formatter = tc.formatter
			cfg.Loggers.Syslog.Framer = tc.framer
			cfg.Loggers.Syslog.FlushInterval = 1
			cfg.Loggers.Syslog.BufferSize = 0

			g := NewSyslog(cfg, logger.New(false), "test")

			// fake json receiver
			fakeRcvr, err := net.Listen(tc.transport, tc.listenAddr)
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

			// send fake dns message to logger
			time.Sleep(time.Second)
			dm := dnsutils.GetFakeDNSMessage()
			g.GetInputChannel() <- dnsutils.NewDNSMessageBatch(&dm)

			// read data on server side and decode-it
			reader := bufio.NewReader(conn)
			line, _, err := reader.ReadLine()
			if err != nil {
				t.Errorf("error to read line on syslog server: %s", err)
			}

			re := regexp.MustCompile(tc.pattern)
			if !re.MatchString(string(line)) {
				t.Errorf("syslog error want %s, got: %s", tc.pattern, string(line))
			}
		})
	}
}

func Test_SyslogRun_RemoveNullCharacter(t *testing.T) {
	// init logger
	cfg := config.GetDefaultConfig()
	cfg.Loggers.Syslog.Transport = netutils.SocketUDP
	cfg.Loggers.Syslog.RemoteAddress = ":4000"
	cfg.Loggers.Syslog.Mode = config.ModeText
	cfg.Loggers.Syslog.Formatter = netutils.SocketUnix
	cfg.Loggers.Syslog.Framer = ""
	cfg.Loggers.Syslog.FlushInterval = 1
	cfg.Loggers.Syslog.BufferSize = 0

	g := NewSyslog(cfg, logger.New(false), "test")

	// fake json receiver
	fakeRcvr, err := net.ListenPacket(cfg.Loggers.Syslog.Transport, ":4000")
	if err != nil {
		t.Fatal(err)
	}
	defer fakeRcvr.Close()

	// start the logger
	go g.StartCollect()
	defer g.Stop()

	// send fake dns message to logger
	time.Sleep(time.Second)
	dm := dnsutils.GetFakeDNSMessage()
	dm.DNS.Qname = "null\x00char.com"
	g.GetInputChannel() <- dnsutils.NewDNSMessageBatch(&dm)

	// read data on fake server side
	buf := make([]byte, (500))
	_ = fakeRcvr.SetReadDeadline(time.Now().Add(5 * time.Second))

	n, _, err := fakeRcvr.ReadFrom(buf)
	if err != nil {
		t.Errorf("error to read data: %s", err)
	}

	if n == 0 {
		t.Errorf("no data received")
	}

	// search null char
	for _, b := range buf[:n] {
		if b == '\x00' {
			t.Errorf("NULL char detected in log")
		}
	}

	// search qname
	pattern := `null` + cfg.Loggers.Syslog.ReplaceNullChar + `char\.com`
	re := regexp.MustCompile(pattern)
	if !re.MatchString(string(buf[:n])) {
		t.Errorf("syslog error want %s, got: %s", pattern, string(buf[:n]))
	}
}

func Test_SyslogRun_DynamicHostname(t *testing.T) {
	testcases := []struct {
		name          string
		hostnameField string
		setupDM       func(dm *dnsutils.DNSMessage)
		expectedHost  string
		listenAddr    string
	}{
		{
			name:          "dynamic_identity",
			hostnameField: "identity",
			setupDM: func(dm *dnsutils.DNSMessage) {
				dm.DNSTap.Identity = "dns-resolver-01"
			},
			expectedHost: "dns-resolver-01",
			listenAddr:   ":4010",
		},
		{
			name:          "dynamic_peer_name",
			hostnameField: "peer-name",
			setupDM: func(dm *dnsutils.DNSMessage) {
				dm.DNSTap.PeerName = "ns1.internal.lan"
			},
			expectedHost: "ns1.internal.lan",
			listenAddr:   ":4011",
		},
		{
			name:          "dynamic_query_ip",
			hostnameField: "query-ip",
			setupDM: func(dm *dnsutils.DNSMessage) {
				dm.NetworkInfo.QueryIP = "192.168.1.100"
			},
			expectedHost: "192.168.1.100",
			listenAddr:   ":4012",
		},
		{
			name:          "static_hostname",
			hostnameField: "custom-static-hostname",
			setupDM: func(dm *dnsutils.DNSMessage) {
				dm.DNSTap.Identity = "should-be-ignored"
			},
			expectedHost: "custom-static-hostname",
			listenAddr:   ":4013",
		},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := config.GetDefaultConfig()
			cfg.Loggers.Syslog.Transport = netutils.SocketUDP
			cfg.Loggers.Syslog.RemoteAddress = tc.listenAddr
			cfg.Loggers.Syslog.Mode = config.ModeText
			cfg.Loggers.Syslog.Formatter = "rfc5424"
			cfg.Loggers.Syslog.Framer = ""
			cfg.Loggers.Syslog.FlushInterval = 1
			cfg.Loggers.Syslog.BufferSize = 0
			cfg.Loggers.Syslog.Hostname = tc.hostnameField

			g := NewSyslog(cfg, logger.New(false), "test_dynamic_host")

			fakeRcvr, err := net.ListenPacket(cfg.Loggers.Syslog.Transport, tc.listenAddr)
			if err != nil {
				t.Fatal(err)
			}
			defer fakeRcvr.Close()

			go g.StartCollect()
			defer g.Stop()

			time.Sleep(500 * time.Millisecond)
			dm := dnsutils.GetFakeDNSMessage()
			tc.setupDM(&dm)
			g.GetInputChannel() <- dnsutils.NewDNSMessageBatch(&dm)

			buf := make([]byte, 1024)
			_ = fakeRcvr.SetReadDeadline(time.Now().Add(3 * time.Second))
			n, _, err := fakeRcvr.ReadFrom(buf)
			if err != nil {
				t.Fatalf("error reading syslog data: %s", err)
			}

			received := string(buf[:n])
			if !strings.Contains(received, tc.expectedHost) {
				t.Errorf("syslog header expected host '%s', got: %s", tc.expectedHost, received)
			}
		})
	}
}
