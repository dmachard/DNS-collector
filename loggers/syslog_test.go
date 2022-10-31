package loggers

import (
	"bufio"
	"net"
	"regexp"
	"testing"

	"github.com/dmachard/go-dnscollector/dnsutils"
	"github.com/dmachard/go-logger"
)

func TestSyslogRunTextMode(t *testing.T) {
	// init logger
	config := dnsutils.GetFakeConfig()
	config.Loggers.Syslog.Transport = dnsutils.SOCKET_TCP
	config.Loggers.Syslog.RemoteAddress = ":4000"
	config.Loggers.Syslog.Mode = dnsutils.MODE_TEXT
	g := NewSyslog(config, logger.New(false), "test")

	// fake json receiver
	fakeRcvr, err := net.Listen(dnsutils.SOCKET_TCP, ":4000")
	if err != nil {
		t.Fatal(err)
	}
	defer fakeRcvr.Close()

	// start the logger
	go g.Run()

	// accept conn from logger
	conn, err := fakeRcvr.Accept()
	if err != nil {
		return
	}
	defer conn.Close()

	// send fake dns message to logger
	dm := dnsutils.GetFakeDnsMessage()
	g.channel <- dm

	// read data on server side and decode-it
	reader := bufio.NewReader(conn)
	line, _, err := reader.ReadLine()
	if err != nil {
		t.Errorf("error to read line on syslog server: %s", err)
	}

	pattern := regexp.MustCompile("dns.collector")
	if !pattern.MatchString(string(line)) {
		t.Errorf("syslog error want dns.collector, got: %s", string(line))
	}
}

func TestSyslogRunJsonMode(t *testing.T) {
	// init logger
	config := dnsutils.GetFakeConfig()
	config.Loggers.Syslog.Transport = dnsutils.SOCKET_TCP
	config.Loggers.Syslog.RemoteAddress = ":4000"
	config.Loggers.Syslog.Mode = dnsutils.MODE_JSON
	g := NewSyslog(config, logger.New(false), "test")

	// fake json receiver
	fakeRcvr, err := net.Listen(dnsutils.SOCKET_TCP, ":4000")
	if err != nil {
		t.Fatal(err)
	}
	defer fakeRcvr.Close()

	// start the logger
	go g.Run()

	// accept conn from logger
	conn, err := fakeRcvr.Accept()
	if err != nil {
		return
	}
	defer conn.Close()

	// send fake dns message to logger
	dm := dnsutils.GetFakeDnsMessage()
	g.channel <- dm

	// read data on server side and decode-it
	reader := bufio.NewReader(conn)
	line, _, err := reader.ReadLine()
	if err != nil {
		t.Errorf("error to read line on syslog server: %s", err)
	}

	pattern := regexp.MustCompile("\"qname\":\"dns.collector\"")
	if !pattern.MatchString(string(line)) {
		t.Errorf("syslog error want json, got: %s", string(line))
	}
}
