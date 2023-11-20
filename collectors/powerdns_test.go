package collectors

import (
	"log"
	"net"
	"testing"

	"github.com/dmachard/go-dnscollector/dnsutils"
	"github.com/dmachard/go-dnscollector/loggers"
	"github.com/dmachard/go-logger"
)

func TestPowerDNS_Run(t *testing.T) {
	g := loggers.NewFakeLogger()

	c := NewProtobufPowerDNS([]dnsutils.Worker{g}, dnsutils.GetFakeConfig(), logger.New(false), "test")
	if err := c.Listen(); err != nil {
		log.Fatal("collector powerdns  listening error: ", err)
	}
	go c.Run()

	conn, err := net.Dial(dnsutils.SocketTCP, ":6001")
	if err != nil {
		t.Error("could not connect to TCP server: ", err)
	}
	defer conn.Close()
}
