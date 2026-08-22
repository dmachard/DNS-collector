//go:build linux

package workers

import (
	"log"
	"net"
	"testing"

	"github.com/dmachard/go-dnscollector/v2/dnsutils"
	"github.com/dmachard/go-dnscollector/v2/pkgconfig"
	"github.com/dmachard/go-logger"
)

func TestAfpacketSnifferRun(t *testing.T) {
	g := GetWorkerForTest(pkgconfig.DefaultBufferSize)
	c := NewAfpacketSniffer([]Worker{g}, pkgconfig.GetDefaultConfig(), logger.New(false), "test")
	if err := c.Listen(); err != nil {
		log.Fatal("collector sniffer listening error: ", err)
	}
	go c.StartCollect()

	// send dns query
	net.LookupIP(pkgconfig.ProgQname)

	// waiting message in channel
	for {
		batch := <-g.GetInputChannel()
		if len(batch.Messages) > 0 && batch.Messages[0].DNSTap.Operation == dnsutils.DNSTapClientQuery && batch.Messages[0].DNS.Qname == pkgconfig.ProgQname {
			break
		}
	}
}
