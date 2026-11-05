//go:build linux

package workers

import (
	"net"
	"testing"
	"time"

	"github.com/dmachard/go-dnscollector/v3/dnsutils"
	"github.com/dmachard/go-dnscollector/v3/pkg/config"
	"github.com/dmachard/go-logger"
)

func TestAfpacketSnifferRun(t *testing.T) {
	g := GetWorkerForTest(config.DefaultBufferSize)
	c := NewAfpacketSniffer([]Worker{g}, config.GetDefaultConfig(), logger.New(false), "test")
	if err := c.Listen(); err != nil {
		t.Skip("skipping afpacket test (requires root/CAP_NET_RAW): ", err)
	}
	go c.StartCollect()

	// send dns query
	net.LookupIP(config.ProgQname)

	// waiting message in channel
	for {
		batch := <-g.GetInputChannel()
		if len(batch.Messages) > 0 && batch.Messages[0].DNSTap.Operation == dnsutils.DNSTapClientQuery && batch.Messages[0].DNS.Qname == config.ProgQname {
			break
		}
	}
}

func TestAfpacketSniffer_StartCollect_ListenFailure(t *testing.T) {
	cfg := config.GetDefaultConfig()
	cfg.Collectors.AfpacketLiveCapture.Device = "nonexistent_iface_xyz"

	g := GetWorkerForTest(config.DefaultBufferSize)
	c := NewAfpacketSniffer([]Worker{g}, cfg, logger.New(false), "test")

	done := make(chan struct{})
	go func() {
		c.StartCollect()
		close(done)
	}()

	select {
	case <-done:
		// success: returned cleanly without os.Exit
	case <-time.After(2 * time.Second):
		t.Fatal("StartCollect did not return after listen failure")
	}
}
