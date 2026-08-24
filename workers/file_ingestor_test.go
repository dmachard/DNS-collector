package workers

import (
	"testing"

	"github.com/dmachard/go-dnscollector/v2/dnsutils"
	"github.com/dmachard/go-dnscollector/v2/pkgconfig"
	"github.com/dmachard/go-logger"
)

func Test_FileIngestor(t *testing.T) {
	tests := []struct {
		name      string
		watchMode string
		watchDir  string
	}{
		{
			name:      "Pcap",
			watchMode: "pcap",
			watchDir:  "./../tests/testsdata/pcap/",
		},
		{
			name:      "Dnstap",
			watchMode: "dnstap",
			watchDir:  "./../tests/testsdata/dnstap/",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g := GetWorkerForTest(pkgconfig.DefaultBufferSize)
			config := pkgconfig.GetDefaultConfig()

			// watch tests data folder
			config.Collectors.FileIngestor.WatchMode = tt.watchMode
			config.Collectors.FileIngestor.WatchDir = tt.watchDir

			// init collector
			c := NewFileIngestor([]Worker{g}, config, logger.New(false), "test")
			go c.StartCollect()
			defer c.Stop()

			// waiting message in channel
			for {
				// read dns message from channel
				batch := <-g.GetInputChannel()

				// check qname
				if len(batch.Messages) > 0 && batch.Messages[0].DNSTap.Operation == dnsutils.DNSTapClientQuery {
					break
				}
			}
		})
	}
}
