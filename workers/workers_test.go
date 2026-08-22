package workers

import (
	"sync"
	"testing"
	"time"

	"github.com/dmachard/go-dnscollector/v2/dnsutils"
	"github.com/dmachard/go-dnscollector/v2/pkgconfig"
	"github.com/dmachard/go-logger"
	"google.golang.org/protobuf/proto"
)

func TestGenericWorker(t *testing.T) {
	NewGenericWorker(pkgconfig.GetDefaultConfig(), logger.New(false), "testonly", "", pkgconfig.DefaultBufferSize, pkgconfig.WorkerMonitorDisabled)
}

func Test_MultiLogger_ConcurrentRace(t *testing.T) {
	config := pkgconfig.GetDefaultConfig()
	config.Collectors.Dnstap.DisableDNSParser = false
	config.Global.Worker.ChannelBufferSize = 1000

	// Create 5 consumer workers (multi-logger scenario)
	numLoggers := 5
	loggers := make([]Worker, numLoggers)
	for i := 0; i < numLoggers; i++ {
		devNull := NewDevNull(config, logger.New(false), "devnull-multi")
		go devNull.StartCollect()
		defer devNull.Stop()
		loggers[i] = devNull
	}

	dnsquery, err := dnsutils.GetFakeDNS()
	if err != nil {
		t.Fatalf("dns question pack error: %v", err)
	}

	dtQuery := GetFakeDNSTap(dnsquery)
	data, err := proto.Marshal(dtQuery)
	if err != nil {
		t.Fatalf("dnstap proto marshal error: %v", err)
	}

	proc := NewDNSTapProcessor(1, "test-multi-peer", config, logger.New(false), "test-multi-proc", 1000)
	proc.SetDefaultRoutes(loggers)
	go proc.StartCollect()
	defer proc.Stop()

	dataChan := proc.GetDataChannel()

	var wg sync.WaitGroup
	numSenders := 4
	msgsPerSender := 500

	for s := 0; s < numSenders; s++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < msgsPerSender; i++ {
				buf := make([]byte, len(data))
				copy(buf, data)
				dataChan <- buf
				time.Sleep(1 * time.Microsecond)
			}
		}()
	}

	wg.Wait()
	time.Sleep(50 * time.Millisecond)
}
