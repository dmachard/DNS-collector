package workers

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/dmachard/go-dnscollector/v2/dnsutils"
	"github.com/dmachard/go-dnscollector/v2/pkg/config"
	"github.com/dmachard/go-logger"
	"google.golang.org/protobuf/proto"
)

func TestGenericWorker(t *testing.T) {
	NewGenericWorker(config.GetDefaultConfig(), logger.New(false), "testonly", "", config.DefaultBufferSize, config.WorkerMonitorDisabled)
}

func Test_MultiLogger_ConcurrentRace(t *testing.T) {
	cfg := config.GetDefaultConfig()
	cfg.Collectors.Dnstap.DisableDNSParser = false
	cfg.Global.Worker.ChannelBufferSize = 1000

	// Create 5 consumer workers (multi-logger scenario)
	numLoggers := 5
	loggers := make([]Worker, numLoggers)
	for i := 0; i < numLoggers; i++ {
		devNull := NewDevNull(cfg, logger.New(false), "devnull-multi")
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

	proc := NewDNSTapProcessor(1, "test-multi-peer", cfg, logger.New(false), "test-multi-proc", 1000)
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

func TestGenericWorker_ContextCancellation(t *testing.T) {
	gw := NewGenericWorker(config.GetDefaultConfig(), logger.New(false), "testctx", "", 10, config.WorkerMonitorDisabled)
	ctx := gw.Context()
	if ctx == nil {
		t.Fatalf("expected non-nil context")
	}

	select {
	case <-ctx.Done():
		t.Fatalf("context should not be cancelled yet")
	default:
	}

	go gw.StartCollect()
	gw.Stop()

	select {
	case <-ctx.Done():
		// Success: context was cancelled upon Stop()
	case <-time.After(1 * time.Second):
		t.Fatalf("context was not cancelled after Stop()")
	}
}

func TestStopWorkersParallel(t *testing.T) {
	cfg := config.GetDefaultConfig()
	log := logger.New(false)

	w1 := NewGenericWorker(cfg, log, "w1", "", 10, config.WorkerMonitorDisabled)
	w2 := NewGenericWorker(cfg, log, "w2", "", 10, config.WorkerMonitorDisabled)
	w3 := NewGenericWorker(cfg, log, "w3", "", 10, config.WorkerMonitorDisabled)

	go w1.StartCollect()
	go w2.StartCollect()
	go w3.StartCollect()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	StopWorkersParallel(ctx, []Worker{w1, w2, w3}, log)

	if w1.Context().Err() == nil || w2.Context().Err() == nil || w3.Context().Err() == nil {
		t.Errorf("all workers should have cancelled contexts after StopWorkersParallel")
	}
}
