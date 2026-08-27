package workers

import (
	"bytes"
	"context"
	"sync"
	"sync/atomic"
	"time"

	"github.com/dmachard/go-dnscollector/v2/dnsutils"
	"github.com/dmachard/go-dnscollector/v2/pkgconfig"
	"github.com/dmachard/go-dnscollector/v2/telemetry"
	"github.com/dmachard/go-logger"
)

// Ensure time import is used by Monitor() ticker; declared here to keep linter happy.

type Worker interface {
	SetMetrics(metrics *telemetry.PrometheusCollector)
	AddDefaultRoute(wrk Worker)
	AddDroppedRoute(wrk Worker)
	SetLoggers(loggers []Worker)
	GetName() string
	Stop()
	StartCollect()
	CountIngressTraffic()
	CountEgressTraffic()
	GetInputChannel() chan *dnsutils.DNSMessageBatch
	ReadConfig()
	ReloadConfig(config *pkgconfig.Config)
	GetMetrics() *telemetry.PrometheusCollector
	GetTextBuffer() *bytes.Buffer
	PutTextBuffer(buf *bytes.Buffer)
}

type GenericWorker struct {
	ctx                          context.Context
	cancel                       context.CancelFunc
	loggerCtx                    context.Context
	loggerCancel                 context.CancelFunc
	collectDone                  chan struct{}
	processDone                  chan struct{}
	monitorDone                  chan struct{}
	doneOnceCollect              sync.Once
	doneOnceProcess              sync.Once
	doneOnceMonitor              sync.Once
	monitor                      bool
	config                       *pkgconfig.Config
	configChan                   chan *pkgconfig.Config
	logger                       *logger.Logger
	name, descr                  string
	droppedRoutes, defaultRoutes []Worker
	stopOnce, stopLoggerOnce     sync.Once
	// droppedWorkerCounts maps route-name -> atomic dropped message count.
	// Using a sync.Map of *atomic.Int64 avoids starvation that a channel-based
	// accumulator can cause when the monitor ticker competes with a high-volume
	// drop stream inside a single select.
	droppedWorkerCounts         sync.Map // map[string]*atomic.Int64
	dnsMessageIn, dnsMessageOut chan *dnsutils.DNSMessageBatch

	metrics                                                                 atomic.Pointer[telemetry.PrometheusCollector]
	totalIngress, totalEgress, totalForwarded, totalDropped, totalDiscarded atomic.Uint64

	TextBufferPool *sync.Pool
}

func NewGenericWorker(config *pkgconfig.Config, logger *logger.Logger, name string, descr string, bufferSize int, monitor bool) *GenericWorker {
	logger.Info(pkgconfig.PrefixLogWorker+"[%s] %s - enabled", name, descr)
	ctx, cancel := context.WithCancel(context.Background())
	loggerCtx, loggerCancel := context.WithCancel(context.Background())
	w := &GenericWorker{
		ctx:           ctx,
		cancel:        cancel,
		loggerCtx:     loggerCtx,
		loggerCancel:  loggerCancel,
		collectDone:   make(chan struct{}),
		processDone:   make(chan struct{}),
		monitorDone:   make(chan struct{}),
		monitor:       monitor,
		config:        config,
		configChan:    make(chan *pkgconfig.Config),
		logger:        logger,
		name:          name,
		descr:         descr,
		dnsMessageIn:  make(chan *dnsutils.DNSMessageBatch, bufferSize),
		dnsMessageOut: make(chan *dnsutils.DNSMessageBatch, bufferSize),
		TextBufferPool: &sync.Pool{
			New: func() interface{} { return new(bytes.Buffer) },
		},
	}
	if monitor {
		go w.Monitor()
	}
	return w
}

func (w *GenericWorker) SetMetrics(metrics *telemetry.PrometheusCollector) {
	w.metrics.Store(metrics)
}

func (w *GenericWorker) GetMetrics() *telemetry.PrometheusCollector {
	return w.metrics.Load()
}

func (w *GenericWorker) GetName() string { return w.name }

func (w *GenericWorker) GetConfig() *pkgconfig.Config { return w.config }

func (w *GenericWorker) SetConfig(config *pkgconfig.Config) { w.config = config }

func (w *GenericWorker) GetBatchSize() int {
	if w.config != nil && w.config.Global.Worker.BatchSize > 0 {
		return w.config.Global.Worker.BatchSize
	}
	return pkgconfig.DefaultBatchSize
}

func (w *GenericWorker) GetFlushInterval() time.Duration {
	if w.config != nil && w.config.Global.Worker.BatchFlushIntervalMs > 0 {
		return time.Duration(w.config.Global.Worker.BatchFlushIntervalMs) * time.Millisecond
	}
	return time.Duration(pkgconfig.DefaultFlushInterval) * time.Millisecond
}

func (w *GenericWorker) ReadConfig() {}

func (w *GenericWorker) NewConfig() chan *pkgconfig.Config { return w.configChan }

func (w *GenericWorker) GetLogger() *logger.Logger { return w.logger }

func (w *GenericWorker) GetDroppedRoutes() []Worker { return w.droppedRoutes }

func (w *GenericWorker) GetDefaultRoutes() []Worker { return w.defaultRoutes }

func (w *GenericWorker) GetInputChannel() chan *dnsutils.DNSMessageBatch { return w.dnsMessageIn }

func (w *GenericWorker) GetInputChannelAsList() []chan *dnsutils.DNSMessageBatch {
	return []chan *dnsutils.DNSMessageBatch{w.dnsMessageIn}
}

func (w *GenericWorker) GetOutputChannel() chan *dnsutils.DNSMessageBatch { return w.dnsMessageOut }

func (w *GenericWorker) GetOutputChannelAsList() []chan *dnsutils.DNSMessageBatch {
	return []chan *dnsutils.DNSMessageBatch{w.dnsMessageOut}
}

func (w *GenericWorker) AddDroppedRoute(wrk Worker) {
	w.droppedRoutes = append(w.droppedRoutes, wrk)
}

func (w *GenericWorker) AddDefaultRoute(wrk Worker) {
	w.defaultRoutes = append(w.defaultRoutes, wrk)
}

func (w *GenericWorker) SetDefaultRoutes(workers []Worker) {
	w.defaultRoutes = workers
}

func (w *GenericWorker) SetDefaultDropped(workers []Worker) {
	w.droppedRoutes = workers
}

func (w *GenericWorker) SetLoggers(loggers []Worker) { w.defaultRoutes = loggers }

func (w *GenericWorker) Loggers() ([]chan *dnsutils.DNSMessageBatch, []string) {
	return GetRoutes(w.defaultRoutes)
}

func (w *GenericWorker) ReloadConfig(config *pkgconfig.Config) {
	w.LogInfo("reload configuration...")
	w.configChan <- config
}

func (w *GenericWorker) LogInfo(msg string, v ...interface{}) {
	w.logger.Info(pkgconfig.PrefixLogWorker+"["+w.name+"] "+w.descr+" - "+msg, v...)
}

func (w *GenericWorker) LogWarning(msg string, v ...interface{}) {
	w.logger.Warning(pkgconfig.PrefixLogWorker+"["+w.name+"] "+w.descr+" - "+msg, v...)
}

func (w *GenericWorker) LogError(msg string, v ...interface{}) {
	w.logger.Error(pkgconfig.PrefixLogWorker+"["+w.name+"] "+w.descr+" - "+msg, v...)
}

func (w *GenericWorker) LogFatal(v ...interface{}) {
	w.logger.Fatal(v...)
}

func (w *GenericWorker) Context() context.Context {
	return w.ctx
}

func (w *GenericWorker) OnStop() <-chan struct{} {
	return w.ctx.Done()
}

func (w *GenericWorker) OnLoggerStopped() <-chan struct{} {
	return w.loggerCtx.Done()
}

func (w *GenericWorker) StopLogger() {
	w.stopLoggerOnce.Do(func() {
		w.loggerCancel()
		<-w.processDone
	})
}

func (w *GenericWorker) CollectDone() {
	w.LogInfo("collection terminated")
	w.doneOnceCollect.Do(func() {
		close(w.collectDone)
	})
}

func (w *GenericWorker) LoggingDone() {
	w.LogInfo("logging terminated")
	w.doneOnceProcess.Do(func() {
		close(w.processDone)
	})
}

func (w *GenericWorker) Stop() {
	w.stopOnce.Do(func() {
		w.cancel()
		w.LogInfo("stopping collect...")
		<-w.collectDone
		if w.monitor {
			w.LogInfo("stopping monitor...")
			<-w.monitorDone
		}
	})
}

// StopWorkersParallel terminates a list of workers concurrently, bounded by ctx.
func StopWorkersParallel(ctx context.Context, workersList []Worker, log *logger.Logger) {
	if len(workersList) == 0 {
		return
	}
	var wg sync.WaitGroup
	for _, wrk := range workersList {
		if wrk == nil {
			continue
		}
		wg.Add(1)
		go func(w Worker) {
			defer wg.Done()
			w.Stop()
		}(wrk)
	}

	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	select {
	case <-done:
	case <-ctx.Done():
		if log != nil {
			log.Warning("workers stop timeout reached (%v)", ctx.Err())
		}
	}
}

func (w *GenericWorker) Monitor() {
	defer func() {
		if r := recover(); r != nil {
			w.LogError("monitor - recovered panic: %v", r)
		}
		w.LogInfo("monitor terminated")
		w.doneOnceMonitor.Do(func() {
			close(w.monitorDone)
		})
	}()

	interval := 10
	if w.config != nil && w.config.Global.Worker.InternalMonitor > 0 {
		interval = w.config.Global.Worker.InternalMonitor
	}

	w.LogInfo("starting monitoring - refresh every %ds", interval)
	ticker := time.NewTicker(time.Duration(interval) * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-w.ctx.Done():
			return

		case <-ticker.C:
			// Log dropped counts accumulated since last tick.
			w.droppedWorkerCounts.Range(func(key, val any) bool {
				counter := val.(*atomic.Int64)
				if k := counter.Swap(0); k > 0 {
					w.LogWarning("worker[%s] buffer is full, %d dnsmessage(s) dropped", key.(string), k)
				}
				return true
			})

			// send to telemetry?
			metrics := w.metrics.Load()
			if w.config.Global.Telemetry.Enabled && metrics != nil {
				totalIngress := int(w.totalIngress.Swap(0))
				totalEgress := int(w.totalEgress.Swap(0))
				totalForwarded := int(w.totalForwarded.Swap(0))
				totalDropped := int(w.totalDropped.Swap(0))
				totalDiscarded := int(w.totalDiscarded.Swap(0))

				if totalIngress > 0 || totalEgress > 0 || totalForwarded > 0 || totalDropped > 0 || totalDiscarded > 0 {
					metrics.Record <- telemetry.WorkerStats{
						Name:                 w.GetName(),
						TotalIngress:         totalIngress,
						TotalEgress:          totalEgress,
						TotalForwardedPolicy: totalForwarded,
						TotalDroppedPolicy:   totalDropped,
						TotalDiscarded:       totalDiscarded,
					}
				}
			}
		}
	}
}

func (w *GenericWorker) WorkerIsBusy(name string, count int) {
	// Load-or-store an *atomic.Int64 for this route name, then add atomically.
	// This is lock-free and cannot starve the Monitor ticker.
	var counter *atomic.Int64
	if v, ok := w.droppedWorkerCounts.Load(name); ok {
		counter = v.(*atomic.Int64)
	} else {
		new := &atomic.Int64{}
		actual, _ := w.droppedWorkerCounts.LoadOrStore(name, new)
		counter = actual.(*atomic.Int64)
	}
	counter.Add(int64(count))
}

func (w *GenericWorker) StartCollect() {
	w.LogInfo("starting data collection")
	defer w.CollectDone()
}

func (w *GenericWorker) StartLogging() {
	w.LogInfo("logging has started")
	defer w.LoggingDone()
}

func (w *GenericWorker) CountIngressTraffic() {
	if w.config.Global.Telemetry.Enabled {
		w.totalIngress.Add(1)
	}
}

func (w *GenericWorker) CountEgressTraffic() {
	if w.config.Global.Telemetry.Enabled {
		w.totalEgress.Add(1)
	}
}

func (w *GenericWorker) CountEgressDiscarded() {
	if w.config.Global.Telemetry.Enabled {
		w.totalDiscarded.Add(1)
	}
}

// sendBatch is the internal helper that dispatches a *DNSMessageBatch to all routes.
// It handles reference counting for fan-out and drops + telemetry when a route is full.
func (w *GenericWorker) sendBatch(routes []chan *dnsutils.DNSMessageBatch, routesName []string, b *dnsutils.DNSMessageBatch, dropped bool) {
	if len(routes) == 0 {
		b.Release()
		return
	}
	if len(routes) > 1 {
		b.Retain(int32(len(routes) - 1))
	}
	for i := range routes {
		select {
		case routes[i] <- b:
			if w.config.Global.Telemetry.Enabled {
				if dropped {
					w.totalDropped.Add(uint64(len(b.Messages)))
				} else {
					w.totalForwarded.Add(uint64(len(b.Messages)))
				}
			}
		default:
			droppedCount := len(b.Messages)
			b.Release()
			if w.config.Global.Telemetry.Enabled {
				w.totalDiscarded.Add(uint64(droppedCount))
			}
			w.WorkerIsBusy(routesName[i], droppedCount)
		}
	}
}

// SendDroppedTo wraps dm in a batch-of-1 and dispatches it to all dropped routes.
func (w *GenericWorker) SendDroppedTo(routes []chan *dnsutils.DNSMessageBatch, routesName []string, dm *dnsutils.DNSMessage) {
	dm.Retain(1)
	b := dnsutils.AcquireDNSMessageBatch(1)
	b.Messages = append(b.Messages, dm)
	w.sendBatch(routes, routesName, b, true)
}

// SendForwardedTo wraps dm in a batch-of-1 and dispatches it to all default routes.
func (w *GenericWorker) SendForwardedTo(routes []chan *dnsutils.DNSMessageBatch, routesName []string, dm *dnsutils.DNSMessage) {
	dm.Retain(1)
	b := dnsutils.AcquireDNSMessageBatch(1)
	b.Messages = append(b.Messages, dm)
	w.sendBatch(routes, routesName, b, false)
}

// SendForwardedBatchTo dispatches a pre-assembled *DNSMessageBatch to all default routes.
// This is the high-throughput path — callers that can accumulate messages should use this.
func (w *GenericWorker) SendForwardedBatchTo(routes []chan *dnsutils.DNSMessageBatch, routesName []string, batch *dnsutils.DNSMessageBatch) {
	if batch == nil || len(batch.Messages) == 0 {
		if batch != nil {
			batch.Release()
		}
		return
	}
	w.sendBatch(routes, routesName, batch, false)
}

// RunBatchLoop reads *DNSMessageBatch values from the input channel and calls
// process() for each one. Batching is now done by the producer (via SendForwardedBatchTo
// or SendForwardedTo which wraps into batch-of-1). No accumulation or ticker needed here.
func (w *GenericWorker) RunBatchLoop(process func(*dnsutils.DNSMessageBatch)) {
	for {
		select {
		case <-w.OnStop():
			return

		case batch, opened := <-w.dnsMessageIn:
			if !opened {
				w.LogInfo("run: input channel closed!")
				return
			}
			process(batch)
		}
	}
}

func (w *GenericWorker) SendToOutputAndForward(routes []chan *dnsutils.DNSMessageBatch, routesName []string, dm *dnsutils.DNSMessage) {
	w.CountEgressTraffic()
	dm.Retain(1)
	b := dnsutils.AcquireDNSMessageBatch(1)
	b.Messages = append(b.Messages, dm)

	outChan := w.GetOutputChannel()
	switch {
	case outChan != nil && len(routes) > 0:
		b.Retain(1)
		w.sendBatch(routes, routesName, b, false)
		outChan <- b
	case outChan != nil:
		outChan <- b
	default:
		w.sendBatch(routes, routesName, b, false)
	}
}

func (w *GenericWorker) SendToOutputAndForwardBatch(routes []chan *dnsutils.DNSMessageBatch, routesName []string, batch *dnsutils.DNSMessageBatch) {
	if batch == nil || len(batch.Messages) == 0 {
		if batch != nil {
			batch.Release()
		}
		return
	}
	if w.config.Global.Telemetry.Enabled {
		w.totalEgress.Add(uint64(len(batch.Messages)))
	}

	outChan := w.GetOutputChannel()
	switch {
	case outChan != nil && len(routes) > 0:
		batch.Retain(1)
		w.sendBatch(routes, routesName, batch, false)
		outChan <- batch
	case outChan != nil:
		outChan <- batch
	default:
		w.sendBatch(routes, routesName, batch, false)
	}
}

func (w *GenericWorker) GetTextBuffer() *bytes.Buffer {
	return w.TextBufferPool.Get().(*bytes.Buffer)
}

func (w *GenericWorker) PutTextBuffer(buf *bytes.Buffer) {
	buf.Reset()
	w.TextBufferPool.Put(buf)
}

func GetRoutes(routes []Worker) ([]chan *dnsutils.DNSMessageBatch, []string) {
	channels := []chan *dnsutils.DNSMessageBatch{}
	names := []string{}
	for _, p := range routes {
		if p == nil {
			continue
		}
		if c := p.GetInputChannel(); c != nil {
			channels = append(channels, c)
			names = append(names, p.GetName())
		}
	}
	return channels, names
}

func GetName(name string) string {
	return "[" + name + "] - "
}

func GetWorkerForTest(bufferSize int) *GenericWorker {
	return NewGenericWorker(pkgconfig.GetDefaultConfig(), logger.New(false), "testonly", "", bufferSize, pkgconfig.WorkerMonitorDisabled)
}
