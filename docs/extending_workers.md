# How-to: Add a Worker (Collector or Logger)

This guide explains how to extend DNS-collector by creating a custom worker (input collector or output logger) using the **Pluggable Component Registry**.

---

## 1. Add Configuration

Add the configuration struct for your worker in `pkgconfig/loggers.go` or `pkgconfig/collectors.go`:

```golang
type ConfigLoggers struct {
    MyLogger struct {
        Enable bool   `yaml:"enable"`
        // add other custom parameters here
    } `yaml:"mylogger"`
}
```

Define the defaults in `SetDefault()`:

```golang
func (c *ConfigLoggers) SetDefault() {
    c.MyLogger.Enable = false
}
```

---

## 2. Implement the Worker

Create your worker file `workers/mylogger.go` (and unit tests `workers/mylogger_test.go`):

```golang
package workers

import (
	"github.com/dmachard/go-dnscollector/v3/dnsutils"
	"github.com/dmachard/go-dnscollector/v3/pkgconfig"
	"github.com/dmachard/go-logger"
)

type MyWorker struct {
	*GenericWorker
}

func NewMyWorker(config *pkgconfig.Config, console *logger.Logger, name string) *MyWorker {
	bufSize := config.Global.Worker.ChannelBufferSize
	s := &MyWorker{
		GenericWorker: NewGenericWorker(config, console, name, "mylogger", bufSize, pkgconfig.DefaultMonitor),
	}
	s.ReadConfig()
	return s
}

func (w *MyWorker) StartCollect() {
	w.LogInfo("starting data collection")
	defer w.CollectDone()

	// goroutine to process transformed DNS messages
	go w.StartLogging()

	// loop to process incoming messages
	for {
		select {
		case <-w.OnStop():
			w.StopLogger()
			return

		case _, opened := <-w.GetInputChannel():
			if !opened {
				w.LogInfo("run: input channel closed!")
				return
			}
		}
	}
}

func (w *MyWorker) StartLogging() {
	w.LogInfo("logging has started")
	defer w.LoggingDone()

	for {
		select {
		case <-w.OnLoggerStopped():
			return

		case batch, opened := <-w.GetOutputChannel():
			if !opened {
				w.LogInfo("process: output channel closed!")
				return
			}

			for _, dm := range batch.Messages {
				// Process/forward the DNS message
				w.CountEgressTraffic()
			}
			batch.Release()
		}
	}
}
```

---

## 3. Register via Component Registry

Register your worker directly in the same file using `init()`.

### For a Logger:
```golang
func init() {
	RegisterLogger("mylogger", func(c *pkgconfig.Config) bool { return c.Loggers.MyLogger.Enable }, func(c *pkgconfig.Config, l *logger.Logger, s string) Worker {
		return NewMyWorker(c, l, s)
	})
}
```

### For a Collector:
```golang
func init() {
	RegisterCollector("mycollector", func(c *pkgconfig.Config) bool { return c.Collectors.MyCollector.Enable }, func(c *pkgconfig.Config, l *logger.Logger, s string) Worker {
		return NewMyCollector(nil, c, l, s)
	})
}
```

---

## 4. Documentation & Tests

1. Add unit tests in `workers/mylogger_test.go`.
2. Add reference documentation in `docs/platforms/` or `docs/collectors/` and update `README.md`.
