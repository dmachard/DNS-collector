package workers

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"sync/atomic"
	"time"

	"github.com/dmachard/go-dnscollector/v3/dnsutils"
	"github.com/dmachard/go-dnscollector/v3/pkg/config"
	"github.com/dmachard/go-dnscollector/v3/transformers"
	"github.com/dmachard/go-logger"
)

type Webhook struct {
	*GenericWorker
	httpclient       *http.Client
	URL              string
	BasicAuthEnabled bool
	BasicAuthLogin   string
	BasicAuthPwd     string
}

func NewWebhook(next []Worker, cfg *config.Config, logger *logger.Logger, name string) *Webhook {
	bufSize := cfg.Global.Worker.ChannelBufferSize
	w := &Webhook{GenericWorker: NewGenericWorker(cfg, logger, name, "webhook", bufSize, config.DefaultMonitor)}
	w.SetDefaultRoutes(next)
	w.ReadConfig()
	return w
}

func (w *Webhook) ReadConfig() {
	w.URL = w.GetConfig().Loggers.Webhook.URL
	w.BasicAuthEnabled = w.GetConfig().Loggers.Webhook.BasicAuthEnabled
	w.BasicAuthLogin = w.GetConfig().Loggers.Webhook.BasicAuthLogin
	w.BasicAuthPwd = w.GetConfig().Loggers.Webhook.BasicAuthPwd

	maxConns := w.GetConfig().Loggers.Webhook.NumThreads * 2
	if maxConns < 10 {
		maxConns = 10
	}

	tr := &http.Transport{
		MaxIdleConns:        maxConns,
		MaxIdleConnsPerHost: maxConns,
		IdleConnTimeout:     30 * time.Second,
	}

	w.httpclient = &http.Client{
		Timeout:   time.Duration(w.GetConfig().Loggers.Webhook.Timeout) * time.Second,
		Transport: tr,
	}
}

func (w *Webhook) StartCollect() {
	w.LogInfo("starting data collection")
	defer w.CollectDone()

	// prepare next channels for dropped messages, forwarding is done in logger
	droppedRoutes, droppedNames := GetRoutes(w.GetDroppedRoutes())

	// prepare transforms
	subprocessors := transformers.NewTransforms(&w.GetConfig().OutgoingTransformers, w.GetLogger(), w.GetName(), w.GetOutputChannelAsList(), 0)

	// goroutines to process and forward transformed dns messages
	ctx, cancel := context.WithCancel(context.Background())
	for n := 1; n <= w.GetConfig().Loggers.Webhook.NumThreads; n++ {
		go w.StartLogging(n, ctx)
	}

	// read incoming dns message
	w.LogInfo("waiting dns message to process...")
	for {
		select {
		case <-w.OnStop():
			subprocessors.Reset()
			cancel()
			return

		// save the new config
		case cfg := <-w.NewConfig():
			w.SetConfig(cfg)
			w.ReadConfig()

		case batch, opened := <-w.GetInputChannel():
			if !opened {
				w.LogInfo("channel closed, exit")
				cancel()
				return
			}
			outBatch := w.ProcessBatch(batch, &subprocessors, droppedRoutes, droppedNames)
			w.SendToOutputAndForwardBatch(nil, nil, outBatch)
			batch.Release()
		}
	}
}

func (w *Webhook) StartLogging(threadnum int, ctx context.Context) {
	w.LogInfo("logging thread %d has started", threadnum)
	defer w.LoggingDone()

	defaultRoutes, defaultNames := GetRoutes(w.GetDefaultRoutes())
	hasRoutes := len(defaultRoutes) > 0

	for {
		select {
		case <-ctx.Done():
			return

		case batch, opened := <-w.GetOutputChannel():
			if !opened {
				w.LogInfo("output channel closed!")
				return
			}

			for _, dm := range batch.Messages {
				if hasRoutes {
					targetDm := dm
					if atomic.LoadInt32(&dm.RefCount) > 1 {
						targetDm = dm.Clone()
					}
					targetDm.Rest = &dnsutils.TransformRest{Failed: true, Response: ""}
					_ = w.Request(targetDm)
					w.SendForwardedTo(defaultRoutes, defaultNames, targetDm)
					if targetDm != dm {
						targetDm.Release()
					}
				} else {
					_ = w.Request(dm)
				}
			}
			batch.Release()
		}
	}
}

func (w *Webhook) Request(dm *dnsutils.DNSMessage) error {
	buffer := w.GetTextBuffer()
	buffer.Reset()
	defer w.PutTextBuffer(buffer)
	dm.EncodeJSON(buffer)

	post, err := http.NewRequest("POST", w.URL, bytes.NewReader(buffer.Bytes()))
	if err != nil {
		w.LogError("HTTP error: %s", err)
		return err
	}

	post.Header.Set("Content-Type", "application/json")

	if w.BasicAuthEnabled {
		post.SetBasicAuth(w.BasicAuthLogin, w.BasicAuthPwd)
	}

	resp, err := w.httpclient.Do(post)
	if err != nil {
		w.LogError("HTTP request failed: %s", err)
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		w.LogError("invalid HTTP status code: %d", resp.StatusCode)
		return err
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		w.LogError("HTTP body read failed: %s", err)
		return err
	}

	if dm.Rest != nil {
		dm.Rest.Failed = false
		dm.Rest.Response = string(body)
	}

	return nil
}

func init() {
	RegisterLogger("webhook", func(c *config.Config) bool { return c.Loggers.Webhook.Enable }, func(c *config.Config, l *logger.Logger, s string) Worker {
		return NewWebhook(nil, c, l, s)
	})
}
