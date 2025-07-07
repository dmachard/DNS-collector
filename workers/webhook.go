package workers

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"time"

	"github.com/dmachard/go-dnscollector/dnsutils"
	"github.com/dmachard/go-dnscollector/pkgconfig"
	"github.com/dmachard/go-dnscollector/transformers"
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

func NewWebhook(next []Worker, config *pkgconfig.Config, logger *logger.Logger, name string) *Webhook {
	bufSize := config.Global.Worker.ChannelBufferSize
	if config.Collectors.Webhook.ChannelBufferSize > 0 {
		bufSize = config.Collectors.Webhook.ChannelBufferSize
	}
	w := &Webhook{GenericWorker: NewGenericWorker(config, logger, name, "webhook", bufSize, pkgconfig.DefaultMonitor)}
	w.SetDefaultRoutes(next)
	w.ReadConfig()
	return w
}

func (w *Webhook) ReadConfig() {
	w.URL = w.GetConfig().Collectors.Webhook.URL
	w.BasicAuthEnabled = w.GetConfig().Collectors.Webhook.BasicAuthEnabled
	w.BasicAuthLogin = w.GetConfig().Collectors.Webhook.BasicAuthLogin
	w.BasicAuthPwd = w.GetConfig().Collectors.Webhook.BasicAuthPwd

	tr := &http.Transport{
		MaxIdleConns:        10,
		MaxIdleConnsPerHost: 10,
		IdleConnTimeout:     30 * time.Second,
	}

	w.httpclient = &http.Client{
		Timeout:   time.Duration(w.GetConfig().Collectors.Webhook.Timeout) * time.Second,
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
	for n := 1; n <= w.GetConfig().Collectors.Webhook.NumThreads; n++ {
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

		case dm, opened := <-w.GetInputChannel():
			if !opened {
				w.LogInfo("channel closed, exit")
				cancel()
				return
			}
			// count global messages
			w.CountIngressTraffic()

			// apply tranforms, init dns message with additionnals parts if necessary
			transformResult, err := subprocessors.ProcessMessage(&dm)
			if err != nil {
				w.LogError(err.Error())
			}
			if transformResult == transformers.ReturnDrop {
				w.SendDroppedTo(droppedRoutes, droppedNames, dm)
				continue
			}
			// count output packets
			w.CountEgressTraffic()

			w.GetOutputChannel() <- dm
		}
	}
}

func (w *Webhook) StartLogging(threadnum int, ctx context.Context) {
	w.LogInfo("logging thread %d has started", threadnum)
	defer w.LoggingDone()

	defaultRoutes, defaultNames := GetRoutes(w.GetDefaultRoutes())

	for {
		select {
		case <-ctx.Done():
			return

		case dm, opened := <-w.GetOutputChannel():
			if !opened {
				w.LogInfo("output channel closed!")
				return
			}

			// enrich dm with HTTP data
			w.Request(&dm)

			// send to next
			w.SendForwardedTo(defaultRoutes, defaultNames, dm)
		}
	}
}

func (w *Webhook) Request(dm *dnsutils.DNSMessage) error {
	if dm.Rest == nil {
		dm.Rest = &dnsutils.TransformRest{Failed: true, Response: ""}
	}

	payload, err := json.Marshal(dm)
	if err != nil {
		w.LogError("JSON marshal failed: %s", err)
		return err
	}

	post, err := http.NewRequest("POST", w.URL, bytes.NewBuffer(payload))
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

	dm.Rest.Failed = false
	dm.Rest.Response = string(body)

	return nil
}
