package workers

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/dmachard/go-dnscollector/v3/dnsutils"
	"github.com/dmachard/go-dnscollector/v3/pkg/config"
	"github.com/dmachard/go-logger"
)

func Test_Webhook(t *testing.T) {
	// Create a test HTTP server to simulate remote API
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		username, password, ok := r.BasicAuth()

		if !ok {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		if username != "whuser" || password != "whpass" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		fmt.Fprintf(w, "whbody")
	}))
	defer server.Close()

	// simulate next workers
	kept := GetWorkerForTest(config.DefaultBufferSize)
	dropped := GetWorkerForTest(config.DefaultBufferSize)

	// config for the collector
	cfg := config.GetDefaultConfig()
	cfg.Collectors.Webhook.Enable = true
	cfg.Collectors.Webhook.URL = server.URL
	cfg.Collectors.Webhook.BasicAuthEnabled = true
	cfg.Collectors.Webhook.BasicAuthLogin = "whuser"
	cfg.Collectors.Webhook.BasicAuthPwd = "whpass"

	// init collector
	c := NewWebhook(nil, cfg, logger.New(false), "test")
	c.SetDefaultRoutes([]Worker{kept})
	c.SetDefaultDropped([]Worker{dropped})

	// start to collect and send DNS messages on it
	go c.StartCollect()

	// send fake dns message to logger
	dm := dnsutils.GetFakeDNSMessage()
	c.GetInputChannel() <- dnsutils.NewDNSMessageBatch(&dm)

	batchOut := <-kept.GetInputChannel()
	if len(batchOut.Messages) == 0 {
		t.Fatalf("expected message in batch")
	}
	dmOut := batchOut.Messages[0]

	// check results
	if dmOut.Rest.Failed != false {
		t.Errorf("REST request failed")
	}

	if dmOut.Rest.Response != "whbody" {
		t.Errorf("REST body mismatch, want: whbody got: %s", dmOut.Rest.Response)
	}
}
