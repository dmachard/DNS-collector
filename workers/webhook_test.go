package workers

import (
	"bytes"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
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

	// config for the logger
	cfg := config.GetDefaultConfig()
	cfg.Loggers.Webhook.Enable = true
	cfg.Loggers.Webhook.URL = server.URL
	cfg.Loggers.Webhook.BasicAuthEnabled = true
	cfg.Loggers.Webhook.BasicAuthLogin = "whuser"
	cfg.Loggers.Webhook.BasicAuthPwd = "whpass"

	// init logger
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

func TestWebhook_LeafRequest_SharedMessage(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, "ok")
	}))
	defer server.Close()

	cfg := config.GetDefaultConfig()
	cfg.Loggers.Webhook.Enable = true
	cfg.Loggers.Webhook.URL = server.URL

	c := NewWebhook(nil, cfg, logger.New(false), "test")

	dm := dnsutils.GetFakeDNSMessage()
	dm.Rest = nil

	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		_ = c.Request(&dm)
	}()

	go func() {
		defer wg.Done()
		var buf bytes.Buffer
		dm.EncodeJSON(&buf)
	}()

	wg.Wait()
}

func TestWebhook_ForwardedRoutes_SharedMessageClone(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, "routed_ok")
	}))
	defer server.Close()

	kept := GetWorkerForTest(config.DefaultBufferSize)

	cfg := config.GetDefaultConfig()
	cfg.Loggers.Webhook.Enable = true
	cfg.Loggers.Webhook.URL = server.URL

	c := NewWebhook(nil, cfg, logger.New(false), "test")
	c.SetDefaultRoutes([]Worker{kept})

	go c.StartCollect()

	dm := dnsutils.AcquireDNSMessage()
	dm.Init()
	dm.DNSTap.Identity = "shared-test"
	dm.Rest = nil

	// Simulate fan-out: retain +1 so RefCount=2 (shared between webhook and another worker)
	dm.Retain(1)

	var wg sync.WaitGroup
	wg.Add(1)
	stopRead := make(chan struct{})

	// Sibling worker concurrently reading original dm
	go func() {
		defer wg.Done()
		var buf bytes.Buffer
		for {
			select {
			case <-stopRead:
				return
			default:
				buf.Reset()
				dm.EncodeJSON(&buf)
				if dm.Rest != nil {
					t.Errorf("original dm.Rest was mutated concurrently by webhook!")
					return
				}
			}
		}
	}()

	b := dnsutils.AcquireDNSMessageBatch(1)
	b.Messages = append(b.Messages, dm)
	c.GetInputChannel() <- b

	batchOut := <-kept.GetInputChannel()
	close(stopRead)
	wg.Wait()

	if len(batchOut.Messages) == 0 {
		t.Fatalf("expected message in forwarded batch")
	}
	dmOut := batchOut.Messages[0]

	if dmOut.Rest == nil {
		t.Fatalf("expected dmOut.Rest to be set")
	}
	if dmOut.Rest.Failed {
		t.Errorf("expected dmOut.Rest.Failed = false")
	}
	if dmOut.Rest.Response != "routed_ok" {
		t.Errorf("expected routed_ok, got %s", dmOut.Rest.Response)
	}

	if dm.Rest != nil {
		t.Errorf("original dm.Rest should be nil, got %+v", dm.Rest)
	}

	batchOut.Release()
	dm.Release()
	c.Stop()
}
