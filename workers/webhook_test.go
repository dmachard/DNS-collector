package workers

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/dmachard/go-dnscollector/dnsutils"
	"github.com/dmachard/go-dnscollector/pkgconfig"
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
	kept := GetWorkerForTest(pkgconfig.DefaultBufferSize)
	dropped := GetWorkerForTest(pkgconfig.DefaultBufferSize)

	// config for the collector
	config := pkgconfig.GetDefaultConfig()
	config.Collectors.Webhook.Enable = true
	config.Collectors.Webhook.URL = server.URL
	config.Collectors.Webhook.BasicAuthEnabled = true
	config.Collectors.Webhook.BasicAuthLogin = "whuser"
	config.Collectors.Webhook.BasicAuthPwd = "whpass"

	// init collector
	c := NewWebhook(nil, config, logger.New(false), "test")
	c.SetDefaultRoutes([]Worker{kept})
	c.SetDefaultDropped([]Worker{dropped})

	// start to collect and send DNS messages on it
	go c.StartCollect()

	// send fake dns message to logger
	dm := dnsutils.GetFakeDNSMessage()
	c.GetInputChannel() <- dm

	dmOut := <-kept.GetInputChannel()

	// check results
	if dmOut.Rest.Failed != false {
		t.Errorf("REST request failed")
	}

	if dmOut.Rest.Response != "whbody" {
		t.Errorf("REST body mismatch, want: whbody got: %s", dmOut.Rest.Response)
	}
}
