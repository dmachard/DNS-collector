package transformers

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/dmachard/go-dnscollector/v3/dnsutils"
	"github.com/dmachard/go-dnscollector/v3/pkg/config"
	"github.com/dmachard/go-logger"
)

func TestRest_Request(t *testing.T) {
	// Create a test HTTP server to simulate remote API
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		username, password, ok := r.BasicAuth()

		if !ok {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		if username != "restuser" || password != "restpass" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		fmt.Fprintf(w, "restbody")
	}))
	defer server.Close()

	// enable feature
	cfg := config.GetFakeConfigTransformers()
	cfg.Rest.Enable = true
	cfg.Rest.URL = server.URL
	cfg.Rest.BasicAuthEnabled = true
	cfg.Rest.BasicAuthLogin = "restuser"
	cfg.Rest.BasicAuthPwd = "restpass"

	// init the processor
	outChans := []chan *dnsutils.DNSMessageBatch{}
	rest := NewRestTransform(&cfg.Rest, logger.New(false), "test", 0, outChans)
	rest.GetTransforms()

	// send message
	dm := dnsutils.GetFakeDNSMessage()
	rest.Request(&dm)

	// check results
	if dm.Rest.Failed != false {
		t.Errorf("REST request failed")
	}

	if dm.Rest.Response != "restbody" {
		t.Errorf("REST body mismatch, want: restbody got: %s", dm.Rest.Response)
	}
}
