package transformers

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/dmachard/go-dnscollector/dnsutils"
	"github.com/dmachard/go-dnscollector/pkgconfig"
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

		if username != "testuser" || password != "testpass" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		fmt.Fprintf(w, "testbody")
	}))
	defer server.Close()

	// enable feature
	config := pkgconfig.GetFakeConfigTransformers()
	config.Rest.Enable = true
	config.Rest.URL = server.URL
	config.Rest.BasicAuthEnabled = true
	config.Rest.BasicAuthLogin = "testuser"
	config.Rest.BasicAuthPwd = "testpass"

	// init the processor
	outChans := []chan dnsutils.DNSMessage{}
	rest := NewRestTransform(config, logger.New(false), "test", 0, outChans)
	rest.GetTransforms()

	// send message
	dm := dnsutils.GetFakeDNSMessage()
	rest.Request(&dm)

	// check results
	if dm.Rest.Failed != false {
		t.Errorf("REST request failed")
	}

	if dm.Rest.Response != "testbody" {
		t.Errorf("REST body mismatch, want: testbody got: %s", dm.Rest.Response)
	}
}
