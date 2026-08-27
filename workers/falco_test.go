package workers

import (
	"bufio"
	"io"
	"net"
	"net/http"
	"regexp"
	"testing"
	"time"

	"github.com/dmachard/go-dnscollector/v3/dnsutils"
	"github.com/dmachard/go-dnscollector/v3/pkg/config"
	"github.com/dmachard/go-logger"
)

func Test_FalcoClient(t *testing.T) {

	testcases := []struct {
		mode    string
		pattern string
	}{
		{
			mode:    config.ModeJSON,
			pattern: "\"qname\":\"dns.collector\"",
		},
	}

	fakeRcvr, err := net.Listen("tcp", "127.0.0.1:9200")
	if err != nil {
		t.Fatal(err)
	}
	defer fakeRcvr.Close()

	for _, tc := range testcases {
		t.Run(tc.mode, func(t *testing.T) {
			conf := config.GetDefaultConfig()
			g := NewFalcoClient(conf, logger.New(false), "test")

			go g.StartCollect()
			defer g.Stop()

			dm := dnsutils.GetFakeDNSMessage()
			g.GetInputChannel() <- dnsutils.NewDNSMessageBatch(&dm)

			// accept conn
			conn, err := fakeRcvr.Accept()
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()

			_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))

			// read and parse http request on server side
			request, err := http.ReadRequest(bufio.NewReader(conn))
			if err != nil {
				t.Fatal(err)
			}
			conn.Write([]byte(config.HTTPOK))

			// read payload from request body
			payload, err := io.ReadAll(request.Body)
			if err != nil {
				t.Fatal(err)
			}

			pattern := regexp.MustCompile(tc.pattern)
			if !pattern.MatchString(string(payload)) {
				t.Errorf("falco test error want %s, got: %s", tc.pattern, string(payload))
			}
		})
	}
}
