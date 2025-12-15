package workers

import (
	"bufio"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/dmachard/go-dnscollector/dnsutils"
	"github.com/dmachard/go-dnscollector/pkgconfig"
	"github.com/dmachard/go-logger"
	"github.com/stretchr/testify/assert"
)

const (
	testUser     = "testuser"
	testPassword = "testpass"
)

func Test_ElasticSearchClient_BulkSize_Exceeded(t *testing.T) {

	testcases := []struct {
		mode      string
		bulkSize  int
		inputSize int
	}{
		{
			mode:      pkgconfig.ModeFlatJSON,
			bulkSize:  1024,
			inputSize: 15,
		},
	}

	fakeRcvr, err := net.Listen("tcp", "127.0.0.1:59200")
	if err != nil {
		t.Fatal(err)
	}
	defer fakeRcvr.Close()

	for _, tc := range testcases {
		t.Run(tc.mode, func(t *testing.T) {
			conf := pkgconfig.GetDefaultConfig()
			conf.Loggers.ElasticSearchClient.Index = "indexname"
			conf.Loggers.ElasticSearchClient.Server = "http://127.0.0.1:59200/"
			conf.Loggers.ElasticSearchClient.BulkSize = tc.bulkSize
			conf.Loggers.ElasticSearchClient.BulkChannelSize = 50
			g := NewElasticSearchClient(conf, logger.New(false), "test")

			var totalDm int32
			done := make(chan struct{})

			go func() {
				for {
					conn, err := fakeRcvr.Accept()
					if err != nil {
						select {
						case <-done:
							return
						default:
							t.Logf("accept error: %v", err)
							return
						}
					}
					go func(conn net.Conn) {
						defer conn.Close()
						connReader := bufio.NewReader(conn)
						connReaderT := bufio.NewReaderSize(connReader, tc.bulkSize*2)
						request, err := http.ReadRequest(connReaderT)
						if err == nil {
							payload, _ := io.ReadAll(request.Body)
							scanner := bufio.NewScanner(strings.NewReader(string(payload)))
							cnt := 0
							for scanner.Scan() {
								if cnt%2 == 1 {
									atomic.AddInt32(&totalDm, 1)
								}
								cnt++
							}
						}
						conn.Write([]byte("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 16\r\n\r\n{\"errors\":false}"))
					}(conn)
				}
			}()

			go g.StartCollect()

			dm := dnsutils.GetFakeDNSMessage()
			for i := 0; i < tc.inputSize; i++ {
				g.GetInputChannel() <- dm
			}

			try := 0
			for try < 20 {
				if atomic.LoadInt32(&totalDm) >= int32(tc.inputSize) {
					break
				}
				time.Sleep(100 * time.Millisecond)
				try++
			}
			close(done)
			assert.Equal(t, int32(tc.inputSize), atomic.LoadInt32(&totalDm))
		})
	}
}

func Test_ElasticSearchClient_FlushInterval_Exceeded(t *testing.T) {

	testcases := []struct {
		mode          string
		bulkSize      int
		inputSize     int
		flushInterval int
	}{
		{
			mode:          pkgconfig.ModeFlatJSON,
			bulkSize:      1048576,
			inputSize:     50,
			flushInterval: 5,
		},
	}

	fakeRcvr, err := net.Listen("tcp", "127.0.0.1:59200")
	if err != nil {
		t.Fatal(err)
	}
	defer fakeRcvr.Close()

	for _, tc := range testcases {
		totalDm := 0
		t.Run(tc.mode, func(t *testing.T) {
			conf := pkgconfig.GetDefaultConfig()
			conf.Loggers.ElasticSearchClient.Index = "indexname"
			conf.Loggers.ElasticSearchClient.Server = "http://127.0.0.1:59200/"
			conf.Loggers.ElasticSearchClient.BulkSize = tc.bulkSize
			conf.Loggers.ElasticSearchClient.FlushInterval = tc.flushInterval
			g := NewElasticSearchClient(conf, logger.New(true), "test")

			// run logger
			go g.StartCollect()
			time.Sleep(1 * time.Second)

			// send DNSmessage
			dm := dnsutils.GetFakeDNSMessage()
			for i := 0; i < tc.inputSize; i++ {
				g.GetInputChannel() <- dm
			}
			time.Sleep(6 * time.Second)

			// accept the new connection from logger
			// the connection should contains all packets
			conn, err := fakeRcvr.Accept()
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()

			connReader := bufio.NewReader(conn)
			connReaderT := bufio.NewReaderSize(connReader, tc.bulkSize*2)
			request, err := http.ReadRequest(connReaderT)
			if err != nil {
				t.Fatal(err)
			}
			conn.Write([]byte(pkgconfig.HTTPOK))

			// read payload from request body
			payload, err := io.ReadAll(request.Body)
			if err != nil {
				t.Fatal("no body in request:", err)
			}

			scanner := bufio.NewScanner(strings.NewReader(string(payload)))
			cnt := 0
			for scanner.Scan() {
				if cnt%2 == 0 {
					var res map[string]interface{}
					json.Unmarshal(scanner.Bytes(), &res)
					assert.Equal(t, map[string]interface{}{}, res["create"])
				} else {
					var bulkDm dnsutils.DNSMessage
					err := json.Unmarshal(scanner.Bytes(), &bulkDm)
					assert.NoError(t, err)
					totalDm += 1
				}
				cnt++
			}

			g.Stop()

		})
		assert.Equal(t, tc.inputSize, totalDm)
	}
}

func Test_ElasticSearchClient_sendBulk_WithBasicAuth(t *testing.T) {
	// Create a test HTTP server to simulate Elasticsearch
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Verify that the Authorization header is present
		username, password, ok := r.BasicAuth()
		assert.True(t, ok, "Basic Auth header is missing in the request")
		assert.Equal(t, testUser, username, "Incorrect username")
		assert.Equal(t, testPassword, password, "Incorrect password")

		if username != testUser || password != testPassword {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	// Initialize the configuration using GetDefaultConfig() for consistency
	config := pkgconfig.GetDefaultConfig()
	config.Loggers.ElasticSearchClient.Server = server.URL
	config.Loggers.ElasticSearchClient.BasicAuthEnabled = true
	config.Loggers.ElasticSearchClient.BasicAuthLogin = testUser
	config.Loggers.ElasticSearchClient.BasicAuthPwd = testPassword

	client := NewElasticSearchClient(config, logger.New(false), "test-client")

	// Send a request with a test payload
	err := client.sendBulk([]byte("test payload"))
	assert.NoError(t, err, "Unexpected error when sending request with Basic Auth")
}
