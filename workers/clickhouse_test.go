package workers

import (
	"bufio"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/dmachard/go-dnscollector/v2/dnsutils"
	"github.com/dmachard/go-dnscollector/v2/pkg/config"
	"github.com/dmachard/go-logger"
	"github.com/stretchr/testify/assert"
)

func Test_ClickhouseClient_BatchInsert(t *testing.T) {
	var receivedCount atomic.Int32
	var receivedBody []byte
	var receivedQuery string
	var receivedUser, receivedKey string

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedUser = r.Header.Get("X-ClickHouse-User")
		receivedKey = r.Header.Get("X-ClickHouse-Key")
		receivedQuery = r.URL.Query().Get("query")

		scanner := bufio.NewScanner(r.Body)
		for scanner.Scan() {
			line := scanner.Bytes()
			if len(line) > 0 {
				receivedCount.Add(1)
				var record ClickhouseRecord
				if err := json.Unmarshal(line, &record); err == nil {
					assert.Equal(t, "dnscollector.dev", record.QName)
					assert.True(t, record.RD)
				}
			}
		}
		receivedBody = scanner.Bytes()
		_ = receivedBody
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("Ok."))
	}))
	defer server.Close()

	cfg := config.GetDefaultConfig()
	cfg.Loggers.ClickhouseClient.URL = server.URL
	cfg.Loggers.ClickhouseClient.User = "myuser"
	cfg.Loggers.ClickhouseClient.Password = "mypass"
	cfg.Loggers.ClickhouseClient.Database = "dnsdb"
	cfg.Loggers.ClickhouseClient.Table = "queries"
	cfg.Loggers.ClickhouseClient.BufferSize = 3
	cfg.Loggers.ClickhouseClient.FlushInterval = 10

	g := NewClickhouseClient(cfg, logger.New(false), "test_clickhouse")
	go g.StartCollect()

	// Send 3 messages to trigger buffer full flush
	for i := 0; i < 3; i++ {
		dm := dnsutils.GetFakeDNSMessage()
		dm.DNS.Qname = "dnscollector.dev"
		dm.DNS.Flags = dnsutils.DNSFlags{RD: true, QR: false}
		g.GetInputChannel() <- dnsutils.NewDNSMessageBatch(&dm)
	}

	time.Sleep(300 * time.Millisecond)
	g.Stop()

	assert.Equal(t, int32(3), receivedCount.Load())
	assert.Equal(t, "myuser", receivedUser)
	assert.Equal(t, "mypass", receivedKey)
	assert.Contains(t, receivedQuery, "INSERT INTO dnsdb.queries FORMAT JSONEachRow")
}

func Test_ClickhouseClient_FlushInterval(t *testing.T) {
	var receivedCount atomic.Int32

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		scanner := bufio.NewScanner(r.Body)
		for scanner.Scan() {
			if len(scanner.Bytes()) > 0 {
				receivedCount.Add(1)
			}
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	cfg := config.GetDefaultConfig()
	cfg.Loggers.ClickhouseClient.URL = server.URL
	cfg.Loggers.ClickhouseClient.BufferSize = 100  // Buffer won't be full
	cfg.Loggers.ClickhouseClient.FlushInterval = 1 // Flush every 1s

	g := NewClickhouseClient(cfg, logger.New(false), "test_flush")
	go g.StartCollect()

	// Send 2 messages
	for i := 0; i < 2; i++ {
		dm := dnsutils.GetFakeDNSMessage()
		g.GetInputChannel() <- dnsutils.NewDNSMessageBatch(&dm)
	}

	// Wait for timer flush
	time.Sleep(1500 * time.Millisecond)
	g.Stop()

	assert.Equal(t, int32(2), receivedCount.Load())
}

func Test_ClickhouseClient_ServerError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("DB::Exception: Table does not exist"))
	}))
	defer server.Close()

	cfg := config.GetDefaultConfig()
	cfg.Loggers.ClickhouseClient.URL = server.URL
	cfg.Loggers.ClickhouseClient.BufferSize = 1
	cfg.Loggers.ClickhouseClient.FlushInterval = 1

	g := NewClickhouseClient(cfg, logger.New(false), "test_error")
	go g.StartCollect()

	dm := dnsutils.GetFakeDNSMessage()
	g.GetInputChannel() <- dnsutils.NewDNSMessageBatch(&dm)

	time.Sleep(300 * time.Millisecond)
	g.Stop()
}

func Test_ClickhouseRecord_DNSFlags(t *testing.T) {
	dm := dnsutils.GetFakeDNSMessage()
	dm.DNS.Qname = "test.example.com"
	dm.DNS.Flags = dnsutils.DNSFlags{
		QR: true,
		AA: true,
		TC: false,
		RD: true,
		RA: true,
		AD: true,
		CD: false,
	}
	dm.DNSTap.Latency = 0.001234
	dm.PublicSuffix = &dnsutils.TransformPublicSuffix{
		QnamePublicSuffix:        "com",
		QnameEffectiveTLDPlusOne: "example.com",
	}

	record := convertDNSMessageToRecord(&dm)

	assert.Equal(t, "test.example.com", record.QName)
	assert.True(t, record.QR)
	assert.True(t, record.AA)
	assert.False(t, record.TC)
	assert.True(t, record.RD)
	assert.True(t, record.RA)
	assert.True(t, record.AD)
	assert.False(t, record.CD)
	assert.Equal(t, 0.001234, record.Latency)
	assert.Equal(t, "com", record.TLD)
	assert.Equal(t, "example.com", record.ETLDPlusOne)

	// JSON Marshalling test
	data, err := json.Marshal(record)
	assert.NoError(t, err)
	assert.True(t, strings.Contains(string(data), `"qr":true`))
	assert.True(t, strings.Contains(string(data), `"aa":true`))
	assert.True(t, strings.Contains(string(data), `"etld_plus_one":"example.com"`))
}
