package workers

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/dmachard/go-dnscollector/v2/dnsutils"
	"github.com/dmachard/go-dnscollector/v2/pkg/config"
	"github.com/dmachard/go-dnscollector/v2/transformers"
	"github.com/dmachard/go-logger"
	"github.com/dmachard/go-netutils"
)

type ClickhouseRecord struct {
	Timestamp       int64   `json:"timestamp"`
	TimeNSec        int64   `json:"timensec"`
	TimestampRFC    string  `json:"timestamp_rfc3339,omitempty"`
	Identity        string  `json:"identity,omitempty"`
	QueryIP         string  `json:"queryip,omitempty"`
	QueryPort       int     `json:"queryport,omitempty"`
	ResponseIP      string  `json:"responseip,omitempty"`
	ResponsePort    int     `json:"responseport,omitempty"`
	Family          string  `json:"family,omitempty"`
	Protocol        string  `json:"protocol,omitempty"`
	Length          int     `json:"length,omitempty"`
	ID              int     `json:"id,omitempty"`
	Opcode          int     `json:"opcode,omitempty"`
	RCode           string  `json:"rcode,omitempty"`
	QName           string  `json:"qname,omitempty"`
	QType           string  `json:"qtype,omitempty"`
	Operation       string  `json:"operation,omitempty"`
	Latency         float64 `json:"latency,omitempty"`
	QR              bool    `json:"qr"`
	TC              bool    `json:"tc"`
	AA              bool    `json:"aa"`
	RA              bool    `json:"ra"`
	AD              bool    `json:"ad"`
	RD              bool    `json:"rd"`
	CD              bool    `json:"cd"`
	TLD             string  `json:"tld,omitempty"`
	ETLDPlusOne     string  `json:"etld_plus_one,omitempty"`
	City            string  `json:"city,omitempty"`
	Country         string  `json:"country,omitempty"`
	ASNumber        int     `json:"as_number,omitempty"`
	ASOwner         string  `json:"as_owner,omitempty"`
	SuspiciousScore float64 `json:"suspicious_score,omitempty"`
	Malformed       bool    `json:"malformed_packet,omitempty"`
}

type ClickhouseClient struct {
	*GenericWorker
	httpClient  *http.Client
	requestURL  string
	jsonBuffer  *bytes.Buffer
	jsonEncoder *json.Encoder
	bufferCount int
}

func NewClickhouseClient(cfg *config.Config, console *logger.Logger, name string) *ClickhouseClient {
	bufSize := cfg.Global.Worker.ChannelBufferSize
	w := &ClickhouseClient{
		GenericWorker: NewGenericWorker(cfg, console, name, "clickhouse", bufSize, config.DefaultMonitor),
		jsonBuffer:    new(bytes.Buffer),
	}
	w.jsonEncoder = json.NewEncoder(w.jsonBuffer)
	w.ReadConfig()
	return w
}

func (w *ClickhouseClient) ReadConfig() {
	cfg := w.GetConfig().Loggers.ClickhouseClient

	// Build endpoint URL with JSONEachRow format
	targetURL := cfg.URL
	if !strings.HasSuffix(targetURL, "/") {
		targetURL += "/"
	}
	queryParam := fmt.Sprintf("INSERT INTO %s.%s FORMAT JSONEachRow", cfg.Database, cfg.Table)
	w.requestURL = targetURL + "?query=" + url.QueryEscape(queryParam)

	// TLS configuration
	var tlsConfig *tls.Config
	if cfg.TLSSupport {
		var err error
		tlsOptions := netutils.TLSOptions{
			InsecureSkipVerify: cfg.TLSInsecure,
			MinVersion:         cfg.TLSMinVersion,
			CAFile:             cfg.CAFile,
			CertFile:           cfg.CertFile,
			KeyFile:            cfg.KeyFile,
		}
		tlsConfig, err = netutils.TLSClientConfig(tlsOptions)
		if err != nil {
			w.LogFatal(config.PrefixLogWorker+"["+w.GetName()+"] clickhouse - tls config error: ", err.Error())
		}
	}

	// HTTP Transport with connection pooling
	transport := &http.Transport{
		TLSClientConfig:     tlsConfig,
		MaxIdleConns:        100,
		MaxIdleConnsPerHost: 100,
		IdleConnTimeout:     90 * time.Second,
		DialContext: (&net.Dialer{
			Timeout:   time.Duration(cfg.Timeout) * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
	}

	w.httpClient = &http.Client{
		Timeout:   time.Duration(cfg.Timeout) * time.Second,
		Transport: transport,
	}
}

func (w *ClickhouseClient) StartCollect() {
	w.LogInfo("starting data collection")
	defer w.CollectDone()

	defaultRoutes, defaultNames := GetRoutes(w.GetDefaultRoutes())
	droppedRoutes, droppedNames := GetRoutes(w.GetDroppedRoutes())

	subprocessors := transformers.NewTransforms(&w.GetConfig().OutgoingTransformers, w.GetLogger(), w.GetName(), w.GetOutputChannelAsList(), 0)

	go w.StartLogging()

	for {
		select {
		case <-w.OnStop():
			w.StopLogger()
			subprocessors.Reset()
			return

		case cfg := <-w.NewConfig():
			w.SetConfig(cfg)
			w.ReadConfig()
			subprocessors.ReloadConfig(&cfg.OutgoingTransformers)

		case batch, opened := <-w.GetInputChannel():
			if !opened {
				w.LogInfo("input channel closed!")
				return
			}
			outBatch := dnsutils.AcquireDNSMessageBatch(len(batch.Messages))
			for _, dm := range batch.Messages {
				w.CountIngressTraffic()

				transformResult, err := subprocessors.ProcessMessage(dm)
				if err != nil {
					w.LogError(err.Error())
				}
				if transformResult == transformers.ReturnDrop {
					w.SendDroppedTo(droppedRoutes, droppedNames, dm)
					continue
				}

				dm.Retain(1)
				outBatch.Messages = append(outBatch.Messages, dm)
			}
			w.SendToOutputAndForwardBatch(defaultRoutes, defaultNames, outBatch)
			batch.Release()
		}
	}
}

func (w *ClickhouseClient) StartLogging() {
	w.LogInfo("logging has started")
	defer w.LoggingDone()

	flushInterval := time.Duration(w.GetConfig().Loggers.ClickhouseClient.FlushInterval) * time.Second
	if flushInterval <= 0 {
		flushInterval = 10 * time.Second
	}
	flushTicker := time.NewTicker(flushInterval)
	defer flushTicker.Stop()

	for {
		select {
		case <-w.OnLoggerStopped():
			if w.bufferCount > 0 {
				w.flush()
			}
			return

		case <-flushTicker.C:
			if w.bufferCount > 0 {
				w.flush()
			}

		case batch, opened := <-w.GetOutputChannel():
			if !opened {
				w.LogInfo("output channel closed!")
				if w.bufferCount > 0 {
					w.flush()
				}
				return
			}

			bufferSize := w.GetConfig().Loggers.ClickhouseClient.BufferSize
			if bufferSize <= 0 {
				bufferSize = 100
			}

			for _, dm := range batch.Messages {
				record := convertDNSMessageToRecord(dm)
				if err := w.jsonEncoder.Encode(record); err != nil {
					w.LogError("failed to encode record to json: %s", err)
					continue
				}
				w.bufferCount++
				if w.bufferCount >= bufferSize {
					w.flush()
				}
			}
			batch.Release()
		}
	}
}

func (w *ClickhouseClient) flush() {
	if w.bufferCount == 0 || w.jsonBuffer.Len() == 0 {
		return
	}

	payloadBytes := w.jsonBuffer.Bytes()
	req, err := http.NewRequest("POST", w.requestURL, bytes.NewReader(payloadBytes))
	if err != nil {
		w.LogError("failed to create http request: %s", err)
		w.jsonBuffer.Reset()
		w.bufferCount = 0
		return
	}

	cfg := w.GetConfig().Loggers.ClickhouseClient
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "*/*")
	if len(cfg.User) > 0 {
		req.Header.Set("X-ClickHouse-User", cfg.User)
	}
	if len(cfg.Password) > 0 {
		req.Header.Set("X-ClickHouse-Key", cfg.Password)
	}

	resp, err := w.httpClient.Do(req)
	if err != nil {
		w.CountEgressDiscarded()
		w.LogError("http post failed: %s", err)
		w.jsonBuffer.Reset()
		w.bufferCount = 0
		return
	}

	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		w.CountEgressDiscarded()
		w.LogError("clickhouse returned error status %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	} else {
		w.CountEgressTraffic()
	}

	w.jsonBuffer.Reset()
	w.bufferCount = 0
}

func convertDNSMessageToRecord(dm *dnsutils.DNSMessage) ClickhouseRecord {
	qPort, _ := strconv.Atoi(dm.NetworkInfo.QueryPort)
	rPort, _ := strconv.Atoi(dm.NetworkInfo.ResponsePort)

	record := ClickhouseRecord{
		Timestamp:    int64(dm.DNSTap.TimeSec),
		TimeNSec:     dm.DNSTap.Timestamp,
		TimestampRFC: dm.DNSTap.TimestampRFC3339,
		Identity:     dm.DNSTap.Identity,
		QueryIP:      dm.NetworkInfo.GetQueryIP(),
		QueryPort:    qPort,
		ResponseIP:   dm.NetworkInfo.GetResponseIP(),
		ResponsePort: rPort,
		Family:       dm.NetworkInfo.Family,
		Protocol:     dm.NetworkInfo.Protocol,
		Length:       dm.DNS.Length,
		ID:           dm.DNS.ID,
		Opcode:       dm.DNS.Opcode,
		RCode:        dm.DNS.Rcode,
		QName:        dm.DNS.Qname,
		QType:        dm.DNS.Qtype,
		Operation:    dm.DNSTap.Operation,
		Latency:      dm.DNSTap.Latency,
		QR:           dm.DNS.Flags.QR,
		TC:           dm.DNS.Flags.TC,
		AA:           dm.DNS.Flags.AA,
		RA:           dm.DNS.Flags.RA,
		AD:           dm.DNS.Flags.AD,
		RD:           dm.DNS.Flags.RD,
		CD:           dm.DNS.Flags.CD,
		Malformed:    dm.DNS.MalformedPacket,
	}

	if dm.PublicSuffix != nil {
		record.TLD = dm.PublicSuffix.QnamePublicSuffix
		record.ETLDPlusOne = dm.PublicSuffix.QnameEffectiveTLDPlusOne
	}
	if dm.Geo != nil {
		record.City = dm.Geo.City
		record.Country = dm.Geo.CountryIsoCode
		record.ASNumber, _ = strconv.Atoi(dm.Geo.AutonomousSystemNumber)
		record.ASOwner = dm.Geo.AutonomousSystemOrg
	}
	if dm.Suspicious != nil {
		record.SuspiciousScore = dm.Suspicious.Score
	}

	return record
}

func init() {
	RegisterLogger("clickhouse", func(c *config.Config) bool { return c.Loggers.ClickhouseClient.Enable }, func(c *config.Config, l *logger.Logger, s string) Worker {
		return NewClickhouseClient(c, l, s)
	})
}
