package workers

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"net/http"
	"regexp"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/dmachard/go-dnscollector/v3/dnsutils"
	"github.com/dmachard/go-dnscollector/v3/pkg/config"
	"github.com/dmachard/go-logger"
	"github.com/golang/snappy"
	"github.com/prometheus/common/model"
	"github.com/prometheus/prometheus/model/relabel"
)

func Test_LokiClientRun(t *testing.T) {
	testcases := []struct {
		mode    string
		pattern string
	}{
		{
			mode:    config.ModeText,
			pattern: "0b dns.collector A",
		},
		{
			mode:    config.ModeJSON,
			pattern: "\"qname\":\"dns.collector\"",
		},
		{
			mode:    config.ModeFlatJSON,
			pattern: "\"dns.qname\":\"dns.collector\"",
		},
	}

	// fake msgpack receiver
	fakeRcvr, err := net.Listen("tcp", "127.0.0.1:3100")
	if err != nil {
		t.Fatal(err)
	}
	defer fakeRcvr.Close()

	for _, tc := range testcases {
		t.Run(tc.mode, func(t *testing.T) {
			// init logger
			cfg := config.GetDefaultConfig()
			cfg.Loggers.LokiClient.Mode = tc.mode
			cfg.Loggers.LokiClient.BatchSize = 0
			g := NewLokiClient(cfg, logger.New(false), "test")

			// start the logger
			go g.StartCollect()
			defer g.Stop()

			// send fake dns message to logger
			dm := dnsutils.GetFakeDNSMessage()
			dm.DNSTap.Identity = dnsutils.DNSTapIdentityTest
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
			protobuf, err := io.ReadAll(request.Body)
			if err != nil {
				t.Fatal(err)
			}

			protobufDec, err := snappy.Decode(nil, protobuf)
			if err != nil {
				t.Fatal(err)
			}
			labelsPattern := regexp.MustCompile("{identity=\"test_id\", job=\"dnscollector\"}")
			if !labelsPattern.MatchString(string(protobufDec)) {
				t.Errorf("loki test error want {identity=\"test_id\", job=\"dnscollector\"}, got: %s", string(protobufDec))
			}
			pattern := regexp.MustCompile(tc.pattern)
			if !pattern.MatchString(string(protobufDec)) {
				t.Errorf("loki test error want %s, got: %s", tc.pattern, string(protobufDec))
			}
		})
	}
}

func Test_LokiClientRelabel(t *testing.T) {
	testcases := []struct {
		name          string
		relabelConfig []*relabel.Config
		labelsPattern string
	}{
		{
			name: "export rcode label from __dns_rcode",
			relabelConfig: []*relabel.Config{
				{
					Action:       relabel.Replace,
					Separator:    ";",
					Regex:        relabel.MustNewRegexp("^(.+)$"),
					Replacement:  "$1",
					SourceLabels: model.LabelNames{"__dns_rcode"},
					TargetLabel:  "rcode",
				},
			},
			labelsPattern: "{identity=\"test_id\", job=\"dnscollector\", rcode=\"NOERROR\"}",
		},
		{
			name: "internal relabel is dropped (__ labels are not exported)",
			relabelConfig: []*relabel.Config{
				{
					Action:       relabel.Replace,
					Separator:    ";",
					Regex:        relabel.MustNewRegexp("^(.+)$"),
					Replacement:  "$1",
					SourceLabels: model.LabelNames{"__dns_rcode"},
					TargetLabel:  "__rcode",
				},
			},
			labelsPattern: "{identity=\"test_id\", job=\"dnscollector\"}",
		},
		{
			name: "drop job label via relabel config",
			relabelConfig: []*relabel.Config{
				{
					Action: relabel.LabelDrop,
					Regex:  relabel.MustNewRegexp("job"),
				},
			},
			labelsPattern: "{identity=\"test_id\"}",
		},
		{
			name: "labelmap reads every internal label",
			relabelConfig: []*relabel.Config{
				{
					Action:      relabel.LabelMap,
					Regex:       relabel.MustNewRegexp("__dns_(rcode)"),
					Replacement: "$1",
				},
			},
			labelsPattern: "{identity=\"test_id\", job=\"dnscollector\", rcode=\"NOERROR\"}",
		},
		{
			name: "keepequal reads its target label",
			relabelConfig: []*relabel.Config{
				{
					Action:      relabel.Replace,
					Regex:       relabel.MustNewRegexp("(.*)"),
					Replacement: "NOERROR",
					TargetLabel: "__want",
				},
				{
					Action:       relabel.KeepEqual,
					SourceLabels: model.LabelNames{"__want"},
					TargetLabel:  "__dns_rcode",
				},
				{
					Action:      relabel.Replace,
					Regex:       relabel.MustNewRegexp("(.*)"),
					Replacement: "kept",
					TargetLabel: "status",
				},
			},
			labelsPattern: "{identity=\"test_id\", job=\"dnscollector\", status=\"kept\"}",
		},
	}

	// fake msgpack receiver
	fakeRcvr, err := net.Listen("tcp", "127.0.0.1:3100")
	if err != nil {
		t.Fatal(err)
	}
	defer fakeRcvr.Close()

	for _, tc := range testcases {
		for _, m := range []string{config.ModeText, config.ModeJSON, config.ModeFlatJSON} {
			t.Run(fmt.Sprintf("%s/%s", m, tc.name), func(t *testing.T) {
				// init logger
				cfg := config.GetDefaultConfig()
				cfg.Loggers.LokiClient.Mode = m
				cfg.Loggers.LokiClient.BatchSize = 0
				cfg.Loggers.LokiClient.RelabelConfigs = tc.relabelConfig
				g := NewLokiClient(cfg, logger.New(true), "test")

				// start the logger
				go g.StartCollect()
				defer g.Stop()

				// send fake dns message to logger
				dm := dnsutils.GetFakeDNSMessage()
				dm.DNSTap.Identity = dnsutils.DNSTapIdentityTest
				g.GetInputChannel() <- dnsutils.NewDNSMessageBatch(&dm)

				// accept conn; a message the relabel rules dropped never arrives
				_ = fakeRcvr.(*net.TCPListener).SetDeadline(time.Now().Add(5 * time.Second))
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
				protobuf, err := io.ReadAll(request.Body)
				if err != nil {
					t.Fatal(err)
				}

				protobufDec, err := snappy.Decode(nil, protobuf)
				if err != nil {
					t.Fatal(err)
				}

				labelsPattern := regexp.MustCompile(tc.labelsPattern)
				if !labelsPattern.MatchString(string(protobufDec)) {
					t.Errorf("loki test error want %s, got: %s", tc.labelsPattern, string(protobufDec))
				}
			})
		}
	}
}

func Test_LokiClientRelabelInput(t *testing.T) {
	flat := map[string]interface{}{
		"dns.qname":             "dns.collector",
		"dns.rcode":             "NOERROR",
		"dnstap.identity":       "test_id",
		"network-info.query-ip": "1.2.3.4",
	}

	testcases := []struct {
		name   string
		rules  []*relabel.Config
		expect []string
	}{
		{
			name: "only the source labels are built",
			rules: []*relabel.Config{
				{Action: relabel.Replace, Regex: relabel.MustNewRegexp("(.*)"), Replacement: "$1",
					SourceLabels: model.LabelNames{"__dns_qname"}, TargetLabel: "qname"},
				{Action: relabel.Keep, Regex: relabel.MustNewRegexp("1.*"),
					SourceLabels: model.LabelNames{"__network_info_query_ip"}},
			},
			expect: []string{"__dns_qname", "__network_info_query_ip"},
		},
		{
			name: "keepequal target is built",
			rules: []*relabel.Config{
				{Action: relabel.KeepEqual, SourceLabels: model.LabelNames{"__dns_qname"}, TargetLabel: "__dns_rcode"},
			},
			expect: []string{"__dns_qname", "__dns_rcode"},
		},
		{
			name: "labelmap builds everything",
			rules: []*relabel.Config{
				{Action: relabel.LabelMap, Regex: relabel.MustNewRegexp("__dns_(.*)"), Replacement: "$1"},
			},
			expect: []string{"__dns_qname", "__dns_rcode", "__dnstap_identity", "__network_info_query_ip"},
		},
		{
			name:   "no source labels builds nothing",
			rules:  []*relabel.Config{{Action: relabel.LabelDrop, Regex: relabel.MustNewRegexp("job")}},
			expect: []string{},
		},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := config.GetDefaultConfig()
			cfg.Loggers.LokiClient.RelabelConfigs = tc.rules
			g := NewLokiClient(cfg, logger.New(false), "test")

			got := []string{}
			for _, l := range g.relabelInput(flat, nil) {
				got = append(got, l.Name)
			}
			sort.Strings(got)
			if strings.Join(got, ",") != strings.Join(tc.expect, ",") {
				t.Errorf("want %v, got %v", tc.expect, got)
			}
			for _, rc := range tc.rules {
				if rc.NameValidationScheme != model.LegacyValidation {
					t.Errorf("validation scheme not set on %v", rc.Action)
				}
			}
		})
	}
}
