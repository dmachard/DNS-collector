package telemetry

import (
	"context"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/dmachard/go-dnscollector/v3/pkg/config"
	"github.com/dmachard/go-logger"
	"github.com/stretchr/testify/assert"
)

func TestTelemetry_SanitizeMetricName(t *testing.T) {
	testCases := []struct {
		input    string
		expected string
	}{
		{"metric:name", "metric_name"},
		{"metric-name", "metric_name"},
		{"metric.name", "metric_name"},
	}

	for _, tc := range testCases {
		actual := SanitizeMetricName(tc.input)
		assert.Equal(t, tc.expected, actual)
	}
}

func TestTelemetry_PrometheusCollectorUpdateStats(t *testing.T) {
	cfg := config.Config{}

	collector := NewPrometheusCollector(&cfg)

	// Create a sample WorkerStats
	ws := WorkerStats{
		Name:         "worker1",
		TotalIngress: 10, TotalEgress: 5,
		TotalForwardedPolicy: 2, TotalDroppedPolicy: 1, TotalDiscarded: 3,
	}

	// Send the stats to the collector
	go collector.UpdateStats()
	collector.Record <- ws

	// Verify that the stats were updated
	storedWS, ok := collector.GetWorkerStats("worker1")
	assert.True(t, ok, "Worker stats should be present in the collector")
	assert.Equal(t, ws.TotalIngress, storedWS.TotalIngress)
	assert.Equal(t, ws.TotalEgress, storedWS.TotalEgress)
	assert.Equal(t, ws.TotalForwardedPolicy, storedWS.TotalForwardedPolicy)
	assert.Equal(t, ws.TotalDroppedPolicy, storedWS.TotalDroppedPolicy)
	assert.Equal(t, ws.TotalDiscarded, storedWS.TotalDiscarded)
}

func TestTelemetry_InitTelemetryServer_UnixSocket(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	// keep the filename to one char: AF_UNIX sun_path is capped at ~108 bytes
	sockPath := filepath.Join(tmpDir, "a")

	cfg := config.GetDefaultConfig()
	cfg.Global.Telemetry.Enabled = true
	cfg.Global.Telemetry.SockPath = sockPath
	cfg.Global.Telemetry.SockMode = "0660"
	cfg.Global.Telemetry.BasicAuthEnable = true
	cfg.Global.Telemetry.BasicAuthLogin = "admin"
	cfg.Global.Telemetry.BasicAuthPwd = "changeme"

	promServer, _, errChan := InitTelemetryServer(cfg, logger.New(false))

	go func() {
		for err := range errChan {
			t.Logf("telemetry server error: %v", err)
		}
	}()

	// wait for the listener goroutine to create the socket file
	deadline := time.Now().Add(2 * time.Second)
	for {
		if _, statErr := os.Stat(sockPath); statErr == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("socket file was not created: %s", sockPath)
		}
		time.Sleep(10 * time.Millisecond)
	}

	client := &http.Client{
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				var d net.Dialer
				return d.DialContext(ctx, "unix", sockPath)
			},
		},
	}

	// no credentials -> 401
	resp, err := client.Get("http://unix/metrics")
	if err != nil {
		t.Fatalf("request without credentials failed: %v", err)
	}
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
	resp.Body.Close()

	// correct credentials -> 200, body contains a well-known metric
	req, err := http.NewRequest(http.MethodGet, "http://unix/metrics", nil)
	if err != nil {
		t.Fatalf("failed to build request: %v", err)
	}
	req.SetBasicAuth("admin", "changeme")
	resp, err = client.Do(req)
	if err != nil {
		t.Fatalf("authenticated request failed: %v", err)
	}
	body, err := io.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		t.Fatalf("failed to read response body: %v", err)
	}
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Contains(t, string(body), "go_goroutines")

	// socket mode matches sock-mode
	fi, err := os.Stat(sockPath)
	if err != nil {
		t.Fatalf("failed to stat socket: %v", err)
	}
	assert.Equal(t, os.FileMode(0660), fi.Mode().Perm())

	// graceful shutdown removes the socket file
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := promServer.Shutdown(ctx); err != nil {
		t.Fatalf("shutdown failed: %v", err)
	}

	_, err = os.Stat(sockPath)
	assert.True(t, os.IsNotExist(err), "socket file should be removed after shutdown")
}

func TestTelemetry_prepareUnixSocket_RefusesNonSocket(t *testing.T) {
	dir, err := os.MkdirTemp("", "")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)

	p := filepath.Join(dir, "f")
	if err := os.WriteFile(p, []byte("keep me"), 0o600); err != nil {
		t.Fatal(err)
	}

	l, err := prepareUnixSocket(p, 0o660)
	if err == nil {
		l.Close()
		t.Fatal("expected an error for a non-socket file")
	}
	if _, statErr := os.Stat(p); statErr != nil {
		t.Fatalf("non-socket file must not be deleted: %v", statErr)
	}
}
