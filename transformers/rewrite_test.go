package transformers

import (
	"strings"
	"testing"

	"github.com/dmachard/go-dnscollector/v3/dnsutils"
	"github.com/dmachard/go-dnscollector/v3/pkg/config"
	"github.com/dmachard/go-logger"
)

func TestRewrite_UpdateFields(t *testing.T) {
	// enable feature
	cfg := config.GetFakeConfigTransformers()
	cfg.Rewrite.Enable = true
	cfg.Rewrite.Identifiers = make(map[string]interface{})
	cfg.Rewrite.Identifiers["dnstap.identity"] = "testidentity"

	// init the processor
	outChans := []chan *dnsutils.DNSMessageBatch{}
	rewrite := NewRewriteTransform(&cfg.Rewrite, logger.New(false), "test", 0, outChans)

	// get fake
	dm := dnsutils.GetFakeDNSMessage()

	rewrite.GetTransforms()
	returnCode, err := rewrite.UpdateValues(&dm)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if returnCode != ReturnKeep {
		t.Errorf("Return code is %v, want keep(%v)", returnCode, ReturnKeep)
	}

	if dm.DNSTap.Identity != "testidentity" {
		t.Errorf("Want testidentity, got %v", dm.DNSTap.Identity)
	}
}

func TestRewrite_UpdateFields_InvalidType(t *testing.T) {
	// enable feature
	cfg := config.GetFakeConfigTransformers()
	cfg.Rewrite.Enable = true
	cfg.Rewrite.Identifiers = make(map[string]interface{})
	cfg.Rewrite.Identifiers["dnstap.identity"] = 0

	// init the processor
	outChans := []chan *dnsutils.DNSMessageBatch{}
	rewrite := NewRewriteTransform(&cfg.Rewrite, logger.New(false), "test", 0, outChans)

	// get fake
	dm := dnsutils.GetFakeDNSMessage()

	rewrite.GetTransforms()
	_, err := rewrite.UpdateValues(&dm)
	if err == nil {
		t.Fatalf("Expected error, got nil")
	}

	if !strings.Contains(err.Error(), "unable to set value") {
		t.Errorf("invalid error: %s", err)
	}
}

func TestRewrite_QueryIP_BinaryIngestionIgnored(t *testing.T) {
	// Reproduce Bug B.2:
	// When rewrite changes network.query-ip, it assigns dm.NetworkInfo.QueryIP = s.
	// But if the packet came from a binary collector (QueryIPBuf populated, QueryIPLen > 0),
	// QueryIPBuf is never cleared.
	// Therefore GetQueryIP(), ToJSON(), and ToText() continue to return the original IP!
	cfg := config.GetFakeConfigTransformers()
	cfg.Rewrite.Enable = true
	cfg.Rewrite.Identifiers = map[string]interface{}{
		"network.query-ip": "10.0.0.99",
	}

	rewrite := NewRewriteTransform(&cfg.Rewrite, logger.New(false), "test", 0, nil)
	rewrite.GetTransforms()

	dm := dnsutils.GetFakeDNSMessage()
	dm.NetworkInfo.SetQueryIPBytes([]byte{1, 2, 3, 4}) // Ingested as 1.2.3.4

	_, err := rewrite.UpdateValues(&dm)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// The struct field was written:
	if dm.NetworkInfo.QueryIP != "10.0.0.99" {
		t.Fatalf("expected QueryIP field to be 10.0.0.99, got: %s", dm.NetworkInfo.QueryIP)
	}

	// But GetQueryIP() and ToJSON() still return the OLD IP 1.2.3.4:
	gotIP := dm.NetworkInfo.GetQueryIP()
	if gotIP != "10.0.0.99" {
		t.Errorf("REWRITE INOPERATIVE in GetQueryIP(): expected 10.0.0.99, got: %s", gotIP)
	}

	jsonOutput := dm.ToJSON()
	if strings.Contains(jsonOutput, `"query-ip":"1.2.3.4"`) {
		t.Errorf("REWRITE INOPERATIVE in ToJSON(): output still has old IP 1.2.3.4! Output: %s", jsonOutput)
	}
	if !strings.Contains(jsonOutput, `"query-ip":"10.0.0.99"`) {
		t.Errorf("expected rewritten IP 10.0.0.99 in JSON output, got: %s", jsonOutput)
	}
}

