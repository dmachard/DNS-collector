package transformers

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/dmachard/go-dnscollector/v2/dnsutils"
	"github.com/dmachard/go-dnscollector/v2/pkg/config"
	"github.com/dmachard/go-logger"
)

func TestExtract_Json(t *testing.T) {
	// enable feature
	cfg := config.GetFakeConfigTransformers()
	outChans := []chan *dnsutils.DNSMessageBatch{}
	outChans = append(outChans, make(chan *dnsutils.DNSMessageBatch, 1))

	// get dns message
	dm := dnsutils.GetFakeDNSMessageWithPayload()

	// init subprocessor
	extract := NewExtractTransform(cfg, logger.New(false), "test", 0, outChans)
	extract.GetTransforms()
	extract.addBase64Payload(&dm)

	encodedPayload := base64.StdEncoding.EncodeToString(dm.DNS.Payload)

	// expected json
	refJSON := fmt.Sprintf(`
			{
				"extracted":{
					"dns_payload": "%s"
				}
			}
			`, encodedPayload)

	var dmMap map[string]interface{}
	err := json.Unmarshal([]byte(dm.ToJSON()), &dmMap)
	if err != nil {
		t.Fatalf("could not unmarshal dm json: %s\n", err)
	}

	var refMap map[string]interface{}
	err = json.Unmarshal([]byte(refJSON), &refMap)
	if err != nil {
		t.Fatalf("could not unmarshal ref json: %s\n", err)
	}

	if _, ok := dmMap["extracted"]; !ok {
		t.Fatalf("transformer key is missing")
	}

	if !reflect.DeepEqual(dmMap["extracted"], refMap["extracted"]) {
		t.Errorf("json format different from reference")
	}
}

func TestExtract_Base64AndHexFields(t *testing.T) {
	// This test validates the new "Base64 and Hex extraction" feature.
	// It ensures that even when a field contains invalid UTF-8 characters
	// (which are normally replaced by \ufffd in the default JSON output),
	// the Data Extractor can still provide the original raw bytes via Base64 or Hex encoding.

	// enable feature
	cfg := config.GetFakeConfigTransformers()
	cfg.Extract.Enable = true
	cfg.Extract.Base64Fields = []string{"dns.qname"}
	cfg.Extract.HexFields = []string{"dns.qname"}

	outChans := []chan *dnsutils.DNSMessageBatch{}
	outChans = append(outChans, make(chan *dnsutils.DNSMessageBatch, 1))

	// get dns message with non-UTF8 qname (Latin-1 \344)
	dm := dnsutils.GetFakeDNSMessage()
	dm.DNS.Qname = "test-request-\xe4bcd.com"

	// init transform
	extract := NewExtractTransform(cfg, logger.New(false), "test", 0, outChans)
	extract.GetTransforms()

	// process
	extract.addBase64Fields(&dm)
	extract.addHexFields(&dm)

	// Check results in Extracted struct
	if dm.Extracted == nil {
		t.Fatalf("Extracted struct is nil")
	}

	// Base64 check
	// "test-request-\xe4bcd.com" in base64 is "dGVzdC1yZXF1ZXN0LeRiY2QuY29t"
	expectedBase64 := "dGVzdC1yZXF1ZXN0LeRiY2QuY29t"
	if _, ok := dm.Extracted.Base64Fields["dns.qname"]; !ok {
		t.Errorf("dns.qname missing from base64_fields")
	}

	// Marshalling to JSON to verify the "replacement character" behavior and our new fields
	jsonStr := dm.ToJSON()

	// 1. Verify that the standard qname contains the replacement character (UTF-8 \ufffd)
	// It might be escaped as \ufffd in JSON
	if !strings.Contains(jsonStr, "\\ufffd") && !strings.Contains(jsonStr, "\ufffd") {
		t.Errorf("JSON should contain replacement character for invalid UTF-8 in qname")
	}

	// 2. Verify Base64Fields
	if !strings.Contains(jsonStr, expectedBase64) {
		t.Errorf("JSON should contain the correct Base64 encoded qname")
	}

	// 3. Verify HexFields
	// "test-request-\xe4bcd.com" in hex: 746573742d726571756573742de46263642e636f6d
	expectedHex := "746573742d726571756573742de46263642e636f6d"
	if !strings.Contains(jsonStr, expectedHex) {
		t.Errorf("JSON should contain the correct Hex encoded qname")
	}
}

func TestExtract_WildcardSliceFields(t *testing.T) {
	// enable feature
	cfg := config.GetFakeConfigTransformers()
	cfg.Extract.Enable = true
	cfg.Extract.Base64Fields = []string{"dns.resource-records.an.*.rdata"}
	cfg.Extract.HexFields = []string{"dns.resource-records.an.*.rdata"}

	outChans := []chan *dnsutils.DNSMessageBatch{}
	outChans = append(outChans, make(chan *dnsutils.DNSMessageBatch, 1))

	// get dns message
	dm := dnsutils.GetFakeDNSMessage()
	// add multiple resource records (answers) with non-UTF8 rdata (Latin-1 \344)
	dm.DNS.DNSRRs.Answers = []dnsutils.DNSAnswer{
		{
			Name:      "google.com",
			Rdatatype: "TXT",
			Rdata:     "test-\xe4bcd",
		},
		{
			Name:      "google.com",
			Rdatatype: "TXT",
			Rdata:     "another-\xe4bcd",
		},
	}

	// init transform
	extract := NewExtractTransform(cfg, logger.New(false), "test", 0, outChans)
	extract.GetTransforms()

	// process
	extract.addBase64Fields(&dm)
	extract.addHexFields(&dm)

	// Check results in Extracted struct
	if dm.Extracted == nil {
		t.Fatalf("Extracted struct is nil")
	}

	// Base64 check
	// "test-\xe4bcd" -> "dGVzdC3kYmNk"
	// "another-\xe4bcd" -> "YW5vdGhlci3kYmNk"
	expectedBase64_1 := "dGVzdC3kYmNk"
	expectedBase64_2 := "YW5vdGhlci3kYmNk"

	b64FieldVal, ok := dm.Extracted.Base64Fields["dns.resource-records.an.*.rdata"]
	if !ok {
		t.Fatalf("dns.resource-records.an.*.rdata missing from base64_fields")
	}
	sliceB64, ok := b64FieldVal.([][]byte)
	if !ok {
		t.Fatalf("base64 field dns.resource-records.an.*.rdata is not a [][]byte slice")
	}
	if len(sliceB64) != 2 {
		t.Fatalf("expected 2 base64 values, got %d", len(sliceB64))
	}
	if string(sliceB64[0]) != "test-\xe4bcd" || string(sliceB64[1]) != "another-\xe4bcd" {
		t.Errorf("base64 values mismatch, got: %s and %s", sliceB64[0], sliceB64[1])
	}

	// Hex check
	// "test-\xe4bcd" -> "746573742de4626364"
	// "another-\xe4bcd" -> "616e6f746865722de4626364"
	expectedHex_1 := "746573742de4626364"
	expectedHex_2 := "616e6f746865722de4626364"

	hexFieldVal, ok := dm.Extracted.HexFields["dns.resource-records.an.*.rdata"]
	if !ok {
		t.Fatalf("dns.resource-records.an.*.rdata missing from hex_fields")
	}
	sliceHex, ok := hexFieldVal.([]string)
	if !ok {
		t.Fatalf("hex field dns.resource-records.an.*.rdata is not a []string slice")
	}
	if len(sliceHex) != 2 {
		t.Fatalf("expected 2 hex values, got %d", len(sliceHex))
	}
	if sliceHex[0] != expectedHex_1 || sliceHex[1] != expectedHex_2 {
		t.Errorf("hex values mismatch, got: %s and %s", sliceHex[0], sliceHex[1])
	}

	// Marshalling to JSON to verify the "replacement character" behavior and our new fields
	jsonStr := dm.ToJSON()

	// 1. Verify JSON contains Base64 values (inside list/array)
	if !strings.Contains(jsonStr, expectedBase64_1) || !strings.Contains(jsonStr, expectedBase64_2) {
		t.Errorf("JSON should contain the correct Base64 encoded values in array")
	}

	// 2. Verify JSON contains Hex values (inside list/array)
	if !strings.Contains(jsonStr, expectedHex_1) || !strings.Contains(jsonStr, expectedHex_2) {
		t.Errorf("JSON should contain the correct Hex encoded values in array")
	}
}
