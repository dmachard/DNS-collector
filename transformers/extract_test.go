package transformers

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/dmachard/go-dnscollector/dnsutils"
	"github.com/dmachard/go-dnscollector/pkgconfig"
	"github.com/dmachard/go-logger"
)

func TestExtract_Json(t *testing.T) {
	// enable feature
	config := pkgconfig.GetFakeConfigTransformers()
	outChans := []chan dnsutils.DNSMessage{}
	outChans = append(outChans, make(chan dnsutils.DNSMessage, 1))

	// get dns message
	dm := dnsutils.GetFakeDNSMessageWithPayload()

	// init subprocessor
	extract := NewExtractTransform(config, logger.New(false), "test", 0, outChans)
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
	config := pkgconfig.GetFakeConfigTransformers()
	config.Extract.Enable = true
	config.Extract.Base64Fields = []string{"dns.qname"}
	config.Extract.HexFields = []string{"dns.qname"}

	outChans := []chan dnsutils.DNSMessage{}
	outChans = append(outChans, make(chan dnsutils.DNSMessage, 1))

	// get dns message with non-UTF8 qname (Latin-1 \344)
	dm := dnsutils.GetFakeDNSMessage()
	dm.DNS.Qname = "test-request-\xe4bcd.com"

	// init transform
	extract := NewExtractTransform(config, logger.New(false), "test", 0, outChans)
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
