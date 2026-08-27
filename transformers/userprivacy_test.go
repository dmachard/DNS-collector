package transformers

import (
	"testing"

	"github.com/dmachard/go-dnscollector/v3/dnsutils"
	"github.com/dmachard/go-dnscollector/v3/pkg/config"
	"github.com/dmachard/go-logger"
)

var (
	TestIP4     = "192.168.1.2"
	TestIP6     = "fe80::6111:626:c1b2:2353"
	IPv6ShortND = "fe80::"
)

func TestUserPrivacy_ReduceQname(t *testing.T) {
	// enable feature
	cfg := config.GetFakeConfigTransformers()
	cfg.UserPrivacy.Enable = true
	cfg.UserPrivacy.MinimizeQname = true

	outChans := []chan *dnsutils.DNSMessageBatch{}

	// init the processor
	userPrivacy := NewUserPrivacyTransform(&cfg.UserPrivacy, logger.New(false), "test", 0, outChans)
	userPrivacy.GetTransforms()

	// Define test cases
	testCases := []struct {
		input      string
		expected   string
		returnCode int
	}{
		{"www.google.com", "google.com", ReturnKeep},
		{"localhost", "localhost", ReturnKeep},
		{"null", "null", ReturnKeep},
		{"invalid", "invalid", ReturnKeep},
		{"localhost.domain.local.home", "local.home", ReturnKeep},
	}

	// Execute test cases
	for _, tc := range testCases {
		t.Run(tc.input, func(t *testing.T) {
			dm := dnsutils.GetFakeDNSMessage()
			dm.DNS.Qname = tc.input

			returnCode, err := userPrivacy.minimizeQname(&dm)
			if err != nil {
				t.Fatalf("Unexpected error: %v", err)
			}

			if dm.DNS.Qname != tc.expected {
				t.Errorf("Qname minimization failed, got %s, want %s", dm.DNS.Qname, tc.expected)
			}

			if returnCode != tc.returnCode {
				t.Errorf("Return code is %v, want %v", returnCode, tc.returnCode)
			}
		})
	}
}

func TestUserPrivacy_HashIP(t *testing.T) {
	// Define test cases
	testCases := []struct {
		name       string
		inputIP    string
		expectedIP string
		hashAlgo   string
	}{
		{"Hash IP Default", TestIP4, "c0ca1efec6aaf505e943397662c28f89ac8f3bc2", ""},
		{"Hash IP Sha512", TestIP4, "800e8f97a29404b7031dfb8d7185b2d30a3cd326b535cda3dcec20a0f4749b1099f98e49245d67eb188091adfba9a45dc0c15e612b554ae7181d8f8a479b67a0", "sha512"},
	}

	// Execute test cases
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Enable feature and set specific hash algorithm if provided
			cfg := config.GetFakeConfigTransformers()
			cfg.UserPrivacy.Enable = true
			cfg.UserPrivacy.HashQueryIP = true
			if tc.hashAlgo != "" {
				cfg.UserPrivacy.HashIPAlgo = tc.hashAlgo
			}

			outChans := []chan *dnsutils.DNSMessageBatch{}

			// Init the processor
			userPrivacy := NewUserPrivacyTransform(&cfg.UserPrivacy, logger.New(false), "test", 0, outChans)
			userPrivacy.GetTransforms()

			dm := dnsutils.GetFakeDNSMessage()
			dm.NetworkInfo.QueryIP = tc.inputIP

			returnCode, err := userPrivacy.hashQueryIP(&dm)
			if err != nil {
				t.Fatalf("Unexpected error: %v", err)
			}

			if dm.NetworkInfo.QueryIP != tc.expectedIP {
				t.Errorf("IP hashing failed, got %s, want %s", dm.NetworkInfo.QueryIP, tc.expectedIP)
			}

			if returnCode != ReturnKeep {
				t.Errorf("Return code is %v, want %v", returnCode, ReturnKeep)
			}
		})
	}
}

func TestUserPrivacy_AnonymizeIP(t *testing.T) {
	// Enable feature
	cfg := config.GetFakeConfigTransformers()
	cfg.UserPrivacy.Enable = true
	cfg.UserPrivacy.AnonymizeIP = true

	outChans := []chan *dnsutils.DNSMessageBatch{}

	// Init the processor
	userPrivacy := NewUserPrivacyTransform(&cfg.UserPrivacy, logger.New(false), "test", 0, outChans)
	userPrivacy.GetTransforms()

	// Define test cases
	testCases := []struct {
		name       string
		inputIP    string
		expected   string
		expectErr  bool
		returnCode int
	}{
		{"IPv4 Default Mask", "192.168.1.2", "192.168.0.0", false, ReturnKeep},
		{"IPv6 Default Mask", "fe80::6111:626:c1b2:2353", "fe80::", false, ReturnKeep},
		{"Invalid ip", "xxxxxxxxxxx", "xxxxxxxxxxx", true, ReturnKeep},
	}

	// Execute test cases
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			dm := dnsutils.GetFakeDNSMessage()
			dm.NetworkInfo.QueryIP = tc.inputIP

			returnCode, err := userPrivacy.anonymizeQueryIP(&dm)
			if err != nil && !tc.expectErr {
				t.Fatalf("Unexpected error: %v", err)
			}

			if dm.NetworkInfo.QueryIP != tc.expected {
				t.Errorf("%s anonymization failed, got %s, want %s", tc.name, dm.NetworkInfo.QueryIP, tc.expected)
			}

			if returnCode != tc.returnCode {
				t.Errorf("Return code is %v, want %v", returnCode, tc.returnCode)
			}
		})
	}

	// Test with binary buffer (lazy IP)
	dm := dnsutils.GetFakeDNSMessage()
	dm.NetworkInfo.SetQueryIPBytes([]byte{192, 168, 1, 2})
	returnCode, err := userPrivacy.anonymizeQueryIP(&dm)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if dm.NetworkInfo.GetQueryIP() != "192.168.0.0" {
		t.Errorf("Lazy IP anonymization failed, got %s, want 192.168.0.0", dm.NetworkInfo.GetQueryIP())
	}
	if returnCode != ReturnKeep {
		t.Errorf("Return code is %v, want %v", returnCode, ReturnKeep)
	}
}

func TestUserPrivacy_AnonymizeIPRemove(t *testing.T) {
	// Enable feature and set specific IP anonymization mask
	cfg := config.GetFakeConfigTransformers()
	cfg.UserPrivacy.Enable = true
	cfg.UserPrivacy.AnonymizeIP = true
	cfg.UserPrivacy.AnonymizeIPV4Bits = "/0"
	cfg.UserPrivacy.AnonymizeIPV6Bits = "::/0"

	// Init the processor
	userPrivacy := NewUserPrivacyTransform(&cfg.UserPrivacy, logger.New(false), "test", 0, []chan *dnsutils.DNSMessageBatch{})
	userPrivacy.GetTransforms()

	// Define test cases
	testCases := []struct {
		name       string
		inputIP    string
		expectedIP string
	}{
		{"IPv4 Remove IP", TestIP4, "0.0.0.0"},
		{"IPv6 Remove IP", TestIP6, "::"},
	}

	// Execute test cases
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {

			dm := dnsutils.GetFakeDNSMessage()
			dm.NetworkInfo.QueryIP = tc.inputIP

			userPrivacy.anonymizeQueryIP(&dm)
			if dm.NetworkInfo.QueryIP != tc.expectedIP {
				t.Errorf("anonymization failed got %s, want %s", dm.NetworkInfo.QueryIP, tc.expectedIP)
			}
		})
	}
}
