package transformers

import (
	"testing"

	"github.com/dmachard/go-dnscollector/v2/dnsutils"
	"github.com/dmachard/go-dnscollector/v2/pkgconfig"
	"github.com/dmachard/go-logger"
)

const (
	IPv6Address = "fe80::6111:626:c1b2:2353"
	CapsAddress = "www.Google.Com"
	NormAddress = "www.google.com"

	Localhost = "localhost"
)

func TestTransforms_ProcessOrder(t *testing.T) {
	// enable feature
	config := pkgconfig.GetFakeConfigTransformers()
	config.Normalize.Enable = true
	config.Normalize.QnameLowerCase = true
	config.UserPrivacy.Enable = true
	config.UserPrivacy.AnonymizeIP = true
	config.Filtering.Enable = true
	config.Filtering.KeepDomainFile = "../tests/testsdata/filtering_keep_domains.txt" // file contains google.fr, test.github.com

	testURL1 := "mail.google.com"
	testURL2 := "test.github.com"

	// init the transformer
	subprocessors := NewTransforms(config, logger.New(false), "test", []chan *dnsutils.DNSMessage{}, 0)

	// create test message
	dm := dnsutils.GetFakeDNSMessage()

	// should be dropped and not transformed
	dm.DNS.Qname = testURL1
	dm.NetworkInfo.QueryIP = IPv6Address

	returnCode, err := subprocessors.ProcessMessage(&dm)
	if err != nil {
		t.Errorf("process transform err %s", err.Error())
	}

	if returnCode != ReturnDrop {
		t.Errorf("Return code is %v and not RETURN_KEEP (%v)", returnCode, ReturnKeep)
	}

	// should not be dropped, and should be transformed
	dm.DNS.Qname = testURL2
	dm.NetworkInfo.QueryIP = IPv6Address

	returnCode, err = subprocessors.ProcessMessage(&dm)
	if err != nil {
		t.Errorf("process transform err %s", err.Error())
	}

	if returnCode != ReturnKeep {
		t.Errorf("Return code is %v and not RETURN_KEEP (%v)", returnCode, ReturnKeep)
	}
	if dm.NetworkInfo.QueryIP != IPv6ShortND {
		t.Errorf("Ipv6 anonymization failed, got %s", dm.NetworkInfo.QueryIP)
	}
}

func TestTransforms_ConfigurableOrder(t *testing.T) {
	config := pkgconfig.GetFakeConfigTransformers()
	config.Order = []string{"geoip", "normalize"}
	config.GeoIP.Enable = true
	config.Normalize.Enable = true
	config.Normalize.QnameLowerCase = true

	subprocessors := NewTransforms(config, logger.New(false), "test", []chan *dnsutils.DNSMessage{}, 0)

	if len(subprocessors.activeTransforms) != 2 {
		t.Fatalf("expected 2 active transforms, got %d", len(subprocessors.activeTransforms))
	}

	st0, _ := subprocessors.activeTransforms[0].GetTransforms()
	if st0[0].name != "geoip:lookup" {
		t.Errorf("expected geoip:lookup first, got %s", st0[0].name)
	}

	// find the qname-lowercase subtransform in normalize
	st1, _ := subprocessors.activeTransforms[1].GetTransforms()
	found := false
	for _, st := range st1 {
		if st.name == "normalize:qname-lowercase" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected normalize:qname-lowercase second, but not found")
	}

	// Reverse order
	config.Order = []string{"normalize", "geoip"}
	subprocessors = NewTransforms(config, logger.New(false), "test", []chan *dnsutils.DNSMessage{}, 0)

	st0, _ = subprocessors.activeTransforms[0].GetTransforms()
	found = false
	for _, st := range st0 {
		if st.name == "normalize:qname-lowercase" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected normalize:qname-lowercase first, but not found")
	}

	st1, _ = subprocessors.activeTransforms[1].GetTransforms()
	if st1[0].name != "geoip:lookup" {
		t.Errorf("expected geoip:lookup second, got %s", st1[0].name)
	}
}
