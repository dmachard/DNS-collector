package transformers

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/dmachard/go-dnscollector/v2/dnsutils"
	"github.com/dmachard/go-dnscollector/v2/pkg/config"
	"github.com/dmachard/go-logger"
)

func TestUniqueResponseTracker_IsNewResponse(t *testing.T) {
	cfg := config.GetFakeConfigTransformers()
	cfg.UniqueResponseTracker.Enable = true
	cfg.UniqueResponseTracker.TTL = 2
	cfg.UniqueResponseTracker.CacheSize = 100

	outChans := []chan *dnsutils.DNSMessageBatch{}
	tracker := NewUniqueResponseTrackerTransform(cfg, logger.New(false), "test", 0, outChans)

	_, err := tracker.GetTransforms()
	if err != nil {
		t.Fatalf("fail to init transform: %v", err)
	}

	// 1. First response for example.com -> 1.2.3.4
	dm := dnsutils.GetFakeDNSMessage()
	dm.DNS.Qname = "example.com"
	dm.DNS.DNSRRs.Answers = []dnsutils.DNSAnswer{
		{Rdatatype: "A", Rdata: "1.2.3.4"},
	}

	if res, _ := tracker.trackUniqueResponse(&dm); res != ReturnKeep {
		t.Errorf("1. initial response should be unique!")
	}

	// 2. Duplicate response -> should be dropped
	if res, _ := tracker.trackUniqueResponse(&dm); res != ReturnDrop {
		t.Errorf("2. duplicate response should NOT be unique!")
	}

	// 3. Same domain, new IP 5.6.7.8 -> should be unique!
	dmNewIP := dnsutils.GetFakeDNSMessage()
	dmNewIP.DNS.Qname = "example.com"
	dmNewIP.DNS.DNSRRs.Answers = []dnsutils.DNSAnswer{
		{Rdatatype: "A", Rdata: "5.6.7.8"},
	}

	if res, _ := tracker.trackUniqueResponse(&dmNewIP); res != ReturnKeep {
		t.Errorf("3. new IP for same domain should be unique!")
	}

	// 4. Same domain, new CNAME -> should be unique!
	dmCNAME := dnsutils.GetFakeDNSMessage()
	dmCNAME.DNS.Qname = "example.com"
	dmCNAME.DNS.DNSRRs.Answers = []dnsutils.DNSAnswer{
		{Rdatatype: "CNAME", Rdata: "target.com"},
	}

	if res, _ := tracker.trackUniqueResponse(&dmCNAME); res != ReturnKeep {
		t.Errorf("4. new CNAME for same domain should be unique!")
	}

	// 5. Wait TTL expiration
	time.Sleep(3 * time.Second)

	// Recheck original response -> should be unique again after TTL
	if res, _ := tracker.trackUniqueResponse(&dm); res != ReturnKeep {
		t.Errorf("5. response after TTL expiration should be unique again!")
	}
}

func TestUniqueResponseTracker_NoAnswers(t *testing.T) {
	cfg := config.GetFakeConfigTransformers()
	cfg.UniqueResponseTracker.Enable = true
	cfg.UniqueResponseTracker.TTL = 2
	cfg.UniqueResponseTracker.CacheSize = 100

	outChans := []chan *dnsutils.DNSMessageBatch{}
	tracker := NewUniqueResponseTrackerTransform(cfg, logger.New(false), "test", 0, outChans)

	_, err := tracker.GetTransforms()
	if err != nil {
		t.Fatalf("fail to init transform: %v", err)
	}

	dm := dnsutils.GetFakeDNSMessage()
	dm.DNS.DNSRRs.Answers = []dnsutils.DNSAnswer{} // No answers

	if res, _ := tracker.trackUniqueResponse(&dm); res != ReturnDrop {
		t.Errorf("DNS message with no answers should be dropped")
	}
}

func TestUniqueResponseTracker_Whitelist(t *testing.T) {
	cfg := config.GetFakeConfigTransformers()
	cfg.UniqueResponseTracker.Enable = true
	cfg.UniqueResponseTracker.TTL = 2
	cfg.UniqueResponseTracker.CacheSize = 100
	cfg.UniqueResponseTracker.WhiteDomainsFile = "../tests/testsdata/newdomain_whitelist_regex.txt"

	outChans := []chan *dnsutils.DNSMessageBatch{}
	tracker := NewUniqueResponseTrackerTransform(cfg, logger.New(false), "test", 0, outChans)

	_, err := tracker.GetTransforms()
	if err != nil {
		t.Fatalf("fail to init transform: %v", err)
	}

	// Whitelisted domain
	dm := dnsutils.GetFakeDNSMessage()
	dm.DNS.Qname = testURL1
	dm.DNS.DNSRRs.Answers = []dnsutils.DNSAnswer{
		{Rdatatype: "A", Rdata: "1.2.3.4"},
	}

	if res, _ := tracker.trackUniqueResponse(&dm); res != ReturnDrop {
		t.Errorf("whitelisted domain response should NOT be flagged as unique!")
	}

	// Non-whitelisted domain
	dmNonWhite := dnsutils.GetFakeDNSMessage()
	dmNonWhite.DNS.Qname = "not-whitelisted.com"
	dmNonWhite.DNS.DNSRRs.Answers = []dnsutils.DNSAnswer{
		{Rdatatype: "A", Rdata: "1.2.3.4"},
	}

	if res, _ := tracker.trackUniqueResponse(&dmNonWhite); res != ReturnKeep {
		t.Errorf("non-whitelisted domain response should be unique!")
	}
}

func TestUniqueResponseTracker_Persistence(t *testing.T) {
	tempDir := t.TempDir()
	persistFile := filepath.Join(tempDir, "udr_cache.json")

	cfg := config.GetFakeConfigTransformers()
	cfg.UniqueResponseTracker.Enable = true
	cfg.UniqueResponseTracker.TTL = 60
	cfg.UniqueResponseTracker.CacheSize = 100
	cfg.UniqueResponseTracker.PersistenceFile = persistFile

	outChans := []chan *dnsutils.DNSMessageBatch{}
	tracker := NewUniqueResponseTrackerTransform(cfg, logger.New(false), "test", 0, outChans)

	_, err := tracker.GetTransforms()
	if err != nil {
		t.Fatalf("fail to init transform: %v", err)
	}

	dm := dnsutils.GetFakeDNSMessage()
	dm.DNS.Qname = "persistent.com"
	dm.DNS.DNSRRs.Answers = []dnsutils.DNSAnswer{
		{Rdatatype: "A", Rdata: "9.9.9.9"},
	}

	// First time -> unique
	if res, _ := tracker.trackUniqueResponse(&dm); res != ReturnKeep {
		t.Fatalf("expected unique response")
	}

	// Save cache to disk
	tracker.Reset()

	// New tracker instance loading state from disk
	tracker2 := NewUniqueResponseTrackerTransform(cfg, logger.New(false), "test2", 0, outChans)
	_, err = tracker2.GetTransforms()
	if err != nil {
		t.Fatalf("fail to init second transform: %v", err)
	}

	// Same query on second instance -> should already be known (ReturnDrop)
	if res, _ := tracker2.trackUniqueResponse(&dm); res != ReturnDrop {
		t.Errorf("response should have been restored from persistence file!")
	}
}

func TestUniqueResponseTracker_LRUCacheFull(t *testing.T) {
	cfg := config.GetFakeConfigTransformers()
	cfg.UniqueResponseTracker.Enable = true
	cfg.UniqueResponseTracker.TTL = 2
	cfg.UniqueResponseTracker.CacheSize = 1

	outChans := []chan *dnsutils.DNSMessageBatch{}
	tracker := NewUniqueResponseTrackerTransform(cfg, logger.New(false), "test", 0, outChans)

	_, err := tracker.GetTransforms()
	if err != nil {
		t.Fatalf("fail to init transform: %v", err)
	}

	dm := dnsutils.GetFakeDNSMessage()
	dm.DNS.Qname = "example.com"
	dm.DNS.DNSRRs.Answers = []dnsutils.DNSAnswer{
		{Rdatatype: "A", Rdata: "1.2.3.4"},
	}

	if res, _ := tracker.trackUniqueResponse(&dm); res != ReturnKeep {
		t.Errorf("initial response should be kept")
	}

	// Second query fills cache limit and returns error
	res, _ := tracker.trackUniqueResponse(&dm)
	if res != ReturnError {
		t.Errorf("expected ReturnError on full cache, got %d", res)
	}
}

func TestUniqueResponseTracker_Cuckoo_IsNewResponse(t *testing.T) {
	cfg := config.GetFakeConfigTransformers()
	cfg.UniqueResponseTracker.Enable = true
	cfg.UniqueResponseTracker.TTL = 2
	cfg.UniqueResponseTracker.CacheSize = 100
	cfg.UniqueResponseTracker.StorageEngine = "cuckoo"

	outChans := []chan *dnsutils.DNSMessageBatch{}
	tracker := NewUniqueResponseTrackerTransform(cfg, logger.New(false), "test-cuckoo", 0, outChans)

	_, err := tracker.GetTransforms()
	if err != nil {
		t.Fatalf("fail to init cuckoo transform: %v", err)
	}
	defer tracker.Reset()

	// 1. First response for example.com -> 1.2.3.4 (should be unique)
	dm := dnsutils.GetFakeDNSMessage()
	dm.DNS.Qname = "example.com"
	dm.DNS.DNSRRs.Answers = []dnsutils.DNSAnswer{
		{Rdatatype: "A", Rdata: "1.2.3.4"},
	}

	if res, _ := tracker.trackUniqueResponse(&dm); res != ReturnKeep {
		t.Errorf("1. cuckoo: initial response should be unique!")
	}

	// 2. Duplicate response -> should be dropped
	if res, _ := tracker.trackUniqueResponse(&dm); res != ReturnDrop {
		t.Errorf("2. cuckoo: duplicate response should NOT be unique!")
	}

	// 3. Same domain, new IP 5.6.7.8 -> should be unique!
	dmNewIP := dnsutils.GetFakeDNSMessage()
	dmNewIP.DNS.Qname = "example.com"
	dmNewIP.DNS.DNSRRs.Answers = []dnsutils.DNSAnswer{
		{Rdatatype: "A", Rdata: "5.6.7.8"},
	}

	if res, _ := tracker.trackUniqueResponse(&dmNewIP); res != ReturnKeep {
		t.Errorf("3. cuckoo: new IP for same domain should be unique!")
	}

	// 4. Same domain, new CNAME -> should be unique!
	dmCNAME := dnsutils.GetFakeDNSMessage()
	dmCNAME.DNS.Qname = "example.com"
	dmCNAME.DNS.DNSRRs.Answers = []dnsutils.DNSAnswer{
		{Rdatatype: "CNAME", Rdata: "target.com"},
	}

	if res, _ := tracker.trackUniqueResponse(&dmCNAME); res != ReturnKeep {
		t.Errorf("4. cuckoo: new CNAME for same domain should be unique!")
	}
}
