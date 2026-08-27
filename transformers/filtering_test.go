package transformers

import (
	"testing"

	"github.com/dmachard/go-dnscollector/v2/dnsutils"
	"github.com/dmachard/go-dnscollector/v2/pkg/config"
	"github.com/dmachard/go-logger"
)

const (
	testURL1 = "mail.google.com"
	testURL2 = "test.github.com"
)

func TestFilteringQR(t *testing.T) {
	// config
	cfg := config.GetFakeConfigTransformers()
	cfg.Filtering.Enable = true
	cfg.Filtering.LogQueries = false
	cfg.Filtering.LogReplies = false

	outChans := []chan *dnsutils.DNSMessageBatch{}

	// init subprocessor
	filtering := NewFilteringTransform(cfg, logger.New(false), "test", 0, outChans)

	// get transforms
	subtransforms, _ := filtering.GetTransforms()
	if len(subtransforms) != 2 {
		t.Errorf("invalid number of subtransforms enabled")
	}

	dm := dnsutils.GetFakeDNSMessage()
	if result, _ := filtering.dropQueryFilter(&dm); result != ReturnDrop {
		t.Errorf("dns query should be dropped")
	}

	dm.DNS.Type = dnsutils.DNSReply
	if result, _ := filtering.dropReplyFilter(&dm); result != ReturnDrop {
		t.Errorf("dns reply should be dropped")
	}
}

func TestFilteringByRcodeNOERROR(t *testing.T) {
	// config
	cfg := config.GetFakeConfigTransformers()
	cfg.Filtering.Enable = true
	cfg.Filtering.DropRcodes = []string{"NOERROR"}

	outChans := []chan *dnsutils.DNSMessageBatch{}

	// init subprocessor
	filtering := NewFilteringTransform(cfg, logger.New(false), "test", 0, outChans)

	// get transforms
	subtransforms, _ := filtering.GetTransforms()
	if len(subtransforms) != 1 {
		t.Errorf("invalid number of subtransforms enabled")
	}

	dm := dnsutils.GetFakeDNSMessage()
	if result, _ := filtering.dropRCodeFilter(&dm); result != ReturnDrop {
		t.Errorf("dns query should be dropped")
	}
}

func TestFilteringByRcodeEmpty(t *testing.T) {
	// config
	cfg := config.GetFakeConfigTransformers()
	cfg.Filtering.Enable = true
	cfg.Filtering.DropRcodes = []string{}

	outChans := []chan *dnsutils.DNSMessageBatch{}

	// init subprocessor
	filtering := NewFilteringTransform(cfg, logger.New(false), "test", 0, outChans)

	// get transforms
	subtransforms, _ := filtering.GetTransforms()
	if len(subtransforms) != 0 {
		t.Errorf("no subtransforms should be enabled")
	}
}

func TestFilteringByKeepQueryIp(t *testing.T) {
	// config
	cfg := config.GetFakeConfigTransformers()
	cfg.Filtering.Enable = true
	cfg.Filtering.KeepQueryIPFile = "../tests/testsdata/filtering_queryip_keep.txt"

	outChans := []chan *dnsutils.DNSMessageBatch{}

	// init subprocessor
	filtering := NewFilteringTransform(cfg, logger.New(false), "test", 0, outChans)

	// get transforms
	subtransforms, _ := filtering.GetTransforms()
	if len(subtransforms) != 1 {
		t.Errorf("invalid number of subtransforms enabled")
	}

	dm := dnsutils.GetFakeDNSMessage()
	dm.NetworkInfo.QueryIP = "192.168.0.1"
	if result, _ := filtering.keepQueryIPFilter(&dm); result != ReturnDrop {
		t.Errorf("dns query should be dropped!")
	}

	dm.NetworkInfo.QueryIP = "192.168.1.10"
	if result, _ := filtering.keepQueryIPFilter(&dm); result != ReturnKeep {
		t.Errorf("dns query should not be dropped!")
	}

	dm.NetworkInfo.QueryIP = "192.3.2.1" // kept by subnet
	if result, _ := filtering.keepQueryIPFilter(&dm); result != ReturnKeep {
		t.Errorf("dns query should not be dropped!")
	}

	// Test with binary buffer (lazy IP)
	dm = dnsutils.GetFakeDNSMessage()
	dm.NetworkInfo.SetQueryIPBytes([]byte{192, 168, 0, 1})
	if result, _ := filtering.keepQueryIPFilter(&dm); result != ReturnDrop {
		t.Errorf("lazy IP dns query should be dropped!")
	}

	dm.NetworkInfo.SetQueryIPBytes([]byte{192, 168, 1, 10})
	if result, _ := filtering.keepQueryIPFilter(&dm); result != ReturnKeep {
		t.Errorf("lazy IP dns query should not be dropped!")
	}
}

func TestFilteringByBothDropAndKeepQueryIp(t *testing.T) {
	// config
	cfg := config.GetFakeConfigTransformers()
	cfg.Filtering.Enable = true
	cfg.Filtering.DropQueryIPFile = "../tests/testsdata/filtering_queryip.txt"
	cfg.Filtering.KeepQueryIPFile = "../tests/testsdata/filtering_queryip_keep.txt"

	outChans := []chan *dnsutils.DNSMessageBatch{}

	// init subprocessor
	filtering := NewFilteringTransform(cfg, logger.New(false), "test", 0, outChans)

	// get transforms
	subtransforms, err := filtering.GetTransforms()
	if err != nil {
		t.Fatalf("failed to get transforms: %v", err)
	}
	if len(subtransforms) != 2 {
		t.Fatalf("expected 2 subtransforms, got %d", len(subtransforms))
	}

	// 1. IP in drop list -> dropQueryIPFilter must drop
	dmDrop := dnsutils.GetFakeDNSMessage()
	dmDrop.NetworkInfo.QueryIP = "192.168.1.15"
	if result, _ := filtering.dropQueryIPFilter(&dmDrop); result != ReturnDrop {
		t.Errorf("expected dropQueryIPFilter to drop 192.168.1.15, got %d", result)
	}

	// 2. IP in keep list -> keepQueryIPFilter must keep
	dmKeep := dnsutils.GetFakeDNSMessage()
	dmKeep.NetworkInfo.QueryIP = "192.0.2.1"
	if result, _ := filtering.keepQueryIPFilter(&dmKeep); result != ReturnKeep {
		t.Errorf("expected keepQueryIPFilter to keep 192.0.2.1, got %d", result)
	}

	// 3. IP not in keep list -> keepQueryIPFilter must drop
	dmNotKeep := dnsutils.GetFakeDNSMessage()
	dmNotKeep.NetworkInfo.QueryIP = "10.0.0.1"
	if result, _ := filtering.keepQueryIPFilter(&dmNotKeep); result != ReturnDrop {
		t.Errorf("expected keepQueryIPFilter to drop 10.0.0.1, got %d", result)
	}
}

func TestFilteringByDropQueryIp(t *testing.T) {
	// config
	cfg := config.GetFakeConfigTransformers()
	cfg.Filtering.Enable = true
	cfg.Filtering.DropQueryIPFile = "../tests/testsdata/filtering_queryip.txt"

	outChans := []chan *dnsutils.DNSMessageBatch{}

	// init subprocessor
	filtering := NewFilteringTransform(cfg, logger.New(false), "test", 0, outChans)

	// get transforms
	subtransforms, _ := filtering.GetTransforms()
	if len(subtransforms) != 1 {
		t.Errorf("invalid number of subtransforms enabled")
	}

	dm := dnsutils.GetFakeDNSMessage()
	dm.NetworkInfo.QueryIP = "192.168.0.1"
	if result, _ := filtering.dropQueryIPFilter(&dm); result != ReturnKeep {
		t.Errorf("dns query should not be dropped!")
	}

	dm.NetworkInfo.QueryIP = "192.168.1.15"
	if result, _ := filtering.dropQueryIPFilter(&dm); result != ReturnDrop {
		t.Errorf("dns query should be dropped!")
	}

	dm.NetworkInfo.QueryIP = "192.0.2.3" // dropped by subnet
	if result, _ := filtering.dropQueryIPFilter(&dm); result != ReturnDrop {
		t.Errorf("dns query should be dropped!")
	}

	// Test with binary buffer (lazy IP)
	dm = dnsutils.GetFakeDNSMessage()
	dm.NetworkInfo.SetQueryIPBytes([]byte{192, 168, 0, 1})
	if result, _ := filtering.dropQueryIPFilter(&dm); result != ReturnKeep {
		t.Errorf("lazy IP dns query should not be dropped!")
	}

	dm.NetworkInfo.SetQueryIPBytes([]byte{192, 168, 1, 15})
	if result, _ := filtering.dropQueryIPFilter(&dm); result != ReturnDrop {
		t.Errorf("lazy IP dns query should be dropped!")
	}
}

func TestFilteringByKeepRdataIp(t *testing.T) {
	// config
	cfg := config.GetFakeConfigTransformers()
	cfg.Filtering.Enable = true
	cfg.Filtering.KeepRdataFile = "../tests/testsdata/filtering_rdataip_keep.txt"

	outChans := []chan *dnsutils.DNSMessageBatch{}

	// init subprocessor
	filtering := NewFilteringTransform(cfg, logger.New(false), "test", 0, outChans)

	// get transforms
	subtransforms, _ := filtering.GetTransforms()
	if len(subtransforms) != 1 {
		t.Errorf("invalid number of subtransforms enabled")
	}

	dm := dnsutils.GetFakeDNSMessage()
	dm.DNS.DNSRRs.Answers = []dnsutils.DNSAnswer{
		{
			Rdatatype: "A",
			Rdata:     "192.168.0.1",
		},
	}
	if result, _ := filtering.keepRdataFilter(&dm); result != ReturnDrop {
		t.Errorf("dns query should be dropped!")
	}

	dm.DNS.DNSRRs.Answers = []dnsutils.DNSAnswer{
		{
			Rdatatype: "A",
			Rdata:     "192.168.1.10",
		},
	}
	if result, _ := filtering.keepRdataFilter(&dm); result != ReturnKeep {
		t.Errorf("dns query should not be dropped!")
	}

	dm.DNS.DNSRRs.Answers = []dnsutils.DNSAnswer{
		{
			Rdatatype: "A",
			Rdata:     "192.168.1.11", // included in subnet
		},
	}
	if result, _ := filtering.keepRdataFilter(&dm); result != ReturnKeep {
		t.Errorf("dns query should not be dropped!")
	}

	dm.DNS.DNSRRs.Answers = []dnsutils.DNSAnswer{
		{
			Rdatatype: "A",
			Rdata:     "192.0.2.3", // dropped by subnet
		},
	}
	if result, _ := filtering.keepRdataFilter(&dm); result != ReturnDrop {
		t.Errorf("dns query should be dropped!")
	}

	dm.DNS.DNSRRs.Answers = []dnsutils.DNSAnswer{
		{
			Rdatatype: "A",
			Rdata:     "192.0.2.1",
		},
	}
	if result, _ := filtering.keepRdataFilter(&dm); result != ReturnKeep {
		t.Errorf("dns query should not be dropped!")
	}

	dm.DNS.DNSRRs.Answers = []dnsutils.DNSAnswer{
		{
			Rdatatype: "AAAA",
			Rdata:     "2001:db8:85a3::8a2e:370:7334",
		},
	}
	if result, _ := filtering.keepRdataFilter(&dm); result != ReturnKeep {
		t.Errorf("dns query should not be dropped!")
	}

	dm.DNS.DNSRRs.Answers = []dnsutils.DNSAnswer{
		{
			Rdatatype: "AAAA",
			Rdata:     "2041::7334",
		},
	}
	if result, _ := filtering.keepRdataFilter(&dm); result != ReturnDrop {
		t.Errorf("dns query should be dropped!")
	}

	dm.DNS.DNSRRs.Answers = []dnsutils.DNSAnswer{
		{
			Rdatatype: "AAAA",
			Rdata:     "2001:0dbd:85a3::0001",
		},
	}
	if result, _ := filtering.keepRdataFilter(&dm); result != ReturnKeep {
		t.Errorf("dns query should not be dropped!")
	}
}

func TestFilteringByFqdn(t *testing.T) {
	// config
	cfg := config.GetFakeConfigTransformers()
	cfg.Filtering.Enable = true
	cfg.Filtering.DropFqdnFile = "../tests/testsdata/filtering_fqdn.txt"

	outChans := []chan *dnsutils.DNSMessageBatch{}

	// init subprocessor
	filtering := NewFilteringTransform(cfg, logger.New(false), "test", 0, outChans)

	// get transforms
	subtransforms, _ := filtering.GetTransforms()
	if len(subtransforms) != 1 {
		t.Errorf("invalid number of subtransforms enabled")
	}

	dm := dnsutils.GetFakeDNSMessage()
	dm.DNS.Qname = "www.microsoft.com"
	if result, _ := filtering.dropFqdnFilter(&dm); result != ReturnKeep {
		t.Errorf("dns query should not be dropped!")
	}

	dm.DNS.Qname = testURL1
	if result, _ := filtering.dropFqdnFilter(&dm); result != ReturnDrop {
		t.Errorf("dns query should be dropped!")
	}
}

func TestFilteringByDomainRegex(t *testing.T) {
	// config
	cfg := config.GetFakeConfigTransformers()
	cfg.Filtering.Enable = true
	cfg.Filtering.DropDomainFile = "../tests/testsdata/filtering_fqdn_regex.txt"

	outChans := []chan *dnsutils.DNSMessageBatch{}

	// init subprocessor
	filtering := NewFilteringTransform(cfg, logger.New(false), "test", 0, outChans)

	// get transforms
	subtransforms, _ := filtering.GetTransforms()
	if len(subtransforms) != 1 {
		t.Errorf("invalid number of subtransforms enabled")
	}

	dm := dnsutils.GetFakeDNSMessage()
	dm.DNS.Qname = testURL1
	if result, _ := filtering.dropDomainRegexFilter(&dm); result != ReturnDrop {
		t.Errorf("dns query should be dropped!")
	}

	dm.DNS.Qname = testURL2
	if result, _ := filtering.dropDomainRegexFilter(&dm); result != ReturnDrop {
		t.Errorf("dns query should be dropped!")
	}

	dm.DNS.Qname = "github.fr"
	if result, _ := filtering.dropDomainRegexFilter(&dm); result != ReturnKeep {
		t.Errorf("dns query should not be dropped!")
	}
}

func TestFilteringByKeepDomain(t *testing.T) {
	// config
	cfg := config.GetFakeConfigTransformers()

	outChans := []chan *dnsutils.DNSMessageBatch{}

	// file contains google.fr, test.github.com
	cfg.Filtering.Enable = true
	cfg.Filtering.KeepFqdnFile = "../tests/testsdata/filtering_keep_domains.txt"

	// init subprocessor
	filtering := NewFilteringTransform(cfg, logger.New(false), "test", 0, outChans)

	// get transforms
	subtransforms, _ := filtering.GetTransforms()
	if len(subtransforms) != 1 {
		t.Errorf("invalid number of subtransforms enabled")
	}

	dm := dnsutils.GetFakeDNSMessage()
	dm.DNS.Qname = testURL1
	if result, _ := filtering.keepFqdnFilter(&dm); result != ReturnDrop {
		t.Errorf("dns query should be dropped! Domain: %s", dm.DNS.Qname)
	}

	dm.DNS.Qname = "example.com"
	if result, _ := filtering.keepFqdnFilter(&dm); result != ReturnDrop {
		t.Errorf("dns query should be dropped! Domain: %s", dm.DNS.Qname)
	}

	dm.DNS.Qname = testURL2
	if result, _ := filtering.keepFqdnFilter(&dm); result != ReturnKeep {
		t.Errorf("dns query should not be dropped!")
	}

	dm.DNS.Qname = "google.fr"
	if result, _ := filtering.keepFqdnFilter(&dm); result != ReturnKeep {
		t.Errorf("dns query should not be dropped!")
	}
}

func TestFilteringByKeepDomainRegex(t *testing.T) {
	// config
	cfg := config.GetFakeConfigTransformers()

	outChans := []chan *dnsutils.DNSMessageBatch{}

	/* file contains:
	(mail|sheets).google.com$
	test.github.com$
	.+.google.com$
	*/
	cfg.Filtering.Enable = true
	cfg.Filtering.KeepDomainFile = "../tests/testsdata/filtering_keep_domains_regex.txt"

	// init subprocessor
	filtering := NewFilteringTransform(cfg, logger.New(false), "test", 0, outChans)

	// get transforms
	subtransforms, _ := filtering.GetTransforms()
	if len(subtransforms) != 1 {
		t.Errorf("invalid number of subtransforms enabled")
	}

	dm := dnsutils.GetFakeDNSMessage()
	dm.DNS.Qname = testURL1
	if result, _ := filtering.keepDomainRegexFilter(&dm); result != ReturnKeep {
		t.Errorf("dns query should not be dropped!")
	}

	dm.DNS.Qname = "test.google.com.ru"
	if result, _ := filtering.keepDomainRegexFilter(&dm); result != ReturnDrop {

		// If this passes then these are not terminated.
		t.Errorf("dns query should be dropped!")
	}

	dm.DNS.Qname = testURL2
	if result, _ := filtering.keepDomainRegexFilter(&dm); result != ReturnKeep {
		t.Errorf("dns query should not be dropped!")
	}

	dm.DNS.Qname = "test.github.com.malware.ru"
	if result, _ := filtering.keepDomainRegexFilter(&dm); result != ReturnDrop {
		t.Errorf("dns query should be dropped!")
	}
}

func TestFilteringMultipleFilters(t *testing.T) {
	// config
	cfg := config.GetFakeConfigTransformers()
	cfg.Filtering.Enable = true
	cfg.Filtering.DropDomainFile = "../tests/testsdata/filtering_fqdn_regex.txt"
	cfg.Filtering.DropQueryIPFile = "../tests/testsdata/filtering_queryip.txt"

	outChans := []chan *dnsutils.DNSMessageBatch{}

	// init subprocessor
	filtering := NewFilteringTransform(cfg, logger.New(false), "test", 0, outChans)
	subtransforms, _ := filtering.GetTransforms()

	if len(subtransforms) != 2 {
		t.Errorf("invalid number of subtransforms enabled")
	}
}

func TestFilteringDownsampleFilter(t *testing.T) {
	// config
	cfg := config.GetFakeConfigTransformers()
	cfg.Filtering.Enable = true
	cfg.Filtering.Downsample = 3

	outChans := []chan *dnsutils.DNSMessageBatch{}

	// init processor
	filtering := NewFilteringTransform(cfg, logger.New(false), "test", 0, outChans)

	// get transform function
	subtransforms, _ := filtering.GetTransforms()
	var downsampleFunc func(dm *dnsutils.DNSMessage) (int, error)
	for _, tr := range subtransforms {
		if tr.name == "filtering:downsampling" {
			downsampleFunc = tr.processFunc
		}
	}

	if downsampleFunc == nil {
		t.Fatal("downsample transform not found")
	}

	// simulate N messages
	var kept, dropped int
	N := cfg.Filtering.Downsample

	for i := 1; i <= 10; i++ {
		dm := dnsutils.GetFakeDNSMessage()

		result, _ := downsampleFunc(&dm)

		if i%N == 0 {
			if result != ReturnKeep {
				t.Errorf("message %d should be kept (expected ReturnKeep)", i)
			} else {
				kept++
			}
		} else {
			if result != ReturnDrop {
				t.Errorf("message %d should be dropped (expected ReturnDrop)", i)
			} else {
				dropped++
			}
		}
	}

	if kept != 10/N {
		t.Errorf("expected %d messages to be kept, got %d", 10/N, kept)
	}
}
