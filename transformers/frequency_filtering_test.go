package transformers

import (
	"testing"
	"time"

	"github.com/dmachard/go-dnscollector/v3/dnsutils"
	"github.com/dmachard/go-dnscollector/v3/pkg/config"
	"github.com/dmachard/go-logger"
)

func TestFrequencyFiltering_ThresholdAndTagOnly(t *testing.T) {
	cfg := &config.TransformFrequencyFiltering{
		Enable:        true,
		TrackBy:       "qname",
		Threshold:     3,
		WindowSeconds: 60,
		SampleRate:    0, // drop 100% when heavy
		TagOnly:       true,
		Capacity:      1000,
	}

	log := logger.New(true)
	tf := NewFrequencyFilteringTransform(cfg, log, "test", 0, nil)
	defer tf.Stop()

	subtransforms, err := tf.GetTransforms()
	if err != nil {
		t.Fatalf("failed to get subtransforms: %v", err)
	}
	if len(subtransforms) != 1 {
		t.Fatalf("expected 1 subtransform, got %d", len(subtransforms))
	}
	filter := subtransforms[0].processFunc

	dm := dnsutils.GetFakeDNSMessage()
	dm.DNS.Qname = "example.com"

	// 1st request -> Count 1, not heavy
	res, _ := filter(&dm)
	if res != ReturnKeep {
		t.Fatalf("expected ReturnKeep on 1st request, got %d", res)
	}
	if dm.Frequency == nil || dm.Frequency.Count != 1 || dm.Frequency.IsHeavyHitter {
		t.Fatalf("unexpected frequency payload on 1st request: %+v", dm.Frequency)
	}

	// 2nd and 3rd requests
	filter(&dm)
	filter(&dm)

	// 4th request -> Count 4 > Threshold(3) -> Heavy Hitter, but TagOnly is true -> ReturnKeep
	res, _ = filter(&dm)
	if res != ReturnKeep {
		t.Fatalf("expected ReturnKeep for TagOnly, got %d", res)
	}
	if dm.Frequency == nil || dm.Frequency.Count != 4 || !dm.Frequency.IsHeavyHitter {
		t.Fatalf("expected IsHeavyHitter true on 4th request, got %+v", dm.Frequency)
	}
}

func TestFrequencyFiltering_DropMode(t *testing.T) {
	cfg := &config.TransformFrequencyFiltering{
		Enable:        true,
		TrackBy:       "qname",
		Threshold:     2,
		WindowSeconds: 60,
		SampleRate:    0, // Drop all heavy hitters
		TagOnly:       false,
		Capacity:      1000,
	}

	log := logger.New(true)
	tf := NewFrequencyFilteringTransform(cfg, log, "test", 0, nil)
	defer tf.Stop()

	subtransforms, _ := tf.GetTransforms()
	filter := subtransforms[0].processFunc

	dm := dnsutils.GetFakeDNSMessage()
	dm.DNS.Qname = "flood.com"

	// 1st request -> keep
	res, _ := filter(&dm)
	if res != ReturnKeep {
		t.Fatalf("expected ReturnKeep, got %d", res)
	}

	// 2nd request -> keep (count = 2 <= threshold 2)
	res, _ = filter(&dm)
	if res != ReturnKeep {
		t.Fatalf("expected ReturnKeep, got %d", res)
	}

	// 3rd request -> count = 3 > threshold 2 -> Drop!
	res, _ = filter(&dm)
	if res != ReturnDrop {
		t.Fatalf("expected ReturnDrop for heavy hitter, got %d", res)
	}
}

func TestFrequencyFiltering_SampleRate(t *testing.T) {
	cfg := &config.TransformFrequencyFiltering{
		Enable:        true,
		TrackBy:       "qname",
		Threshold:     1,
		WindowSeconds: 60,
		SampleRate:    2, // sample 1 in 2
		TagOnly:       false,
		Capacity:      1000,
	}

	log := logger.New(true)
	tf := NewFrequencyFilteringTransform(cfg, log, "test", 0, nil)
	defer tf.Stop()

	subtransforms, _ := tf.GetTransforms()
	filter := subtransforms[0].processFunc

	dm := dnsutils.GetFakeDNSMessage()
	dm.DNS.Qname = "sample.com"

	// 1st request -> count 1 <= threshold 1 -> Keep
	filter(&dm)

	// Heavy hitter requests: SampleRate = 2 -> 1 keep, 1 drop, 1 keep, 1 drop...
	res1, _ := filter(&dm) // sampleCounter=1 -> 1%2!=0 -> Drop
	res2, _ := filter(&dm) // sampleCounter=2 -> 2%2==0 -> Keep
	res3, _ := filter(&dm) // sampleCounter=3 -> 3%2!=0 -> Drop
	res4, _ := filter(&dm) // sampleCounter=4 -> 4%2==0 -> Keep

	if res1 != ReturnDrop || res2 != ReturnKeep || res3 != ReturnDrop || res4 != ReturnKeep {
		t.Fatalf("unexpected sampling pattern: [%d, %d, %d, %d]", res1, res2, res3, res4)
	}
}

func TestFrequencyFiltering_TrackByDomainAndIP(t *testing.T) {
	// Domain track
	cfgDomain := &config.TransformFrequencyFiltering{
		Enable:    true,
		TrackBy:   "domain",
		Threshold: 1,
		Capacity:  1000,
	}
	log := logger.New(true)
	tfDomain := NewFrequencyFilteringTransform(cfgDomain, log, "test", 0, nil)
	defer tfDomain.Stop()

	subtransformsDomain, _ := tfDomain.GetTransforms()
	filterDomain := subtransformsDomain[0].processFunc

	dm := dnsutils.GetFakeDNSMessage()
	dm.PublicSuffix = &dnsutils.TransformPublicSuffix{
		QnameEffectiveTLDPlusOne: "target.com",
	}
	dm.DNS.Qname = "sub1.target.com"
	filterDomain(&dm)

	dm.DNS.Qname = "sub2.target.com"
	filterDomain(&dm)

	if dm.Frequency.Count != 2 || dm.Frequency.TrackedKey != "target.com" {
		t.Fatalf("expected domain tracking for target.com, got count=%d, key=%s", dm.Frequency.Count, dm.Frequency.TrackedKey)
	}

	// IP track
	cfgIP := &config.TransformFrequencyFiltering{
		Enable:    true,
		TrackBy:   "query-ip",
		Threshold: 1,
		Capacity:  1000,
	}
	tfIP := NewFrequencyFilteringTransform(cfgIP, log, "test", 0, nil)
	defer tfIP.Stop()

	subtransformsIP, _ := tfIP.GetTransforms()
	filterIP := subtransformsIP[0].processFunc

	dmIP := dnsutils.GetFakeDNSMessage()
	dmIP.NetworkInfo.QueryIP = "192.0.2.1"
	filterIP(&dmIP)

	if dmIP.Frequency.TrackedKey != "192.0.2.1" || dmIP.Frequency.Count != 1 {
		t.Fatalf("expected IP tracking for 192.0.2.1, got %+v", dmIP.Frequency)
	}
}

func TestFrequencyFiltering_Decay(t *testing.T) {
	cfg := &config.TransformFrequencyFiltering{
		Enable:        true,
		TrackBy:       "qname",
		Threshold:     10,
		WindowSeconds: 1, // 1 second decay
		Capacity:      1000,
	}
	log := logger.New(true)
	tf := NewFrequencyFilteringTransform(cfg, log, "test", 0, nil)
	defer tf.Stop()

	subtransforms, _ := tf.GetTransforms()
	filter := subtransforms[0].processFunc

	dm := dnsutils.GetFakeDNSMessage()
	dm.DNS.Qname = "decay.com"

	for i := 0; i < 4; i++ {
		filter(&dm)
	}
	if dm.Frequency.Count != 4 {
		t.Fatalf("expected count 4, got %d", dm.Frequency.Count)
	}

	// Wait for decay ticker to trigger
	time.Sleep(1200 * time.Millisecond)

	filter(&dm) // count was 4 -> decayed to 2 -> +1 = 3
	if dm.Frequency.Count != 3 {
		t.Fatalf("expected count 3 after decay + 1 increment, got %d", dm.Frequency.Count)
	}
}
