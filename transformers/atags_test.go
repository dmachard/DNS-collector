package transformers

import (
	"testing"

	"github.com/dmachard/go-dnscollector/v3/dnsutils"
	"github.com/dmachard/go-dnscollector/v3/pkg/config"
	"github.com/dmachard/go-logger"
)

func TestATags_AddTag(t *testing.T) {
	// enable feature
	cfg := &config.TransformATags{
		Enable:  true,
		AddTags: []string{"tag1", "tag2"},
	}

	// init the processor
	outChans := []chan *dnsutils.DNSMessageBatch{}
	atags := NewATagsTransform(cfg, logger.New(false), "test", 0, outChans)

	// add tags
	dm := dnsutils.GetFakeDNSMessage()
	atags.addTags(&dm)

	// check results
	if dm.ATags == nil {
		t.Errorf("DNSMessage.Atags should be not nil")
	}
	if len(dm.ATags.Tags) != 2 {
		t.Errorf("incorrect number of tag in DNSMessage")
	}
}
