package transformers

import (
	"testing"

	"github.com/dmachard/go-dnscollector/v3/dnsutils"
	"github.com/dmachard/go-dnscollector/v3/pkg/config"
	"github.com/dmachard/go-logger"
)

func TestRelabeling_CompileRegex(t *testing.T) {
	// enable feature
	cfg := config.GetFakeConfigTransformers()
	cfg.Relabeling.Enable = true
	cfg.Relabeling.Rename = append(cfg.Relabeling.Rename, config.RelabelingConfig{
		Regex:       "^dns.qname$",
		Replacement: "qname_test",
	})
	cfg.Relabeling.Remove = append(cfg.Relabeling.Remove, config.RelabelingConfig{
		Regex: "^dns.qtype$",
	})

	// init the processor
	outChans := []chan *dnsutils.DNSMessageBatch{}
	relabeling := NewRelabelTransform(&cfg.Relabeling, logger.New(false), "test", 0, outChans)
	relabeling.GetTransforms()

	if len(relabeling.RelabelingRules) != 2 {
		t.Errorf("invalid number of rules")
	}
}
