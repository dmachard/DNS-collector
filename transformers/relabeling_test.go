package transformers

import (
	"testing"

	"github.com/dmachard/go-dnscollector/dnsutils"
	"github.com/dmachard/go-dnscollector/pkgconfig"
	"github.com/dmachard/go-logger"
)

func TestRelabeling_CompileRegex(t *testing.T) {
	// enable feature
	config := pkgconfig.GetFakeConfigTransformers()
	config.Relabeling.Enable = true
	config.Relabeling.Rename = append(config.Relabeling.Rename, pkgconfig.RelabelingConfig{
		Regex:       "^dns.qname$",
		Replacement: "qname_test",
	})
	config.Relabeling.Remove = append(config.Relabeling.Remove, pkgconfig.RelabelingConfig{
		Regex: "^dns.qtype$",
	})

	// init the processor
	outChans := []chan dnsutils.DNSMessage{}
	relabeling := NewRelabelTransform(config, logger.New(false), "test", 0, outChans)
	relabeling.GetTransforms()

	if len(relabeling.RelabelingRules) != 2 {
		t.Errorf("invalid number of rules")
	}
}
