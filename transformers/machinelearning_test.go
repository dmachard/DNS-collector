package transformers

import (
	"testing"

	"github.com/dmachard/go-dnscollector/v3/dnsutils"
	"github.com/dmachard/go-dnscollector/v3/pkg/config"
	"github.com/dmachard/go-logger"
)

func TestML_AddFeatures(t *testing.T) {
	// enable feature
	cfg := config.GetFakeConfigTransformers()
	cfg.MachineLearning.Enable = true

	// init the processor
	outChans := []chan *dnsutils.DNSMessageBatch{}
	ml := NewMachineLearningTransform(cfg, logger.New(false), "test", 0, outChans)

	dm := dnsutils.GetFakeDNSMessage()

	// init transforms and check
	ml.GetTransforms()
	ml.addFeatures(&dm)

	if dm.MachineLearning.Labels != 2 {
		t.Errorf("incorrect feature label value in DNSMessage: %d", dm.MachineLearning.Labels)
	}
}
