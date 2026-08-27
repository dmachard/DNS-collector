package transformers

import (
	"github.com/dmachard/go-dnscollector/v3/dnsutils"
	"github.com/dmachard/go-dnscollector/v3/pkg/config"
	"github.com/dmachard/go-logger"
)

type ATagsTransform struct {
	GenericTransformer
}

func NewATagsTransform(cfg *config.ConfigTransformers, logger *logger.Logger, name string, instance int, nextWorkers []chan *dnsutils.DNSMessageBatch) *ATagsTransform {
	t := &ATagsTransform{GenericTransformer: NewTransformer(cfg, logger, "atags", name, instance, nextWorkers)}
	return t
}

func (t *ATagsTransform) GetTransforms() ([]Subtransform, error) {
	subtransforms := []Subtransform{}
	if len(t.config.ATags.AddTags) > 0 {
		subtransforms = append(subtransforms, Subtransform{name: "atags:add", processFunc: t.addTags})
	}
	return subtransforms, nil
}

func (t *ATagsTransform) addTags(dm *dnsutils.DNSMessage) (int, error) {
	if dm.ATags == nil {
		dm.ATags = &dnsutils.TransformATags{Tags: []string{}}
	}

	dm.ATags.Tags = append(dm.ATags.Tags, t.config.ATags.AddTags...)
	return ReturnKeep, nil
}
