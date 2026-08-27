package transformers

import (
	"github.com/dmachard/go-dnscollector/v3/dnsutils"
	"github.com/dmachard/go-dnscollector/v3/pkg/config"
	"github.com/dmachard/go-logger"
)

type ATagsTransform struct {
	GenericTransformer
	config *config.TransformATags
}

func NewATagsTransform(cfg *config.TransformATags, logger *logger.Logger, name string, instance int, nextWorkers []chan *dnsutils.DNSMessageBatch) *ATagsTransform {
	t := &ATagsTransform{
		GenericTransformer: NewTransformer(logger, "atags", name, instance, nextWorkers),
		config:             cfg,
	}
	return t
}

func (t *ATagsTransform) GetTransforms() ([]Subtransform, error) {
	subtransforms := []Subtransform{}
	if len(t.config.AddTags) > 0 {
		subtransforms = append(subtransforms, Subtransform{name: "atags:add", processFunc: t.addTags})
	}
	return subtransforms, nil
}

func (t *ATagsTransform) addTags(dm *dnsutils.DNSMessage) (int, error) {
	if dm.ATags == nil {
		dm.ATags = &dnsutils.TransformATags{Tags: []string{}}
	}

	dm.ATags.Tags = append(dm.ATags.Tags, t.config.AddTags...)
	return ReturnKeep, nil
}
