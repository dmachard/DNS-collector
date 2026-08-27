package transformers

import (
	"regexp"

	"github.com/dmachard/go-dnscollector/v3/dnsutils"
	"github.com/dmachard/go-dnscollector/v3/pkg/config"
	"github.com/dmachard/go-logger"
)

type RelabelTransform struct {
	GenericTransformer
	config          *config.TransformRelabeling
	RelabelingRules []dnsutils.RelabelingRule
}

func NewRelabelTransform(cfg *config.TransformRelabeling, logger *logger.Logger, name string, instance int, nextWorkers []chan *dnsutils.DNSMessageBatch) *RelabelTransform {
	t := &RelabelTransform{config: cfg, GenericTransformer: NewTransformer(logger, "relabeling", name, instance, nextWorkers)}
	return t
}

func (t *RelabelTransform) GetTransforms() ([]Subtransform, error) {
	subtransforms := []Subtransform{}
	if len(t.config.Rename) > 0 || len(t.config.Remove) > 0 {
		actions := t.Precompile()
		subtransforms = append(subtransforms, Subtransform{name: "relabeling:" + actions, processFunc: t.AddRules})
	}
	return subtransforms, nil
}

// Pre-compile regular expressions
func (t *RelabelTransform) Precompile() string {
	actionRename := false
	actionRemove := false
	for _, label := range t.config.Rename {
		t.RelabelingRules = append(t.RelabelingRules, dnsutils.RelabelingRule{
			Regex:       regexp.MustCompile(label.Regex),
			Replacement: label.Replacement,
			Action:      "rename",
		})
		actionRename = true
	}
	for _, label := range t.config.Remove {
		t.RelabelingRules = append(t.RelabelingRules, dnsutils.RelabelingRule{
			Regex:       regexp.MustCompile(label.Regex),
			Replacement: label.Replacement,
			Action:      "drop",
		})
		actionRemove = true
	}

	if actionRename && actionRemove {
		return "rename+remove"
	}
	if actionRename && !actionRemove {
		return "rename"
	}
	if !actionRename && actionRemove {
		return "remove"
	}
	return "error"
}

func (t *RelabelTransform) AddRules(dm *dnsutils.DNSMessage) (int, error) {
	if dm.Relabeling == nil {
		dm.Relabeling = &dnsutils.TransformRelabeling{Rules: t.RelabelingRules}
	}
	return ReturnKeep, nil
}
