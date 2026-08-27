package transformers

import (
	"fmt"

	"github.com/dmachard/go-dnscollector/v2/dnsutils"
	"github.com/dmachard/go-dnscollector/v2/pkg/config"
	"github.com/dmachard/go-logger"
)

var (
	ReturnError = 0
	ReturnKeep  = 1
	ReturnDrop  = 2
)

type Subtransform struct {
	name        string
	processFunc func(dm *dnsutils.DNSMessage) (int, error)
}

type Transformation interface {
	GetTransforms() ([]Subtransform, error)
	ReloadConfig(cfg *config.ConfigTransformers)
	Reset()
}

type GenericTransformer struct {
	config            *config.ConfigTransformers
	logger            *logger.Logger
	name              string
	nextWorkers       []chan *dnsutils.DNSMessageBatch
	LogInfo, LogError func(msg string, v ...interface{})
}

func NewTransformer(cfg *config.ConfigTransformers, logger *logger.Logger, name string, workerName string, instance int, nextWorkers []chan *dnsutils.DNSMessageBatch) GenericTransformer {
	t := GenericTransformer{config: cfg, logger: logger, nextWorkers: nextWorkers, name: name}

	t.LogInfo = func(msg string, v ...interface{}) {
		log := fmt.Sprintf("worker - [%s] (conn #%d) [transform=%s] - ", workerName, instance, name)
		logger.Info(log+msg, v...)
	}

	t.LogError = func(msg string, v ...interface{}) {
		log := fmt.Sprintf("worker - [%s] (conn #%d) [transform=%s] - ", workerName, instance, name)
		logger.Error(log+msg, v...)
	}
	return t
}

func (t *GenericTransformer) ReloadConfig(cfg *config.ConfigTransformers) {
	t.config = cfg
}

func (t *GenericTransformer) Reset() {}

type TransformEntry struct {
	Transformation
}

type Transforms struct {
	config   *config.ConfigTransformers
	logger   *logger.Logger
	name     string
	instance int

	availableTransforms     []TransformEntry
	activeTransforms        []TransformEntry
	activeProcessTransforms []func(dm *dnsutils.DNSMessage) (int, error)
}

func NewTransforms(cfg *config.ConfigTransformers, logger *logger.Logger, name string, nextWorkers []chan *dnsutils.DNSMessageBatch, instance int) Transforms {

	d := Transforms{config: cfg, logger: logger, name: name, instance: instance}

	// order definition
	pipelineOrder := cfg.Order
	if len(pipelineOrder) == 0 {
		pipelineOrder = config.DefaultTransformersOrder
	}

	for _, nameTransform := range pipelineOrder {
		switch nameTransform {
		case "extract":
			d.availableTransforms = append(d.availableTransforms, TransformEntry{NewExtractTransform(cfg, logger, name, instance, nextWorkers)})
		case "normalize":
			d.availableTransforms = append(d.availableTransforms, TransformEntry{NewNormalizeTransform(cfg, logger, name, instance, nextWorkers)})
		case "filtering":
			d.availableTransforms = append(d.availableTransforms, TransformEntry{NewFilteringTransform(cfg, logger, name, instance, nextWorkers)})
		case "geoip":
			d.availableTransforms = append(d.availableTransforms, TransformEntry{NewDNSGeoIPTransform(cfg, logger, name, instance, nextWorkers)})
		case "bgp":
			d.availableTransforms = append(d.availableTransforms, TransformEntry{NewDNSBGPTransform(cfg, logger, name, instance, nextWorkers)})
		case "atags":
			d.availableTransforms = append(d.availableTransforms, TransformEntry{NewATagsTransform(cfg, logger, name, instance, nextWorkers)})
		case "suspicious":
			d.availableTransforms = append(d.availableTransforms, TransformEntry{NewSuspiciousTransform(cfg, logger, name, instance, nextWorkers)})
		case "user-privacy":
			d.availableTransforms = append(d.availableTransforms, TransformEntry{NewUserPrivacyTransform(cfg, logger, name, instance, nextWorkers)})
		case "machine-learning":
			d.availableTransforms = append(d.availableTransforms, TransformEntry{NewMachineLearningTransform(cfg, logger, name, instance, nextWorkers)})
		case "rest":
			d.availableTransforms = append(d.availableTransforms, TransformEntry{NewRestTransform(cfg, logger, name, instance, nextWorkers)})
		case "relabeling":
			d.availableTransforms = append(d.availableTransforms, TransformEntry{NewRelabelTransform(cfg, logger, name, instance, nextWorkers)})
		case "latency":
			d.availableTransforms = append(d.availableTransforms, TransformEntry{NewLatencyTransform(cfg, logger, name, instance, nextWorkers)})
		case "rewrite":
			d.availableTransforms = append(d.availableTransforms, TransformEntry{NewRewriteTransform(cfg, logger, name, instance, nextWorkers)})
		case "new-domain-tracker":
			d.availableTransforms = append(d.availableTransforms, TransformEntry{NewNewDomainTrackerTransform(cfg, logger, name, instance, nextWorkers)})
		case "unique-response-tracker":
			d.availableTransforms = append(d.availableTransforms, TransformEntry{NewUniqueResponseTrackerTransform(cfg, logger, name, instance, nextWorkers)})
		case "reducer":
			d.availableTransforms = append(d.availableTransforms, TransformEntry{NewReducerTransform(cfg, logger, name, instance, nextWorkers)})
		case "reordering":
			d.availableTransforms = append(d.availableTransforms, TransformEntry{NewReorderingTransform(cfg, logger, name, instance, nextWorkers)})
		default:
			d.LogError("unknown transformer name in order list: %s", nameTransform)
		}
	}

	d.Prepare()
	return d
}

func (p *Transforms) ReloadConfig(cfg *config.ConfigTransformers) {
	p.config = cfg

	for _, transform := range p.availableTransforms {
		transform.ReloadConfig(cfg)
	}

	p.Prepare()
}

func (p *Transforms) Prepare() error {
	// clean the slice
	p.activeProcessTransforms = p.activeProcessTransforms[:0]
	p.activeTransforms = p.activeTransforms[:0]
	transformsList := []string{}

	for _, transform := range p.availableTransforms {
		subtransforms, err := transform.GetTransforms()
		if err != nil {
			p.LogError("error on init subtransforms: %v", err)
			continue
		}
		if len(subtransforms) > 0 {
			p.activeTransforms = append(p.activeTransforms, transform)
		}
		for _, subtransform := range subtransforms {
			p.activeProcessTransforms = append(p.activeProcessTransforms, subtransform.processFunc)

			transformsList = append(transformsList, subtransform.name)
		}
	}

	if len(transformsList) > 0 {
		p.LogInfo("transformers applied: %v", transformsList)
	}
	return nil
}

func (p *Transforms) Reset() {
	for _, transform := range p.activeTransforms {
		transform.Reset()
	}
}

func (p *Transforms) LogInfo(msg string, v ...interface{}) {
	connlog := fmt.Sprintf("(conn #%d) ", p.instance)
	p.logger.Info(config.PrefixLogWorker+"["+p.name+"] "+connlog+msg, v...)
}

func (p *Transforms) LogError(msg string, v ...interface{}) {
	p.logger.Error(config.PrefixLogWorker+"["+p.name+"] "+msg, v...)
}

func (p *Transforms) ProcessMessage(dm *dnsutils.DNSMessage) (int, error) {
	if len(p.activeProcessTransforms) > 0 {
		dm.NetworkInfo.GetQueryIP()
		dm.NetworkInfo.GetResponseIP()
	}
	for _, transform := range p.activeProcessTransforms {
		if result, err := transform(dm); err != nil {
			return ReturnKeep, fmt.Errorf("error on transform processing: %v", err.Error())
		} else if result == ReturnDrop {
			return ReturnDrop, nil
		}
	}
	return ReturnKeep, nil
}
