# How-to: Add a Transformer

This guide explains how to extend DNS-collector by creating a custom DNS transformer.

---

## 1. Add Configuration

Define your transformer configuration struct in `pkgconfig/transformers.go` (or `dnsutils/config.go`):

```golang
type ConfigTransformers struct {
    MyTransform struct {
        Enable bool `yaml:"enable"`
    } `yaml:"mytransform"`
}
```

Set its default values:

```golang
func (c *ConfigTransformers) SetDefault() {
    c.MyTransform.Enable = false
}
```

---

## 2. Implement the Transformer

Create the transformer implementation in `transformers/mytransform.go` and unit tests in `transformers/mytransform_test.go`:

```golang
package transformers

import (
	"github.com/dmachard/go-dnscollector/v2/dnsutils"
	"github.com/dmachard/go-dnscollector/v2/pkgconfig"
	"github.com/dmachard/go-logger"
)

type MyTransform struct {
	*GenericTransformer
}

func NewMyTransform(config *pkgconfig.ConfigTransformers, logger *logger.Logger, name string, instance int, nextWorkers []chan dnsutils.DNSMessage) *MyTransform {
	t := &MyTransform{GenericTransformer: NewTransformer(config, logger, "mytransform", name, instance, nextWorkers)}
	return t
}

func (t *MyTransform) ProcessMessage(dm *dnsutils.DNSMessage) (int, error) {
	// Your custom DNS manipulation or enrichment logic here
	return ReturnSuccess, nil
}
```

---

## 3. Register the Transformer

Declare and initialize the transformer in `transformers/transformers.go`:

```golang
if config.MyTransform.Enable {
    // initialize transformer instance
}
```

---

## 4. Documentation & Tests

1. Add unit tests in `transformers/mytransform_test.go`.
2. Document the new transformer options in `docs/transformers/` and update `README.md`.
