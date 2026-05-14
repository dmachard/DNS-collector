package transformers

import (
	"encoding/hex"
	"fmt"
	"reflect"

	"github.com/dmachard/go-dnscollector/dnsutils"
	"github.com/dmachard/go-dnscollector/pkgconfig"
	"github.com/dmachard/go-logger"
)

type ExtractTransform struct {
	GenericTransformer
}

func NewExtractTransform(config *pkgconfig.ConfigTransformers, logger *logger.Logger, name string, instance int, nextWorkers []chan dnsutils.DNSMessage) *ExtractTransform {
	t := &ExtractTransform{GenericTransformer: NewTransformer(config, logger, "extract", name, instance, nextWorkers)}
	return t
}

func (t *ExtractTransform) GetTransforms() ([]Subtransform, error) {
	subtransforms := []Subtransform{}
	if t.config.Extract.AddPayload {
		subtransforms = append(subtransforms, Subtransform{name: "extract:add-base64payload", processFunc: t.addBase64Payload})
	}
	if len(t.config.Extract.Base64Fields) > 0 {
		subtransforms = append(subtransforms, Subtransform{name: "extract:base64-fields", processFunc: t.addBase64Fields})
	}
	if len(t.config.Extract.HexFields) > 0 {
		subtransforms = append(subtransforms, Subtransform{name: "extract:hex-fields", processFunc: t.addHexFields})
	}
	return subtransforms, nil
}

func (t *ExtractTransform) addBase64Payload(dm *dnsutils.DNSMessage) (int, error) {
	if dm.Extracted == nil {
		dm.Extracted = &dnsutils.TransformExtracted{Base64Payload: []byte("-")}
	}

	dm.Extracted.Base64Payload = dm.DNS.Payload
	return ReturnKeep, nil
}

func (t *ExtractTransform) addBase64Fields(dm *dnsutils.DNSMessage) (int, error) {
	if dm.Extracted == nil {
		dm.Extracted = &dnsutils.TransformExtracted{}
	}
	if dm.Extracted.Base64Fields == nil {
		dm.Extracted.Base64Fields = make(map[string][]byte)
	}

	dmValue := reflect.ValueOf(dm).Elem()
	for _, field := range t.config.Extract.Base64Fields {
		if value, found := dnsutils.GetFieldByJSONTag(dmValue, field); found {
			switch value.Kind() {
			case reflect.String:
				dm.Extracted.Base64Fields[field] = []byte(value.String())
			case reflect.Int:
				dm.Extracted.Base64Fields[field] = []byte(fmt.Sprintf("%d", value.Int()))
			}
		}
	}
	return ReturnKeep, nil
}

func (t *ExtractTransform) addHexFields(dm *dnsutils.DNSMessage) (int, error) {
	if dm.Extracted == nil {
		dm.Extracted = &dnsutils.TransformExtracted{}
	}
	if dm.Extracted.HexFields == nil {
		dm.Extracted.HexFields = make(map[string]string)
	}

	dmValue := reflect.ValueOf(dm).Elem()
	for _, field := range t.config.Extract.HexFields {
		if value, found := dnsutils.GetFieldByJSONTag(dmValue, field); found {
			switch value.Kind() {
			case reflect.String:
				dm.Extracted.HexFields[field] = hex.EncodeToString([]byte(value.String()))
			case reflect.Int:
				dm.Extracted.HexFields[field] = hex.EncodeToString([]byte(fmt.Sprintf("%d", value.Int())))
			}
		}
	}
	return ReturnKeep, nil
}
