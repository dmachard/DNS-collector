package transformers

import (
	"encoding/hex"
	"reflect"
	"strconv"

	"github.com/dmachard/go-dnscollector/v2/dnsutils"
	"github.com/dmachard/go-dnscollector/v2/pkgconfig"
	"github.com/dmachard/go-logger"
)

type ExtractorFunc func(dm *dnsutils.DNSMessage) (interface{}, bool)

type ExtractTransform struct {
	GenericTransformer
	base64Extractors []ExtractorFunc
	hexExtractors    []ExtractorFunc
}

func NewExtractTransform(config *pkgconfig.ConfigTransformers, logger *logger.Logger, name string, instance int, nextWorkers []chan *dnsutils.DNSMessageBatch) *ExtractTransform {
	t := &ExtractTransform{GenericTransformer: NewTransformer(config, logger, "extract", name, instance, nextWorkers)}
	t.initExtractors()
	return t
}

func (t *ExtractTransform) ReloadConfig(config *pkgconfig.ConfigTransformers) {
	t.GenericTransformer.ReloadConfig(config)
	t.initExtractors()
}

func (t *ExtractTransform) initExtractors() {
	t.base64Extractors = make([]ExtractorFunc, len(t.config.Extract.Base64Fields))
	for i, field := range t.config.Extract.Base64Fields {
		t.base64Extractors[i] = getExtractor(field)
	}

	t.hexExtractors = make([]ExtractorFunc, len(t.config.Extract.HexFields))
	for i, field := range t.config.Extract.HexFields {
		t.hexExtractors[i] = getExtractor(field)
	}
}

func getExtractor(tag string) ExtractorFunc {
	switch tag {
	case "network.query-ip":
		return func(dm *dnsutils.DNSMessage) (interface{}, bool) { return dm.NetworkInfo.GetQueryIP(), true }
	case "network.response-ip":
		return func(dm *dnsutils.DNSMessage) (interface{}, bool) { return dm.NetworkInfo.GetResponseIP(), true }
	case "dns.qname":
		return func(dm *dnsutils.DNSMessage) (interface{}, bool) { return dm.DNS.Qname, true }
	case "dns.qtype":
		return func(dm *dnsutils.DNSMessage) (interface{}, bool) { return dm.DNS.Qtype, true }
	case "dns.length":
		return func(dm *dnsutils.DNSMessage) (interface{}, bool) { return dm.DNS.Length, true }
	case "dns.id":
		return func(dm *dnsutils.DNSMessage) (interface{}, bool) { return dm.DNS.ID, true }
	case "dns.opcode":
		return func(dm *dnsutils.DNSMessage) (interface{}, bool) { return dm.DNS.Opcode, true }
	case "dns.rcode":
		return func(dm *dnsutils.DNSMessage) (interface{}, bool) { return dm.DNS.Rcode, true }
	case "dns.qclass":
		return func(dm *dnsutils.DNSMessage) (interface{}, bool) { return dm.DNS.Qclass, true }
	case "network.family":
		return func(dm *dnsutils.DNSMessage) (interface{}, bool) { return dm.NetworkInfo.Family, true }
	case "network.protocol":
		return func(dm *dnsutils.DNSMessage) (interface{}, bool) { return dm.NetworkInfo.Protocol, true }
	case "network.query-port":
		return func(dm *dnsutils.DNSMessage) (interface{}, bool) { return dm.NetworkInfo.QueryPort, true }
	case "network.response-port":
		return func(dm *dnsutils.DNSMessage) (interface{}, bool) { return dm.NetworkInfo.ResponsePort, true }
	}

	// Fallback to reflection if not standard
	return func(dm *dnsutils.DNSMessage) (interface{}, bool) {
		dmValue := reflect.ValueOf(dm).Elem()
		if value, found := dnsutils.GetFieldByJSONTag(dmValue, tag); found {
			return value.Interface(), true
		}
		return nil, false
	}
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
		dm.Extracted.Base64Fields = make(map[string]interface{})
	}

	for i, field := range t.config.Extract.Base64Fields {
		extractor := t.base64Extractors[i]
		if val, found := extractor(dm); found {
			switch v := val.(type) {
			case string:
				dm.Extracted.Base64Fields[field] = []byte(v)
			case int:
				dm.Extracted.Base64Fields[field] = []byte(strconv.Itoa(v))
			case []string:
				encodedSlice := make([][]byte, len(v))
				for idx, s := range v {
					encodedSlice[idx] = []byte(s)
				}
				dm.Extracted.Base64Fields[field] = encodedSlice
			case []int:
				encodedSlice := make([][]byte, len(v))
				for idx, s := range v {
					encodedSlice[idx] = []byte(strconv.Itoa(s))
				}
				dm.Extracted.Base64Fields[field] = encodedSlice
			default:
				value := reflect.ValueOf(val)
				switch value.Kind() {
				case reflect.Slice, reflect.Array:
					var encodedSlice [][]byte
					for i := 0; i < value.Len(); i++ {
						elem := value.Index(i)
						if elem.Kind() == reflect.Interface {
							elem = elem.Elem()
						}
						switch elem.Kind() {
						case reflect.String:
							encodedSlice = append(encodedSlice, []byte(elem.String()))
						case reflect.Int:
							encodedSlice = append(encodedSlice, []byte(strconv.Itoa(int(elem.Int()))))
						}
					}
					dm.Extracted.Base64Fields[field] = encodedSlice
				}
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
		dm.Extracted.HexFields = make(map[string]interface{})
	}

	for i, field := range t.config.Extract.HexFields {
		extractor := t.hexExtractors[i]
		if val, found := extractor(dm); found {
			switch v := val.(type) {
			case string:
				dm.Extracted.HexFields[field] = hex.EncodeToString([]byte(v))
			case int:
				dm.Extracted.HexFields[field] = hex.EncodeToString([]byte(strconv.Itoa(v)))
			case []string:
				encodedSlice := make([]string, len(v))
				for idx, s := range v {
					encodedSlice[idx] = hex.EncodeToString([]byte(s))
				}
				dm.Extracted.HexFields[field] = encodedSlice
			case []int:
				encodedSlice := make([]string, len(v))
				for idx, s := range v {
					encodedSlice[idx] = hex.EncodeToString([]byte(strconv.Itoa(s)))
				}
				dm.Extracted.HexFields[field] = encodedSlice
			default:
				value := reflect.ValueOf(val)
				switch value.Kind() {
				case reflect.Slice, reflect.Array:
					var encodedSlice []string
					for i := 0; i < value.Len(); i++ {
						elem := value.Index(i)
						if elem.Kind() == reflect.Interface {
							elem = elem.Elem()
						}
						switch elem.Kind() {
						case reflect.String:
							encodedSlice = append(encodedSlice, hex.EncodeToString([]byte(elem.String())))
						case reflect.Int:
							encodedSlice = append(encodedSlice, hex.EncodeToString([]byte(strconv.Itoa(int(elem.Int())))))
						}
					}
					dm.Extracted.HexFields[field] = encodedSlice
				}
			}
		}
	}
	return ReturnKeep, nil
}
