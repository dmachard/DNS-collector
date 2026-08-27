package transformers

import (
	"errors"
	"reflect"
	"strings"

	"github.com/dmachard/go-dnscollector/v3/dnsutils"
	"github.com/dmachard/go-dnscollector/v3/pkg/config"
	"github.com/dmachard/go-logger"
)

type MutatorFunc func(dm *dnsutils.DNSMessage) error

type RewriteTransform struct {
	GenericTransformer
	config   *config.TransformRewrite
	mutators []MutatorFunc
}

func NewRewriteTransform(cfg *config.TransformRewrite, logger *logger.Logger, name string, instance int, nextWorkers []chan *dnsutils.DNSMessageBatch) *RewriteTransform {
	t := &RewriteTransform{config: cfg, GenericTransformer: NewTransformer(logger, "rewrite", name, instance, nextWorkers)}
	t.initMutators()
	return t
}

func (t *RewriteTransform) ReloadConfig(cfg *config.TransformRewrite) {
	t.config = cfg
	t.initMutators()
}

func (t *RewriteTransform) initMutators() {
	t.mutators = make([]MutatorFunc, 0, len(t.config.Identifiers))
	for nestedKeys, value := range t.config.Identifiers {
		t.mutators = append(t.mutators, getMutator(nestedKeys, value))
	}
}

func getMutator(nestedKeys string, val interface{}) MutatorFunc {
	switch nestedKeys {
	case "network.query-ip":
		if s, ok := val.(string); ok {
			return func(dm *dnsutils.DNSMessage) error { dm.NetworkInfo.QueryIP = s; return nil }
		}
	case "network.response-ip":
		if s, ok := val.(string); ok {
			return func(dm *dnsutils.DNSMessage) error { dm.NetworkInfo.ResponseIP = s; return nil }
		}
	case "dns.qname":
		if s, ok := val.(string); ok {
			return func(dm *dnsutils.DNSMessage) error { dm.DNS.Qname = s; return nil }
		}
	case "dns.qtype":
		if s, ok := val.(string); ok {
			return func(dm *dnsutils.DNSMessage) error { dm.DNS.Qtype = s; return nil }
		}
	case "dns.length":
		if i, ok := val.(int); ok {
			return func(dm *dnsutils.DNSMessage) error { dm.DNS.Length = i; return nil }
		}
	case "dns.id":
		if i, ok := val.(int); ok {
			return func(dm *dnsutils.DNSMessage) error { dm.DNS.ID = i; return nil }
		}
	case "dns.opcode":
		if i, ok := val.(int); ok {
			return func(dm *dnsutils.DNSMessage) error { dm.DNS.Opcode = i; return nil }
		}
	case "dns.rcode":
		if s, ok := val.(string); ok {
			return func(dm *dnsutils.DNSMessage) error { dm.DNS.Rcode = s; return nil }
		}
	case "dns.qclass":
		if s, ok := val.(string); ok {
			return func(dm *dnsutils.DNSMessage) error { dm.DNS.Qclass = s; return nil }
		}
	case "network.family":
		if s, ok := val.(string); ok {
			return func(dm *dnsutils.DNSMessage) error { dm.NetworkInfo.Family = s; return nil }
		}
	case "network.protocol":
		if s, ok := val.(string); ok {
			return func(dm *dnsutils.DNSMessage) error { dm.NetworkInfo.Protocol = s; return nil }
		}
	case "network.query-port":
		if s, ok := val.(string); ok {
			return func(dm *dnsutils.DNSMessage) error { dm.NetworkInfo.QueryPort = s; return nil }
		}
	case "network.response-port":
		if s, ok := val.(string); ok {
			return func(dm *dnsutils.DNSMessage) error { dm.NetworkInfo.ResponsePort = s; return nil }
		}
	case "dnstap.identity":
		if s, ok := val.(string); ok {
			return func(dm *dnsutils.DNSMessage) error { dm.DNSTap.Identity = s; return nil }
		}
	}

	// Fallback to reflection if not standard
	return func(dm *dnsutils.DNSMessage) error {
		dmValue := reflect.ValueOf(dm)
		if dmValue.Kind() == reflect.Pointer {
			dmValue = dmValue.Elem()
		}
		realValue, found := getFieldByTag(dmValue, nestedKeys)
		if !found {
			return errors.New("field not found: " + nestedKeys)
		}
		if !realValue.CanSet() {
			return errors.New("field cannot be set: " + nestedKeys)
		}
		newValue := reflect.ValueOf(val)
		if realValue.Kind() != newValue.Kind() {
			return errors.New("unable to set value (" + newValue.Type().String() + ") for " + nestedKeys + "(" + realValue.Type().String() + ")")
		}
		realValue.Set(newValue)
		return nil
	}
}

func (t *RewriteTransform) GetTransforms() ([]Subtransform, error) {
	subtransforms := []Subtransform{}
	if len(t.config.Identifiers) > 0 {
		subtransforms = append(subtransforms, Subtransform{name: "rewrite", processFunc: t.UpdateValues})
	}
	return subtransforms, nil
}

func (t *RewriteTransform) UpdateValues(dm *dnsutils.DNSMessage) (int, error) {
	for _, mutator := range t.mutators {
		if err := mutator(dm); err != nil {
			return 0, err
		}
	}
	return ReturnKeep, nil
}

func getFieldByTag(value reflect.Value, nestedKeys string) (reflect.Value, bool) {
	listKeys := strings.SplitN(nestedKeys, ".", 2)

	for j, jsonKey := range listKeys {
		// Iterate over the fields of the structure
		for i := 0; i < value.NumField(); i++ {
			field := value.Type().Field(i)

			// Get JSON tag
			tag := field.Tag.Get("json")
			tagClean := strings.TrimSuffix(tag, ",omitempty")

			// Check if the JSON tag matches
			if tagClean == jsonKey {
				switch field.Type.Kind() {
				// ptr
				case reflect.Pointer:
					if fieldValue, found := getFieldByTag(value.Field(i).Elem(), listKeys[j+1]); found {
						return fieldValue, true
					}

				// struct
				case reflect.Struct:
					if fieldValue, found := getFieldByTag(value.Field(i), listKeys[j+1]); found {
						return fieldValue, true
					}
				default:
					return value.Field(i), true
				}
			}
		}
	}

	return reflect.Value{}, false
}
