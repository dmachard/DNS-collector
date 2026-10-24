package transformers

import (
	"math"
	"regexp"
	"strings"

	"github.com/dmachard/go-dnscollector/v3/dnsutils"
	"github.com/dmachard/go-dnscollector/v3/pkg/config"
	"github.com/dmachard/go-logger"
)

type SuspiciousTransform struct {
	GenericTransformer
	config                *config.TransformSuspicious
	commonQtypes          map[string]bool
	whitelistDomainsRegex map[string]*regexp.Regexp
}

func NewSuspiciousTransform(cfg *config.TransformSuspicious, logger *logger.Logger, name string, instance int, nextWorkers []chan *dnsutils.DNSMessageBatch) *SuspiciousTransform {
	t := &SuspiciousTransform{config: cfg, GenericTransformer: NewTransformer(logger, "suspicious", name, instance, nextWorkers)}
	t.commonQtypes = make(map[string]bool)
	t.whitelistDomainsRegex = make(map[string]*regexp.Regexp)
	return t
}

func (t *SuspiciousTransform) GetTransforms() ([]Subtransform, error) {
	subtransforms := []Subtransform{}

	// cleanup maps
	for key := range t.commonQtypes {
		delete(t.commonQtypes, key)
	}
	for key := range t.whitelistDomainsRegex {
		delete(t.whitelistDomainsRegex, key)
	}

	// load maps
	for _, v := range t.config.CommonQtypes {
		t.commonQtypes[v] = true
	}
	for _, v := range t.config.WhitelistDomains {
		t.whitelistDomainsRegex[v] = regexp.MustCompile(v)
	}

	if t.config.Enable {
		subtransforms = append(subtransforms, Subtransform{name: "suspicious:check", processFunc: t.checkIfSuspicious})
	}
	return subtransforms, nil
}

func (t *SuspiciousTransform) checkIfSuspicious(dm *dnsutils.DNSMessage) (int, error) {

	if dm.Suspicious == nil {
		dm.Suspicious = &dnsutils.TransformSuspicious{}
	}

	// ignore some domains ?
	for _, d := range t.whitelistDomainsRegex {
		if d.MatchString(dm.DNS.Qname) {
			return ReturnKeep, nil
		}
	}

	// dns decoding error?
	if dm.DNS.MalformedPacket {
		dm.Suspicious.Score += 1.0
		dm.Suspicious.MalformedPacket = true
	}

	// long domain name ?
	if len(dm.DNS.Qname) > t.config.ThresholdQnameLen {
		dm.Suspicious.Score += 1.0
		dm.Suspicious.LongDomain = true
	}

	// large packet size ?
	if dm.DNS.Length > t.config.ThresholdPacketLen {
		dm.Suspicious.Score += 1.0
		dm.Suspicious.LargePacket = true
	}

	// slow domain name resolution ?
	if dm.DNSTap.Latency > t.config.ThresholdSlow {
		dm.Suspicious.Score += 1.0
		dm.Suspicious.SlowDomain = true
	}

	// uncommon qtype?
	if _, found := t.commonQtypes[dm.DNS.Qtype]; !found {
		dm.Suspicious.Score += 1.0
		dm.Suspicious.UncommonQtypes = true
	}

	// count the number of labels in qname
	if strings.Count(dm.DNS.Qname, ".") > t.config.ThresholdMaxLabels {
		dm.Suspicious.Score += 1.0
		dm.Suspicious.ExcessiveNumberLabels = true
	}

	// search for unallowed characters
	for _, v := range t.config.UnallowedChars {
		if strings.Contains(dm.DNS.Qname, v) {
			dm.Suspicious.Score += 1.0
			dm.Suspicious.UnallowedChars = true
			break
		}
	}

	// high entropy domain name or label ?
	if t.config.ThresholdEntropy > 0 {
		qname := strings.TrimSuffix(dm.DNS.Qname, ".")
		if len(qname) >= 8 && calcEntropy(qname) > t.config.ThresholdEntropy {
			dm.Suspicious.Score += 1.0
			dm.Suspicious.HighEntropy = true
		} else {
			start := 0
			for i := 0; i <= len(qname); i++ {
				if i == len(qname) || qname[i] == '.' {
					if i-start >= 8 && calcEntropy(qname[start:i]) > t.config.ThresholdEntropy {
						dm.Suspicious.Score += 1.0
						dm.Suspicious.HighEntropy = true
						break
					}
					start = i + 1
				}
			}
		}
	}

	return ReturnKeep, nil
}

func calcEntropy(s string) float64 {
	if len(s) == 0 {
		return 0.0
	}
	var freq [256]int
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= 'A' && c <= 'Z' {
			c += 'a' - 'A'
		}
		freq[c]++
	}
	var entropy float64
	invLen := 1.0 / float64(len(s))
	for _, count := range freq {
		if count > 0 {
			p := float64(count) * invLen
			entropy -= p * math.Log2(p)
		}
	}
	return entropy
}
