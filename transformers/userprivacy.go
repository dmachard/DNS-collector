package transformers

import (
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"fmt"
	"net"
	"strings"

	"github.com/dmachard/go-dnscollector/v2/dnsutils"
	"github.com/dmachard/go-dnscollector/v2/pkgconfig"
	"github.com/dmachard/go-logger"
	"github.com/dmachard/go-netutils"
	"golang.org/x/net/publicsuffix"
)

func HashIP(ip string, algo string) string {
	switch algo {
	case "sha1":
		sum := sha1.Sum([]byte(ip))
		return hex.EncodeToString(sum[:])
	case "sha256":
		sum := sha256.Sum256([]byte(ip))
		return hex.EncodeToString(sum[:])
	case "sha512": // nolint
		sum := sha512.Sum512([]byte(ip))
		return hex.EncodeToString(sum[:])
	default:
		return ip
	}
}

type UserPrivacyTransform struct {
	GenericTransformer
	v4Mask, v6Mask net.IPMask
}

func NewUserPrivacyTransform(config *pkgconfig.ConfigTransformers, logger *logger.Logger, name string, instance int, nextWorkers []chan *dnsutils.DNSMessage) *UserPrivacyTransform {
	t := &UserPrivacyTransform{GenericTransformer: NewTransformer(config, logger, "userprivacy", name, instance, nextWorkers)}
	return t
}

func (t *UserPrivacyTransform) GetTransforms() ([]Subtransform, error) {
	subprocessors := []Subtransform{}

	var err error
	t.v4Mask, err = netutils.ParseCIDRMask(t.config.UserPrivacy.AnonymizeIPV4Bits)
	if err != nil {
		return nil, fmt.Errorf("unable to init v4 mask: %w", err)
	}

	if !strings.Contains(t.config.UserPrivacy.AnonymizeIPV6Bits, ":") {
		return nil, fmt.Errorf("invalid v6 mask, expect format ::/integer")
	}
	t.v6Mask, err = netutils.ParseCIDRMask(t.config.UserPrivacy.AnonymizeIPV6Bits)
	if err != nil {
		return nil, fmt.Errorf("unable to init v6 mask: %w", err)
	}

	if t.config.UserPrivacy.AnonymizeIP {
		subprocessors = append(subprocessors, Subtransform{name: "userprivacy:ip-anonymization", processFunc: t.anonymizeQueryIP})
	}

	if t.config.UserPrivacy.MinimizeQname {
		subprocessors = append(subprocessors, Subtransform{name: "userprivacy:minimize-qname", processFunc: t.minimizeQname})
	}

	if t.config.UserPrivacy.HashQueryIP {
		subprocessors = append(subprocessors, Subtransform{name: "userprivacy:hash-query-ip", processFunc: t.hashQueryIP})
	}
	if t.config.UserPrivacy.HashReplyIP {
		subprocessors = append(subprocessors, Subtransform{name: "userprivacy:hash-reply-ip", processFunc: t.hashReplyIP})
	}

	return subprocessors, nil
}

func (t *UserPrivacyTransform) anonymizeQueryIP(dm *dnsutils.DNSMessage) (int, error) {
	rawIP := dm.NetworkInfo.GetQueryIP()
	queryIP := net.ParseIP(rawIP)
	if queryIP == nil {
		return ReturnKeep, fmt.Errorf("not a valid query ip: %v", rawIP)
	}

	switch {
	case queryIP.To4() != nil:
		dm.NetworkInfo.QueryIP = queryIP.Mask(t.v4Mask).String()
	default:
		dm.NetworkInfo.QueryIP = queryIP.Mask(t.v6Mask).String()
	}

	return ReturnKeep, nil
}

func (t *UserPrivacyTransform) hashQueryIP(dm *dnsutils.DNSMessage) (int, error) {
	dm.NetworkInfo.QueryIP = HashIP(dm.NetworkInfo.GetQueryIP(), t.config.UserPrivacy.HashIPAlgo)
	return ReturnKeep, nil
}

func (t *UserPrivacyTransform) hashReplyIP(dm *dnsutils.DNSMessage) (int, error) {
	dm.NetworkInfo.ResponseIP = HashIP(dm.NetworkInfo.GetResponseIP(), t.config.UserPrivacy.HashIPAlgo)
	return ReturnKeep, nil
}

func (t *UserPrivacyTransform) minimizeQname(dm *dnsutils.DNSMessage) (int, error) {
	if etpo, err := publicsuffix.EffectiveTLDPlusOne(dm.DNS.Qname); err == nil {
		dm.DNS.Qname = etpo
	}
	return ReturnKeep, nil
}
