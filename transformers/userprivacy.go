package transformers

import (
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"fmt"
	"net/netip"
	"strings"

	"github.com/dmachard/go-dnscollector/v2/dnsutils"
	"github.com/dmachard/go-dnscollector/v2/pkg/config"
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
	v4MaskArr [4]byte
	v6MaskArr [16]byte
}

func NewUserPrivacyTransform(cfg *config.ConfigTransformers, logger *logger.Logger, name string, instance int, nextWorkers []chan *dnsutils.DNSMessageBatch) *UserPrivacyTransform {
	t := &UserPrivacyTransform{GenericTransformer: NewTransformer(cfg, logger, "userprivacy", name, instance, nextWorkers)}
	return t
}

func (t *UserPrivacyTransform) GetTransforms() ([]Subtransform, error) {
	subprocessors := []Subtransform{}

	v4Mask, err := netutils.ParseCIDRMask(t.config.UserPrivacy.AnonymizeIPV4Bits)
	if err != nil {
		return nil, fmt.Errorf("unable to init v4 mask: %w", err)
	}
	copy(t.v4MaskArr[:], v4Mask)

	if !strings.Contains(t.config.UserPrivacy.AnonymizeIPV6Bits, ":") {
		return nil, fmt.Errorf("invalid v6 mask, expect format ::/integer")
	}
	v6Mask, err := netutils.ParseCIDRMask(t.config.UserPrivacy.AnonymizeIPV6Bits)
	if err != nil {
		return nil, fmt.Errorf("unable to init v6 mask: %w", err)
	}
	copy(t.v6MaskArr[:], v6Mask)

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
	switch dm.NetworkInfo.QueryIPLen {
	case 4:
		dm.NetworkInfo.QueryIPBuf[0] &= t.v4MaskArr[0]
		dm.NetworkInfo.QueryIPBuf[1] &= t.v4MaskArr[1]
		dm.NetworkInfo.QueryIPBuf[2] &= t.v4MaskArr[2]
		dm.NetworkInfo.QueryIPBuf[3] &= t.v4MaskArr[3]
		if dm.NetworkInfo.QueryIP != "-" && dm.NetworkInfo.QueryIP != "" {
			dm.NetworkInfo.QueryIP = dnsutils.FastIPv4ToString(dm.NetworkInfo.QueryIPBuf[:4])
		}
		return ReturnKeep, nil

	case 16:
		for i := 0; i < 16; i++ {
			dm.NetworkInfo.QueryIPBuf[i] &= t.v6MaskArr[i]
		}
		if dm.NetworkInfo.QueryIP != "-" && dm.NetworkInfo.QueryIP != "" {
			dm.NetworkInfo.QueryIP = netip.AddrFrom16(dm.NetworkInfo.QueryIPBuf).String()
		}
		return ReturnKeep, nil

	default:
		if dm.NetworkInfo.QueryIP == "" || dm.NetworkInfo.QueryIP == "-" {
			return ReturnKeep, fmt.Errorf("not a valid query ip: %v", dm.NetworkInfo.QueryIP)
		}
		addr, err := netip.ParseAddr(dm.NetworkInfo.QueryIP)
		if err != nil {
			return ReturnKeep, fmt.Errorf("not a valid query ip: %v", dm.NetworkInfo.QueryIP)
		}
		if addr.Is4() {
			b4 := addr.As4()
			b4[0] &= t.v4MaskArr[0]
			b4[1] &= t.v4MaskArr[1]
			b4[2] &= t.v4MaskArr[2]
			b4[3] &= t.v4MaskArr[3]
			dm.NetworkInfo.SetQueryIPBytes(b4[:])
			dm.NetworkInfo.QueryIP = dnsutils.FastIPv4ToString(b4[:])
		} else {
			b16 := addr.As16()
			for i := 0; i < 16; i++ {
				b16[i] &= t.v6MaskArr[i]
			}
			dm.NetworkInfo.SetQueryIPBytes(b16[:])
			dm.NetworkInfo.QueryIP = netip.AddrFrom16(b16).String()
		}
		return ReturnKeep, nil
	}
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
