package dnsutils

import (
	"bytes"
	"errors"
	"strconv"
	"strings"
)

func compileCollectorDirective(directive string, fieldDelimiter string, fieldBoundary string) (TextDirectiveFunc, error) {
	switch {
	case strings.HasPrefix(directive, "otel-"):
		switch directive {
		case "otel-trace-id":
			return func(dm *DNSMessage, s *bytes.Buffer) error {
				if dm.OpenTelemetry != nil && len(dm.OpenTelemetry.TraceID) > 0 {
					s.WriteString(dm.OpenTelemetry.TraceID)
				} else {
					s.WriteByte('-')
				}
				return nil
			}, nil
		default:
			return nil, errors.New(ErrorUnexpectedDirective + directive)
		}

	case strings.HasPrefix(directive, "powerdns-"):
		var baseDirective string
		var subArg string
		if i := strings.IndexByte(directive, ':'); i != -1 {
			baseDirective = directive[:i]
			subArg = directive[i+1:]
		} else {
			baseDirective = directive
		}

		switch baseDirective {
		case "powerdns-tags":
			if subArg != "" {
				tagIndex, err := strconv.Atoi(subArg)
				if err != nil {
					return nil, errors.New("unsupported tag index provided (integer expected): " + subArg)
				}
				return func(dm *DNSMessage, s *bytes.Buffer) error {
					if dm.PowerDNS != nil && dm.PowerDNS.Tags != nil && tagIndex < len(dm.PowerDNS.Tags) {
						s.WriteString(dm.PowerDNS.Tags[tagIndex])
					} else {
						s.WriteByte('-')
					}
					return nil
				}, nil
			}
			return func(dm *DNSMessage, s *bytes.Buffer) error {
				if dm.PowerDNS != nil && dm.PowerDNS.Tags != nil && len(dm.PowerDNS.Tags) > 0 {
					for i, tag := range dm.PowerDNS.Tags {
						if i > 0 {
							s.WriteByte(',')
						}
						s.WriteString(tag)
					}
				} else {
					s.WriteByte('-')
				}
				return nil
			}, nil

		case "powerdns-applied-policy":
			return func(dm *DNSMessage, s *bytes.Buffer) error {
				if dm.PowerDNS != nil && len(dm.PowerDNS.AppliedPolicy) > 0 {
					s.WriteString(dm.PowerDNS.AppliedPolicy)
				} else {
					s.WriteByte('-')
				}
				return nil
			}, nil

		case "powerdns-applied-policy-hit":
			return func(dm *DNSMessage, s *bytes.Buffer) error {
				if dm.PowerDNS != nil && len(dm.PowerDNS.AppliedPolicyHit) > 0 {
					s.WriteString(dm.PowerDNS.AppliedPolicyHit)
				} else {
					s.WriteByte('-')
				}
				return nil
			}, nil

		case "powerdns-applied-policy-kind":
			return func(dm *DNSMessage, s *bytes.Buffer) error {
				if dm.PowerDNS != nil && len(dm.PowerDNS.AppliedPolicyKind) > 0 {
					s.WriteString(dm.PowerDNS.AppliedPolicyKind)
				} else {
					s.WriteByte('-')
				}
				return nil
			}, nil

		case "powerdns-applied-policy-trigger":
			return func(dm *DNSMessage, s *bytes.Buffer) error {
				if dm.PowerDNS != nil && len(dm.PowerDNS.AppliedPolicyTrigger) > 0 {
					s.WriteString(dm.PowerDNS.AppliedPolicyTrigger)
				} else {
					s.WriteByte('-')
				}
				return nil
			}, nil

		case "powerdns-applied-policy-type":
			return func(dm *DNSMessage, s *bytes.Buffer) error {
				if dm.PowerDNS != nil && len(dm.PowerDNS.AppliedPolicyType) > 0 {
					s.WriteString(dm.PowerDNS.AppliedPolicyType)
				} else {
					s.WriteByte('-')
				}
				return nil
			}, nil

		case "powerdns-requestor-id":
			return func(dm *DNSMessage, s *bytes.Buffer) error {
				if dm.PowerDNS != nil && len(dm.PowerDNS.RequestorID) > 0 {
					s.WriteString(dm.PowerDNS.RequestorID)
				} else {
					s.WriteByte('-')
				}
				return nil
			}, nil

		case "powerdns-device-id":
			return func(dm *DNSMessage, s *bytes.Buffer) error {
				if dm.PowerDNS != nil && len(dm.PowerDNS.DeviceID) > 0 {
					s.WriteString(dm.PowerDNS.DeviceID)
				} else {
					s.WriteByte('-')
				}
				return nil
			}, nil

		case "powerdns-device-name":
			return func(dm *DNSMessage, s *bytes.Buffer) error {
				if dm.PowerDNS != nil && len(dm.PowerDNS.DeviceName) > 0 {
					s.WriteString(dm.PowerDNS.DeviceName)
				} else {
					s.WriteByte('-')
				}
				return nil
			}, nil

		case "powerdns-message-id":
			return func(dm *DNSMessage, s *bytes.Buffer) error {
				if dm.PowerDNS != nil && len(dm.PowerDNS.MessageID) > 0 {
					s.WriteString(dm.PowerDNS.MessageID)
				} else {
					s.WriteByte('-')
				}
				return nil
			}, nil

		case "powerdns-initial-requestor-id":
			return func(dm *DNSMessage, s *bytes.Buffer) error {
				if dm.PowerDNS != nil && len(dm.PowerDNS.InitialRequestorID) > 0 {
					s.WriteString(dm.PowerDNS.InitialRequestorID)
				} else {
					s.WriteByte('-')
				}
				return nil
			}, nil

		case "powerdns-original-request-subnet":
			return func(dm *DNSMessage, s *bytes.Buffer) error {
				if dm.PowerDNS != nil && len(dm.PowerDNS.OriginalRequestSubnet) > 0 {
					s.WriteString(dm.PowerDNS.OriginalRequestSubnet)
				} else {
					s.WriteByte('-')
				}
				return nil
			}, nil

		case "powerdns-metadata":
			if subArg != "" {
				metaKey := subArg
				return func(dm *DNSMessage, s *bytes.Buffer) error {
					if dm.PowerDNS != nil && dm.PowerDNS.Metadata != nil {
						if metaValue, ok := dm.PowerDNS.Metadata[metaKey]; ok && len(metaValue) > 0 {
							s.WriteString(strings.ReplaceAll(metaValue, " ", "_"))
							return nil
						}
					}
					s.WriteByte('-')
					return nil
				}, nil
			}
			return func(dm *DNSMessage, s *bytes.Buffer) error {
				s.WriteByte('-')
				return nil
			}, nil

		case "powerdns-http-version":
			return func(dm *DNSMessage, s *bytes.Buffer) error {
				if dm.PowerDNS != nil && len(dm.PowerDNS.HTTPVersion) > 0 {
					s.WriteString(dm.PowerDNS.HTTPVersion)
				} else {
					s.WriteByte('-')
				}
				return nil
			}, nil

		case "powerdns-edns-version":
			return func(dm *DNSMessage, s *bytes.Buffer) error {
				if dm.PowerDNS != nil && len(dm.PowerDNS.EdnsVersion) > 0 {
					s.WriteString(dm.PowerDNS.EdnsVersion)
				} else {
					s.WriteByte('-')
				}
				return nil
			}, nil

		case "powerdns-opentelemetry-data":
			return func(dm *DNSMessage, s *bytes.Buffer) error {
				if dm.PowerDNS != nil && len(dm.PowerDNS.OpenTelemetryData) > 0 {
					s.WriteString(dm.PowerDNS.OpenTelemetryData)
				} else {
					s.WriteByte('-')
				}
				return nil
			}, nil

		default:
			return nil, errors.New(ErrorUnexpectedDirective + directive)
		}
	}

	return nil, errors.New(ErrorUnexpectedDirective + directive)
}
