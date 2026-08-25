package dnsutils

import (
	"bytes"
	"encoding/base64"
	"errors"
	"strconv"
	"strings"
)

func compileTransformDirective(directive string, fieldDelimiter string, fieldBoundary string) (TextDirectiveFunc, error) {
	switch {
	case strings.HasPrefix(directive, "geoip-"):
		switch directive {
		case "geoip-continent":
			return func(dm *DNSMessage, s *bytes.Buffer) error {
				if dm.Geo != nil {
					s.WriteString(dm.Geo.Continent)
				} else {
					s.WriteByte('-')
				}
				return nil
			}, nil
		case "geoip-country":
			return func(dm *DNSMessage, s *bytes.Buffer) error {
				if dm.Geo != nil {
					s.WriteString(dm.Geo.CountryIsoCode)
				} else {
					s.WriteByte('-')
				}
				return nil
			}, nil
		case "geoip-city":
			return func(dm *DNSMessage, s *bytes.Buffer) error {
				if dm.Geo != nil {
					s.WriteString(dm.Geo.City)
				} else {
					s.WriteByte('-')
				}
				return nil
			}, nil
		case "geoip-as-number":
			return func(dm *DNSMessage, s *bytes.Buffer) error {
				if dm.Geo != nil {
					s.WriteString(dm.Geo.AutonomousSystemNumber)
				} else {
					s.WriteByte('-')
				}
				return nil
			}, nil
		case "geoip-as-owner":
			return func(dm *DNSMessage, s *bytes.Buffer) error {
				if dm.Geo != nil {
					s.WriteString(dm.Geo.AutonomousSystemOrg)
				} else {
					s.WriteByte('-')
				}
				return nil
			}, nil
		case "geoip-lat":
			return func(dm *DNSMessage, s *bytes.Buffer) error {
				if dm.Geo != nil {
					var b [32]byte
					s.Write(strconv.AppendFloat(b[:0], dm.Geo.Latitude, 'f', -1, 64))
				} else {
					s.WriteByte('-')
				}
				return nil
			}, nil
		case "geoip-lon":
			return func(dm *DNSMessage, s *bytes.Buffer) error {
				if dm.Geo != nil {
					var b [32]byte
					s.Write(strconv.AppendFloat(b[:0], dm.Geo.Longitude, 'f', -1, 64))
				} else {
					s.WriteByte('-')
				}
				return nil
			}, nil
		default:
			return nil, errors.New(ErrorUnexpectedDirective + directive)
		}

	case strings.HasPrefix(directive, "bgp-"):
		switch directive {
		case "bgp-origin-asn":
			return func(dm *DNSMessage, s *bytes.Buffer) error {
				if dm.BGP != nil {
					s.WriteString(dm.BGP.OriginASN)
				} else {
					s.WriteByte('-')
				}
				return nil
			}, nil
		case "bgp-as-path":
			return func(dm *DNSMessage, s *bytes.Buffer) error {
				if dm.BGP != nil {
					s.WriteString(dm.BGP.ASPath)
				} else {
					s.WriteByte('-')
				}
				return nil
			}, nil
		case "bgp-prefix":
			return func(dm *DNSMessage, s *bytes.Buffer) error {
				if dm.BGP != nil {
					s.WriteString(dm.BGP.Prefix)
				} else {
					s.WriteByte('-')
				}
				return nil
			}, nil
		default:
			return nil, errors.New(ErrorUnexpectedDirective + directive)
		}

	case strings.HasPrefix(directive, "suspicious-"):
		switch directive {
		case "suspicious-score":
			return func(dm *DNSMessage, s *bytes.Buffer) error {
				if dm.Suspicious != nil {
					var b [32]byte
					s.Write(strconv.AppendInt(b[:0], int64(dm.Suspicious.Score), 10))
				} else {
					s.WriteByte('-')
				}
				return nil
			}, nil
		default:
			return nil, errors.New(ErrorUnexpectedDirective + directive)
		}

	case strings.HasPrefix(directive, "publicsuffix-"):
		switch directive {
		case "publicsuffix-tld":
			return func(dm *DNSMessage, s *bytes.Buffer) error {
				if dm.PublicSuffix != nil {
					s.WriteString(dm.PublicSuffix.QnamePublicSuffix)
				} else {
					s.WriteByte('-')
				}
				return nil
			}, nil
		case "publicsuffix-etld+1":
			return func(dm *DNSMessage, s *bytes.Buffer) error {
				if dm.PublicSuffix != nil {
					s.WriteString(dm.PublicSuffix.QnameEffectiveTLDPlusOne)
				} else {
					s.WriteByte('-')
				}
				return nil
			}, nil
		case "publicsuffix-managed-icann":
			return func(dm *DNSMessage, s *bytes.Buffer) error {
				if dm.PublicSuffix != nil {
					if dm.PublicSuffix.ManagedByICANN {
						s.WriteString("managed")
					} else {
						s.WriteString("private")
					}
				} else {
					s.WriteByte('-')
				}
				return nil
			}, nil
		default:
			return nil, errors.New(ErrorUnexpectedDirective + directive)
		}

	case strings.HasPrefix(directive, "extracted-"):
		switch directive {
		case "extracted-dns-payload":
			return func(dm *DNSMessage, s *bytes.Buffer) error {
				if dm.Extracted != nil && len(dm.DNS.Payload) > 0 {
					dst := make([]byte, base64.StdEncoding.EncodedLen(len(dm.DNS.Payload)))
					base64.StdEncoding.Encode(dst, dm.DNS.Payload)
					s.Write(dst)
				} else {
					s.WriteByte('-')
				}
				return nil
			}, nil
		default:
			return nil, errors.New(ErrorUnexpectedDirective + directive)
		}

	case strings.HasPrefix(directive, "reducer-"):
		switch directive {
		case "reducer-occurrences":
			return func(dm *DNSMessage, s *bytes.Buffer) error {
				if dm.Reducer != nil {
					var b [32]byte
					s.Write(strconv.AppendInt(b[:0], int64(dm.Reducer.Occurrences), 10))
				} else {
					s.WriteByte('-')
				}
				return nil
			}, nil
		case "reducer-cumulative-length":
			return func(dm *DNSMessage, s *bytes.Buffer) error {
				if dm.Reducer != nil {
					var b [32]byte
					s.Write(strconv.AppendInt(b[:0], int64(dm.Reducer.CumulativeLength), 10))
				} else {
					s.WriteByte('-')
				}
				return nil
			}, nil
		default:
			return nil, errors.New(ErrorUnexpectedDirective + directive)
		}

	case strings.HasPrefix(directive, "ml-"):
		switch directive {
		case "ml-entropy":
			return func(dm *DNSMessage, s *bytes.Buffer) error {
				if dm.MachineLearning != nil {
					var b [32]byte
					s.Write(strconv.AppendFloat(b[:0], dm.MachineLearning.Entropy, 'f', -1, 64))
				} else {
					s.WriteByte('-')
				}
				return nil
			}, nil
		case "ml-length":
			return func(dm *DNSMessage, s *bytes.Buffer) error {
				if dm.MachineLearning != nil {
					var b [32]byte
					s.Write(strconv.AppendInt(b[:0], int64(dm.MachineLearning.Length), 10))
				} else {
					s.WriteByte('-')
				}
				return nil
			}, nil
		case "ml-digits":
			return func(dm *DNSMessage, s *bytes.Buffer) error {
				if dm.MachineLearning != nil {
					var b [32]byte
					s.Write(strconv.AppendInt(b[:0], int64(dm.MachineLearning.Digits), 10))
				} else {
					s.WriteByte('-')
				}
				return nil
			}, nil
		case "ml-lowers":
			return func(dm *DNSMessage, s *bytes.Buffer) error {
				if dm.MachineLearning != nil {
					var b [32]byte
					s.Write(strconv.AppendInt(b[:0], int64(dm.MachineLearning.Lowers), 10))
				} else {
					s.WriteByte('-')
				}
				return nil
			}, nil
		case "ml-uppers":
			return func(dm *DNSMessage, s *bytes.Buffer) error {
				if dm.MachineLearning != nil {
					var b [32]byte
					s.Write(strconv.AppendInt(b[:0], int64(dm.MachineLearning.Uppers), 10))
				} else {
					s.WriteByte('-')
				}
				return nil
			}, nil
		case "ml-specials":
			return func(dm *DNSMessage, s *bytes.Buffer) error {
				if dm.MachineLearning != nil {
					var b [32]byte
					s.Write(strconv.AppendInt(b[:0], int64(dm.MachineLearning.Specials), 10))
				} else {
					s.WriteByte('-')
				}
				return nil
			}, nil
		case "ml-others":
			return func(dm *DNSMessage, s *bytes.Buffer) error {
				if dm.MachineLearning != nil {
					var b [32]byte
					s.Write(strconv.AppendInt(b[:0], int64(dm.MachineLearning.Others), 10))
				} else {
					s.WriteByte('-')
				}
				return nil
			}, nil
		case "ml-labels":
			return func(dm *DNSMessage, s *bytes.Buffer) error {
				if dm.MachineLearning != nil {
					var b [32]byte
					s.Write(strconv.AppendInt(b[:0], int64(dm.MachineLearning.Labels), 10))
				} else {
					s.WriteByte('-')
				}
				return nil
			}, nil
		case "ml-ratio-digits":
			return func(dm *DNSMessage, s *bytes.Buffer) error {
				if dm.MachineLearning != nil {
					var b [32]byte
					s.Write(strconv.AppendFloat(b[:0], dm.MachineLearning.RatioDigits, 'f', 3, 64))
				} else {
					s.WriteByte('-')
				}
				return nil
			}, nil
		case "ml-ratio-letters":
			return func(dm *DNSMessage, s *bytes.Buffer) error {
				if dm.MachineLearning != nil {
					var b [32]byte
					s.Write(strconv.AppendFloat(b[:0], dm.MachineLearning.RatioLetters, 'f', 3, 64))
				} else {
					s.WriteByte('-')
				}
				return nil
			}, nil
		case "ml-ratio-specials":
			return func(dm *DNSMessage, s *bytes.Buffer) error {
				if dm.MachineLearning != nil {
					var b [32]byte
					s.Write(strconv.AppendFloat(b[:0], dm.MachineLearning.RatioSpecials, 'f', 3, 64))
				} else {
					s.WriteByte('-')
				}
				return nil
			}, nil
		case "ml-ratio-others":
			return func(dm *DNSMessage, s *bytes.Buffer) error {
				if dm.MachineLearning != nil {
					var b [32]byte
					s.Write(strconv.AppendFloat(b[:0], dm.MachineLearning.RatioOthers, 'f', 3, 64))
				} else {
					s.WriteByte('-')
				}
				return nil
			}, nil
		case "ml-consecutive-chars":
			return func(dm *DNSMessage, s *bytes.Buffer) error {
				if dm.MachineLearning != nil {
					var b [32]byte
					s.Write(strconv.AppendInt(b[:0], int64(dm.MachineLearning.ConsecutiveChars), 10))
				} else {
					s.WriteByte('-')
				}
				return nil
			}, nil
		case "ml-consecutive-vowels":
			return func(dm *DNSMessage, s *bytes.Buffer) error {
				if dm.MachineLearning != nil {
					var b [32]byte
					s.Write(strconv.AppendInt(b[:0], int64(dm.MachineLearning.ConsecutiveVowels), 10))
				} else {
					s.WriteByte('-')
				}
				return nil
			}, nil
		case "ml-consecutive-digits":
			return func(dm *DNSMessage, s *bytes.Buffer) error {
				if dm.MachineLearning != nil {
					var b [32]byte
					s.Write(strconv.AppendInt(b[:0], int64(dm.MachineLearning.ConsecutiveDigits), 10))
				} else {
					s.WriteByte('-')
				}
				return nil
			}, nil
		case "ml-consecutive-consonants":
			return func(dm *DNSMessage, s *bytes.Buffer) error {
				if dm.MachineLearning != nil {
					var b [32]byte
					s.Write(strconv.AppendInt(b[:0], int64(dm.MachineLearning.ConsecutiveConsonants), 10))
				} else {
					s.WriteByte('-')
				}
				return nil
			}, nil
		case "ml-size":
			return func(dm *DNSMessage, s *bytes.Buffer) error {
				if dm.MachineLearning != nil {
					var b [32]byte
					s.Write(strconv.AppendInt(b[:0], int64(dm.MachineLearning.Size), 10))
				} else {
					s.WriteByte('-')
				}
				return nil
			}, nil
		case "ml-occurrences":
			return func(dm *DNSMessage, s *bytes.Buffer) error {
				if dm.MachineLearning != nil {
					var b [32]byte
					s.Write(strconv.AppendInt(b[:0], int64(dm.MachineLearning.Occurrences), 10))
				} else {
					s.WriteByte('-')
				}
				return nil
			}, nil
		case "ml-uncommon-qtypes":
			return func(dm *DNSMessage, s *bytes.Buffer) error {
				if dm.MachineLearning != nil {
					var b [32]byte
					s.Write(strconv.AppendInt(b[:0], int64(dm.MachineLearning.UncommonQtypes), 10))
				} else {
					s.WriteByte('-')
				}
				return nil
			}, nil
		default:
			return nil, errors.New(ErrorUnexpectedDirective + directive)
		}

	case strings.HasPrefix(directive, "filtering-"):
		switch directive {
		case "filtering-sample-rate":
			return func(dm *DNSMessage, s *bytes.Buffer) error {
				if dm.Filtering != nil {
					var b [32]byte
					s.Write(strconv.AppendInt(b[:0], int64(dm.Filtering.SampleRate), 10))
				} else {
					s.WriteByte('-')
				}
				return nil
			}, nil
		default:
			return nil, errors.New(ErrorUnexpectedDirective + directive)
		}

	case strings.HasPrefix(directive, "atags"):
		if i := strings.IndexByte(directive, ':'); i != -1 {
			tagIndex, err := strconv.Atoi(directive[i+1:])
			if err != nil {
				return nil, errors.New("unsupported tag index provided (integer expected): " + directive[i+1:])
			}
			return func(dm *DNSMessage, s *bytes.Buffer) error {
				if dm.ATags != nil && tagIndex < len(dm.ATags.Tags) {
					s.WriteString(dm.ATags.Tags[tagIndex])
				} else {
					s.WriteByte('-')
				}
				return nil
			}, nil
		}
		if directive == "atags" {
			return func(dm *DNSMessage, s *bytes.Buffer) error {
				if dm.ATags != nil && len(dm.ATags.Tags) > 0 {
					for i, tag := range dm.ATags.Tags {
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
		}
		return nil, errors.New(ErrorUnexpectedDirective + directive)
	}

	return nil, errors.New(ErrorUnexpectedDirective + directive)
}
