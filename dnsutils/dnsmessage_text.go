package dnsutils

import (
	"bytes"
	"errors"
	"regexp"
	"strconv"
	"strings"
	"time"
)

var (
	RawTextDirective = regexp.MustCompile(`^ *\{.*\}`)
)

type TextDirectiveFunc func(dm *DNSMessage, s *bytes.Buffer) error

type TextFormatter struct {
	directives []TextDirectiveFunc
	delimiter  string
}

func (tf *TextFormatter) Format(dm *DNSMessage, s *bytes.Buffer) error {
	for i, fn := range tf.directives {
		if err := fn(dm, s); err != nil {
			return err
		}
		if i < len(tf.directives)-1 && len(tf.delimiter) > 0 {
			s.WriteString(tf.delimiter)
		}
	}
	return nil
}

func NewTextFormatter(format []string, fieldDelimiter string, fieldBoundary string) (*TextFormatter, error) {
	directives := make([]TextDirectiveFunc, len(format))
	for i, directive := range format {
		fn, err := compileDirective(directive, fieldDelimiter, fieldBoundary)
		if err != nil {
			return nil, err
		}
		directives[i] = fn
	}
	return &TextFormatter{
		directives: directives,
		delimiter:  fieldDelimiter,
	}, nil
}

func compileDirective(directive string, fieldDelimiter string, fieldBoundary string) (TextDirectiveFunc, error) {
	switch directive {
	case "timestamp-rfc3339ns", "timestamp":
		return func(dm *DNSMessage, s *bytes.Buffer) error {
			s.WriteString(dm.GetTimestampRFC3339())
			return nil
		}, nil

	case "timestamp-unixms":
		return func(dm *DNSMessage, s *bytes.Buffer) error {
			var b [32]byte
			s.Write(strconv.AppendInt(b[:0], dm.DNSTap.Timestamp/1000000, 10))
			return nil
		}, nil

	case "timestamp-unixus":
		return func(dm *DNSMessage, s *bytes.Buffer) error {
			var b [32]byte
			s.Write(strconv.AppendInt(b[:0], dm.DNSTap.Timestamp/1000, 10))
			return nil
		}, nil

	case "timestamp-unixns":
		return func(dm *DNSMessage, s *bytes.Buffer) error {
			var b [32]byte
			s.Write(strconv.AppendInt(b[:0], dm.DNSTap.Timestamp, 10))
			return nil
		}, nil

	case "localtime":
		return func(dm *DNSMessage, s *bytes.Buffer) error {
			ts := time.Unix(int64(dm.DNSTap.TimeSec), int64(dm.DNSTap.TimeNsec))
			s.WriteString(ts.Format("2006-01-02 15:04:05.999999999"))
			return nil
		}, nil

	case "qname":
		return func(dm *DNSMessage, s *bytes.Buffer) error {
			if len(dm.DNS.Qname) == 0 {
				s.WriteByte('.')
			} else {
				QuoteStringAndWrite(s, dm.DNS.Qname, fieldDelimiter, fieldBoundary)
			}
			return nil
		}, nil

	case "identity":
		return func(dm *DNSMessage, s *bytes.Buffer) error {
			if len(dm.DNSTap.Identity) == 0 {
				s.WriteByte('-')
			} else {
				QuoteStringAndWrite(s, dm.DNSTap.Identity, fieldDelimiter, fieldBoundary)
			}
			return nil
		}, nil

	case "peer-name":
		return func(dm *DNSMessage, s *bytes.Buffer) error {
			if len(dm.DNSTap.PeerName) == 0 {
				s.WriteByte('-')
			} else {
				QuoteStringAndWrite(s, dm.DNSTap.PeerName, fieldDelimiter, fieldBoundary)
			}
			return nil
		}, nil

	case "version":
		return func(dm *DNSMessage, s *bytes.Buffer) error {
			if len(dm.DNSTap.Version) == 0 {
				s.WriteByte('-')
			} else {
				QuoteStringAndWrite(s, dm.DNSTap.Version, fieldDelimiter, fieldBoundary)
			}
			return nil
		}, nil

	case "extra":
		return func(dm *DNSMessage, s *bytes.Buffer) error {
			s.WriteString(dm.DNSTap.Extra)
			return nil
		}, nil

	case "policy-rule":
		return func(dm *DNSMessage, s *bytes.Buffer) error {
			s.WriteString(dm.DNSTap.PolicyRule)
			return nil
		}, nil

	case "policy-type":
		return func(dm *DNSMessage, s *bytes.Buffer) error {
			s.WriteString(dm.DNSTap.PolicyType)
			return nil
		}, nil

	case "policy-action":
		return func(dm *DNSMessage, s *bytes.Buffer) error {
			s.WriteString(dm.DNSTap.PolicyAction)
			return nil
		}, nil

	case "policy-match":
		return func(dm *DNSMessage, s *bytes.Buffer) error {
			s.WriteString(dm.DNSTap.PolicyMatch)
			return nil
		}, nil

	case "policy-value":
		return func(dm *DNSMessage, s *bytes.Buffer) error {
			s.WriteString(dm.DNSTap.PolicyValue)
			return nil
		}, nil

	case "query-zone":
		return func(dm *DNSMessage, s *bytes.Buffer) error {
			s.WriteString(dm.DNSTap.QueryZone)
			return nil
		}, nil

	case "http-protocol":
		return func(dm *DNSMessage, s *bytes.Buffer) error {
			s.WriteString(dm.DNSTap.HttpProtocol)
			return nil
		}, nil

	case "operation":
		return func(dm *DNSMessage, s *bytes.Buffer) error {
			s.WriteString(dm.DNSTap.Operation)
			return nil
		}, nil

	case "rcode":
		return func(dm *DNSMessage, s *bytes.Buffer) error {
			s.WriteString(dm.DNS.Rcode)
			return nil
		}, nil

	case "id":
		return func(dm *DNSMessage, s *bytes.Buffer) error {
			var b [32]byte
			s.Write(strconv.AppendInt(b[:0], int64(dm.DNS.ID), 10))
			return nil
		}, nil

	case "queryip":
		return func(dm *DNSMessage, s *bytes.Buffer) error {
			dm.NetworkInfo.WriteQueryIPText(s)
			return nil
		}, nil

	case "queryport":
		return func(dm *DNSMessage, s *bytes.Buffer) error {
			s.WriteString(dm.NetworkInfo.QueryPort)
			return nil
		}, nil

	case "responseip":
		return func(dm *DNSMessage, s *bytes.Buffer) error {
			dm.NetworkInfo.WriteResponseIPText(s)
			return nil
		}, nil

	case "responseport":
		return func(dm *DNSMessage, s *bytes.Buffer) error {
			s.WriteString(dm.NetworkInfo.ResponsePort)
			return nil
		}, nil

	case "family":
		return func(dm *DNSMessage, s *bytes.Buffer) error {
			s.WriteString(dm.NetworkInfo.Family)
			return nil
		}, nil

	case "protocol":
		return func(dm *DNSMessage, s *bytes.Buffer) error {
			s.WriteString(dm.NetworkInfo.Protocol)
			return nil
		}, nil

	case "length-unit":
		return func(dm *DNSMessage, s *bytes.Buffer) error {
			var b [32]byte
			s.Write(strconv.AppendInt(b[:0], int64(dm.DNS.Length), 10))
			s.WriteByte('b')
			return nil
		}, nil

	case "length":
		return func(dm *DNSMessage, s *bytes.Buffer) error {
			var b [32]byte
			s.Write(strconv.AppendInt(b[:0], int64(dm.DNS.Length), 10))
			return nil
		}, nil

	case "qtype":
		return func(dm *DNSMessage, s *bytes.Buffer) error {
			s.WriteString(dm.DNS.Qtype)
			return nil
		}, nil

	case "qclass":
		return func(dm *DNSMessage, s *bytes.Buffer) error {
			s.WriteString(dm.DNS.Qclass)
			return nil
		}, nil

	case "latency":
		return func(dm *DNSMessage, s *bytes.Buffer) error {
			if dm.DNS.Type == DNSQuery {
				s.WriteByte('-')
			} else {
				var b [32]byte
				s.Write(strconv.AppendFloat(b[:0], dm.DNSTap.Latency, 'f', 9, 64))
			}
			return nil
		}, nil

	case "latency_ms":
		return func(dm *DNSMessage, s *bytes.Buffer) error {
			if dm.DNS.Type == DNSQuery {
				s.WriteByte('-')
			} else {
				var b [32]byte
				s.Write(strconv.AppendInt(b[:0], int64(dm.DNSTap.LatencyMs), 10))
			}
			return nil
		}, nil

	case "malformed":
		return func(dm *DNSMessage, s *bytes.Buffer) error {
			if dm.DNS.MalformedPacket {
				s.WriteString("PKTERR")
			} else {
				s.WriteByte('-')
			}
			return nil
		}, nil

	case "qr":
		return func(dm *DNSMessage, s *bytes.Buffer) error {
			s.WriteString(dm.DNS.Type)
			return nil
		}, nil

	case "opcode":
		return func(dm *DNSMessage, s *bytes.Buffer) error {
			var b [32]byte
			s.Write(strconv.AppendInt(b[:0], int64(dm.DNS.Opcode), 10))
			return nil
		}, nil

	case "tr":
		return func(dm *DNSMessage, s *bytes.Buffer) error {
			if dm.NetworkInfo.TCPReassembled {
				s.WriteString("TR")
			} else {
				s.WriteByte('-')
			}
			return nil
		}, nil

	case "df":
		return func(dm *DNSMessage, s *bytes.Buffer) error {
			if dm.NetworkInfo.IPDefragmented {
				s.WriteString("DF")
			} else {
				s.WriteByte('-')
			}
			return nil
		}, nil

	case "tc":
		return func(dm *DNSMessage, s *bytes.Buffer) error {
			if dm.DNS.Flags.TC {
				s.WriteString("TC")
			} else {
				s.WriteByte('-')
			}
			return nil
		}, nil

	case "aa":
		return func(dm *DNSMessage, s *bytes.Buffer) error {
			if dm.DNS.Flags.AA {
				s.WriteString("AA")
			} else {
				s.WriteByte('-')
			}
			return nil
		}, nil

	case "ra":
		return func(dm *DNSMessage, s *bytes.Buffer) error {
			if dm.DNS.Flags.RA {
				s.WriteString("RA")
			} else {
				s.WriteByte('-')
			}
			return nil
		}, nil

	case "ad":
		return func(dm *DNSMessage, s *bytes.Buffer) error {
			if dm.DNS.Flags.AD {
				s.WriteString("AD")
			} else {
				s.WriteByte('-')
			}
			return nil
		}, nil

	case "rd":
		return func(dm *DNSMessage, s *bytes.Buffer) error {
			if dm.DNS.Flags.RD {
				s.WriteString("RD")
			} else {
				s.WriteByte('-')
			}
			return nil
		}, nil

	case "ttl":
		return func(dm *DNSMessage, s *bytes.Buffer) error {
			if len(dm.DNS.DNSRRs.Answers) > 0 {
				var b [32]byte
				s.Write(strconv.AppendInt(b[:0], int64(dm.DNS.DNSRRs.Answers[0].TTL), 10))
			} else {
				s.WriteByte('-')
			}
			return nil
		}, nil

	case "answer":
		return func(dm *DNSMessage, s *bytes.Buffer) error {
			if len(dm.DNS.DNSRRs.Answers) > 0 {
				s.WriteString(dm.DNS.DNSRRs.Answers[0].Rdata)
			} else {
				s.WriteByte('-')
			}
			return nil
		}, nil

	case "answer-a":
		return func(dm *DNSMessage, s *bytes.Buffer) error {
			for _, a := range dm.DNS.DNSRRs.Answers {
				if a.Rdatatype == "A" {
					s.WriteString(a.Rdata)
					return nil
				}
			}
			s.WriteByte('-')
			return nil
		}, nil

	case "answer-aaaa":
		return func(dm *DNSMessage, s *bytes.Buffer) error {
			for _, a := range dm.DNS.DNSRRs.Answers {
				if a.Rdatatype == Rdatatypes[28] {
					s.WriteString(a.Rdata)
					return nil
				}
			}
			s.WriteByte('-')
			return nil
		}, nil

	case "answer-ip":
		return func(dm *DNSMessage, s *bytes.Buffer) error {
			for _, a := range dm.DNS.DNSRRs.Answers {
				if a.Rdatatype == "A" || a.Rdatatype == Rdatatypes[28] {
					s.WriteString(a.Rdata)
					return nil
				}
			}
			s.WriteByte('-')
			return nil
		}, nil

	case "answer-ips":
		return func(dm *DNSMessage, s *bytes.Buffer) error {
			var ips []string
			for _, a := range dm.DNS.DNSRRs.Answers {
				if a.Rdatatype == "A" || a.Rdatatype == Rdatatypes[28] {
					ips = append(ips, a.Rdata)
				}
			}
			if len(ips) > 0 {
				QuoteStringAndWrite(s, strings.Join(ips, ";"), fieldDelimiter, fieldBoundary)
			} else {
				s.WriteByte('-')
			}
			return nil
		}, nil

	case "rdatatype":
		return func(dm *DNSMessage, s *bytes.Buffer) error {
			if len(dm.DNS.DNSRRs.Answers) > 0 {
				s.WriteString(dm.DNS.DNSRRs.Answers[0].Rdatatype)
			} else {
				s.WriteByte('-')
			}
			return nil
		}, nil

	case "rdatatypes":
		return func(dm *DNSMessage, s *bytes.Buffer) error {
			if len(dm.DNS.DNSRRs.Answers) == 0 {
				s.WriteByte('-')
				return nil
			}
			for i, a := range dm.DNS.DNSRRs.Answers {
				if i > 0 {
					s.WriteByte(';')
				}
				s.WriteString(a.Rdatatype)
			}
			return nil
		}, nil

	case "questionscount", "qdcount":
		return func(dm *DNSMessage, s *bytes.Buffer) error {
			var b [32]byte
			s.Write(strconv.AppendInt(b[:0], int64(dm.DNS.QdCount), 10))
			return nil
		}, nil

	case "answercount", "ancount":
		return func(dm *DNSMessage, s *bytes.Buffer) error {
			var b [32]byte
			s.Write(strconv.AppendInt(b[:0], int64(dm.DNS.AnCount), 10))
			return nil
		}, nil

	case "nscount":
		return func(dm *DNSMessage, s *bytes.Buffer) error {
			var b [32]byte
			s.Write(strconv.AppendInt(b[:0], int64(dm.DNS.NsCount), 10))
			return nil
		}, nil

	case "arcount":
		return func(dm *DNSMessage, s *bytes.Buffer) error {
			var b [32]byte
			s.Write(strconv.AppendInt(b[:0], int64(dm.DNS.ArCount), 10))
			return nil
		}, nil

	case "edns-csubnet":
		return func(dm *DNSMessage, s *bytes.Buffer) error {
			for _, opt := range dm.EDNS.Options {
				if opt.Name == "CSUBNET" {
					s.WriteString(opt.Data)
					return nil
				}
			}
			s.WriteByte('-')
			return nil
		}, nil
	}

	// Collector / Logger directives
	if strings.HasPrefix(directive, "otel-") || strings.HasPrefix(directive, "powerdns-") {
		return compileCollectorDirective(directive, fieldDelimiter, fieldBoundary)
	}

	// Transformer directives
	if strings.HasPrefix(directive, "geoip-") ||
		strings.HasPrefix(directive, "suspicious-") ||
		strings.HasPrefix(directive, "publicsuffix-") ||
		strings.HasPrefix(directive, "extracted-") ||
		strings.HasPrefix(directive, "reducer-") ||
		strings.HasPrefix(directive, "ml-") ||
		strings.HasPrefix(directive, "filtering-") ||
		strings.HasPrefix(directive, "atags") {
		return compileTransformDirective(directive, fieldDelimiter, fieldBoundary)
	}

	// Raw text directive enclosed in { ... }
	if RawTextDirective.MatchString(directive) {
		raw := strings.ReplaceAll(directive, "{", "")
		raw = strings.ReplaceAll(raw, "}", "")
		return func(dm *DNSMessage, s *bytes.Buffer) error {
			s.WriteString(raw)
			return nil
		}, nil
	}

	return nil, errors.New(ErrorUnexpectedDirective + directive)
}

func (dm *DNSMessage) ToTextLine(format []string, fieldDelimiter string, fieldBoundary string, s *bytes.Buffer) error {
	formatter, err := NewTextFormatter(format, fieldDelimiter, fieldBoundary)
	if err != nil {
		return err
	}
	return formatter.Format(dm, s)
}
