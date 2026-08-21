package dnsutils

import (
	"encoding/binary"
	"errors"
	"net"
	"strconv"

	"github.com/dmachard/go-dnstap-protobuf"
	"github.com/dmachard/go-netutils"
	"google.golang.org/protobuf/proto"
)

func (dm *DNSMessage) ToDNSTap(extended bool) ([]byte, error) {
	if len(dm.DNSTap.Payload) > 0 {
		return dm.DNSTap.Payload, nil
	}

	dt := &dnstap.Dnstap{}
	t := dnstap.Dnstap_MESSAGE
	dt.Identity = []byte(dm.DNSTap.Identity)
	dt.Version = []byte("-")
	dt.Type = &t

	mt := dnstap.Message_Type(dnstap.Message_Type_value[dm.DNSTap.Operation])

	var sf dnstap.SocketFamily
	if ipNet, valid := netutils.IPToInet[dm.NetworkInfo.Family]; valid {
		sf = dnstap.SocketFamily(dnstap.SocketFamily_value[ipNet])
	}
	sp := dnstap.SocketProtocol(dnstap.SocketProtocol_value[dm.NetworkInfo.Protocol])
	tsec := uint64(dm.DNSTap.TimeSec)
	tnsec := uint32(dm.DNSTap.TimeNsec)

	var rport uint32
	var qport uint32
	if dm.NetworkInfo.ResponsePort != "-" {
		if port, err := strconv.Atoi(dm.NetworkInfo.ResponsePort); err != nil {
			return nil, err
		} else if port < 0 || port > 65535 {
			return nil, errors.New("invalid response port value")
		} else {
			rport = uint32(port)
		}
	}

	if dm.NetworkInfo.QueryPort != "-" {
		if port, err := strconv.Atoi(dm.NetworkInfo.QueryPort); err != nil {
			return nil, err
		} else if port < 0 || port > 65535 {
			return nil, errors.New("invalid query port value")
		} else {
			qport = uint32(port)
		}
	}

	msg := &dnstap.Message{Type: &mt}

	msg.SocketFamily = &sf
	msg.SocketProtocol = &sp

	reqIP := net.ParseIP(dm.NetworkInfo.QueryIP)
	if dm.NetworkInfo.Family == netutils.ProtoIPv4 {
		msg.QueryAddress = reqIP.To4()
	} else {
		msg.QueryAddress = reqIP.To16()
	}
	msg.QueryPort = &qport

	rspIP := net.ParseIP(dm.NetworkInfo.ResponseIP)
	if dm.NetworkInfo.Family == netutils.ProtoIPv4 {
		msg.ResponseAddress = rspIP.To4()
	} else {
		msg.ResponseAddress = rspIP.To16()
	}
	msg.ResponsePort = &rport

	if dm.DNS.Type == DNSQuery {
		msg.QueryMessage = dm.DNS.Payload
		msg.QueryTimeSec = &tsec
		msg.QueryTimeNsec = &tnsec
	} else {
		msg.ResponseTimeSec = &tsec
		msg.ResponseTimeNsec = &tnsec
		msg.ResponseMessage = dm.DNS.Payload
	}

	dt.Message = msg

	// add dnstap extra
	if len(dm.DNSTap.Extra) > 0 {
		dt.Extra = []byte(dm.DNSTap.Extra)
	}

	// construct new dnstap field with all transformations
	// the original extra field is kept if exist
	if extended {
		ednstap := &ExtendedDnstap{}

		// add original dnstap value if exist
		if len(dm.DNSTap.Extra) > 0 {
			ednstap.OriginalDnstapExtra = []byte(dm.DNSTap.Extra)
		}

		// add additional tags ?
		if dm.ATags != nil {
			ednstap.Atags = &ExtendedATags{
				Tags: dm.ATags.Tags,
			}
		}

		// add public suffix
		if dm.PublicSuffix != nil {
			ednstap.Normalize = &ExtendedNormalize{
				Tld:         dm.PublicSuffix.QnamePublicSuffix,
				EtldPlusOne: dm.PublicSuffix.QnameEffectiveTLDPlusOne,
			}
		}

		// add filtering
		if dm.Filtering != nil {
			ednstap.Filtering = &ExtendedFiltering{
				SampleRate: uint32(dm.Filtering.SampleRate),
			}
		}

		// add geo
		if dm.Geo != nil {
			ednstap.Geo = &ExtendedGeo{
				City:      dm.Geo.City,
				Continent: dm.Geo.Continent,
				Isocode:   dm.Geo.CountryIsoCode,
				AsNumber:  dm.Geo.AutonomousSystemNumber,
				AsOrg:     dm.Geo.AutonomousSystemOrg,
			}
		}

		extendedData, err := proto.Marshal(ednstap)
		if err != nil {
			return nil, err
		}
		dt.Extra = extendedData
	}

	data, err := proto.Marshal(dt)
	if err != nil {
		return nil, err
	}
	return data, nil
}

var ErrInvalidDNSTapProtobuf = errors.New("invalid dnstap protobuf wire format")

// DecodeDNSTapWire decodes a raw DNSTap Protobuf wire frame directly into a DNSMessage
// with zero heap allocations in the fast path.
func DecodeDNSTapWire(buf []byte, dm *DNSMessage) error {
	var (
		identityBytes    []byte
		versionBytes     []byte
		extraBytes       []byte
		msgType          uint64
		socketFamily     uint64
		socketProtocol   uint64
		queryIP          []byte
		responseIP       []byte
		queryPort        uint32
		responsePort     uint32
		queryTimeSec     uint64
		queryTimeNsec    uint32
		responseTimeSec  uint64
		responseTimeNsec uint32
		queryMessage     []byte
		responseMessage  []byte
		policyType       string
		policyRule       string
		policyAction     string
		policyMatch      string
		policyValue      string
		httpProtocol     string
		queryZone        []byte
	)

	// Scan top-level Dnstap message
	for len(buf) > 0 {
		tagWire, n := binary.Uvarint(buf)
		if n <= 0 {
			return ErrInvalidDNSTapProtobuf
		}
		buf = buf[n:]
		wireType := tagWire & 7
		fieldNum := tagWire >> 3

		switch wireType {
		case 0: // Varint
			_, n := binary.Uvarint(buf)
			if n <= 0 {
				return ErrInvalidDNSTapProtobuf
			}
			buf = buf[n:]
		case 2: // Length-delimited
			length, n := binary.Uvarint(buf)
			if n <= 0 || int(length) > len(buf[n:]) {
				return ErrInvalidDNSTapProtobuf
			}
			val := buf[n : n+int(length)]
			buf = buf[n+int(length):]

			switch fieldNum {
			case 1: // identity
				identityBytes = val
			case 2: // version
				versionBytes = val
			case 3: // extra
				extraBytes = val
			case 14: // message sub-message
				sub := val
				for len(sub) > 0 {
					subTagWire, sn := binary.Uvarint(sub)
					if sn <= 0 {
						return ErrInvalidDNSTapProtobuf
					}
					sub = sub[sn:]
					subWireType := subTagWire & 7
					subFieldNum := subTagWire >> 3

					switch subWireType {
					case 0: // Varint
						v, sn := binary.Uvarint(sub)
						if sn <= 0 {
							return ErrInvalidDNSTapProtobuf
						}
						sub = sub[sn:]

						switch subFieldNum {
						case 1: // type
							msgType = v
						case 2: // socket_family
							socketFamily = v
						case 3: // socket_protocol
							socketProtocol = v
						case 6: // query_port
							queryPort = uint32(v)
						case 7: // response_port
							responsePort = uint32(v)
						case 8: // query_time_sec
							queryTimeSec = v
						case 12: // response_time_sec
							responseTimeSec = v
						case 16: // http_protocol enum
							httpProtocol = dnstap.HttpProtocol(v).String()
						}
					case 2: // Length-delimited
						slen, sn := binary.Uvarint(sub)
						if sn <= 0 || int(slen) > len(sub[sn:]) {
							return ErrInvalidDNSTapProtobuf
						}
						sval := sub[sn : sn+int(slen)]
						sub = sub[sn+int(slen):]

						switch subFieldNum {
						case 4: // query_address
							queryIP = sval
						case 5: // response_address
							responseIP = sval
						case 10: // query_message
							queryMessage = sval
						case 11: // query_zone
							queryZone = sval
						case 14: // response_message
							responseMessage = sval
						case 15: // policy sub-message
							pol := sval
							for len(pol) > 0 {
								ptagWire, pn := binary.Uvarint(pol)
								if pn <= 0 {
									return ErrInvalidDNSTapProtobuf
								}
								pol = pol[pn:]
								pwireType := ptagWire & 7
								pfieldNum := ptagWire >> 3

								switch pwireType {
								case 0: // Varint (Action/Match)
									pv, pn := binary.Uvarint(pol)
									if pn <= 0 {
										return ErrInvalidDNSTapProtobuf
									}
									pol = pol[pn:]
									switch pfieldNum {
									case 3: // action
										policyAction = dnstap.Policy_Action(pv).String()
									case 4: // match
										policyMatch = dnstap.Policy_Match(pv).String()
									}
								case 2: // Length-delimited (Type, Rule, Value)
									plen, pn := binary.Uvarint(pol)
									if pn <= 0 || int(plen) > len(pol[pn:]) {
										return ErrInvalidDNSTapProtobuf
									}
									pval := pol[pn : pn+int(plen)]
									pol = pol[pn+int(plen):]

									switch pfieldNum {
									case 1: // type
										policyType = string(pval)
									case 2: // rule
										policyRule = string(pval)
									case 5: // value
										policyValue = string(pval)
									}
								case 5:
									if len(pol) < 4 {
										return ErrInvalidDNSTapProtobuf
									}
									pol = pol[4:]
								case 1:
									if len(pol) < 8 {
										return ErrInvalidDNSTapProtobuf
									}
									pol = pol[8:]
								default:
									return ErrInvalidDNSTapProtobuf
								}
							}
						}
					case 5: // 32-bit (fixed32 query_time_nsec=9, response_time_nsec=13)
						if len(sub) < 4 {
							return ErrInvalidDNSTapProtobuf
						}
						v := binary.LittleEndian.Uint32(sub[:4])
						sub = sub[4:]
						switch subFieldNum {
						case 9:
							queryTimeNsec = v
						case 13:
							responseTimeNsec = v
						}
					case 1:
						if len(sub) < 8 {
							return ErrInvalidDNSTapProtobuf
						}
						sub = sub[8:]
					default:
						return ErrInvalidDNSTapProtobuf
					}
				}
			}
		case 5:
			if len(buf) < 4 {
				return ErrInvalidDNSTapProtobuf
			}
			buf = buf[4:]
		case 1:
			if len(buf) < 8 {
				return ErrInvalidDNSTapProtobuf
			}
			buf = buf[8:]
		default:
			return ErrInvalidDNSTapProtobuf
		}
	}

	if len(identityBytes) > 0 {
		dm.DNSTap.Identity = string(identityBytes)
	}
	if len(versionBytes) > 0 {
		dm.DNSTap.Version = string(versionBytes)
	}
	if len(extraBytes) > 0 {
		dm.DNSTap.Extra = string(extraBytes)
	}

	// Operation
	switch dnstap.Message_Type(msgType) {
	case dnstap.Message_AUTH_QUERY:
		dm.DNSTap.Operation = "AUTH_QUERY"
	case dnstap.Message_AUTH_RESPONSE:
		dm.DNSTap.Operation = "AUTH_RESPONSE"
	case dnstap.Message_RESOLVER_QUERY:
		dm.DNSTap.Operation = "RESOLVER_QUERY"
	case dnstap.Message_RESOLVER_RESPONSE:
		dm.DNSTap.Operation = "RESOLVER_RESPONSE"
	case dnstap.Message_CLIENT_QUERY:
		dm.DNSTap.Operation = "CLIENT_QUERY"
	case dnstap.Message_CLIENT_RESPONSE:
		dm.DNSTap.Operation = "CLIENT_RESPONSE"
	case dnstap.Message_FORWARDER_QUERY:
		dm.DNSTap.Operation = "FORWARDER_QUERY"
	case dnstap.Message_FORWARDER_RESPONSE:
		dm.DNSTap.Operation = "FORWARDER_RESPONSE"
	case dnstap.Message_STUB_QUERY:
		dm.DNSTap.Operation = "STUB_QUERY"
	case dnstap.Message_STUB_RESPONSE:
		dm.DNSTap.Operation = "STUB_RESPONSE"
	case dnstap.Message_TOOL_QUERY:
		dm.DNSTap.Operation = "TOOL_QUERY"
	case dnstap.Message_TOOL_RESPONSE:
		dm.DNSTap.Operation = "TOOL_RESPONSE"
	default:
		dm.DNSTap.Operation = "UNKNOWN"
	}

	// Family
	switch dnstap.SocketFamily(socketFamily) {
	case dnstap.SocketFamily_INET:
		dm.NetworkInfo.Family = "INET"
	case dnstap.SocketFamily_INET6:
		dm.NetworkInfo.Family = "INET6"
	default:
		dm.NetworkInfo.Family = "UNKNOWN"
	}

	// Protocol
	switch dnstap.SocketProtocol(socketProtocol) {
	case dnstap.SocketProtocol_UDP:
		dm.NetworkInfo.Protocol = "UDP"
	case dnstap.SocketProtocol_TCP:
		dm.NetworkInfo.Protocol = "TCP"
	case dnstap.SocketProtocol_DOT:
		dm.NetworkInfo.Protocol = "DOT"
	case dnstap.SocketProtocol_DOH:
		dm.NetworkInfo.Protocol = "DOH"
	case dnstap.SocketProtocol_DNSCryptUDP:
		dm.NetworkInfo.Protocol = "DNSCryptUDP"
	case dnstap.SocketProtocol_DNSCryptTCP:
		dm.NetworkInfo.Protocol = "DNSCryptTCP"
	case dnstap.SocketProtocol_DOQ:
		dm.NetworkInfo.Protocol = "DOQ"
	default:
		dm.NetworkInfo.Protocol = "UNKNOWN"
	}

	// Addresses and Ports
	if len(queryIP) > 0 {
		dm.NetworkInfo.QueryIP = FastIPv4ToString(queryIP)
	}
	if queryPort > 0 {
		if queryPort == 53 {
			dm.NetworkInfo.QueryPort = "53"
		} else {
			dm.NetworkInfo.QueryPort = strconv.FormatUint(uint64(queryPort), 10)
		}
	}

	if len(responseIP) > 0 {
		dm.NetworkInfo.ResponseIP = FastIPv4ToString(responseIP)
	}
	if responsePort > 0 {
		if responsePort == 53 {
			dm.NetworkInfo.ResponsePort = "53"
		} else {
			dm.NetworkInfo.ResponsePort = strconv.FormatUint(uint64(responsePort), 10)
		}
	}

	// DNS Payload and Timestamps
	op := int(msgType)
	if op%2 == 1 {
		dm.DNS.Payload = queryMessage
		dm.DNS.Length = len(queryMessage)
		dm.DNS.Type = DNSQuery
		dm.DNSTap.TimeSec = int(queryTimeSec)
		dm.DNSTap.TimeNsec = int(queryTimeNsec)
	} else {
		dm.DNS.Payload = responseMessage
		dm.DNS.Length = len(responseMessage)
		dm.DNS.Type = DNSReply
		dm.DNSTap.TimeSec = int(responseTimeSec)
		dm.DNSTap.TimeNsec = int(responseTimeNsec)

		tsQuery := float64(queryTimeSec) + float64(queryTimeNsec)/1e9
		tsReply := float64(responseTimeSec) + float64(responseTimeNsec)/1e9

		if tsQuery != 0 && tsReply >= tsQuery {
			dm.DNSTap.Latency = tsReply - tsQuery
			dm.DNSTap.LatencyMs = int((tsReply - tsQuery) * 1000)
		}
	}

	// Policy and HTTP protocol
	if len(policyType) > 0 {
		dm.DNSTap.PolicyType = policyType
	}
	if len(policyRule) > 0 {
		dm.DNSTap.PolicyRule = policyRule
	}
	if len(policyAction) > 0 {
		dm.DNSTap.PolicyAction = policyAction
	}
	if len(policyMatch) > 0 {
		dm.DNSTap.PolicyMatch = policyMatch
	}
	if len(policyValue) > 0 {
		dm.DNSTap.PolicyValue = policyValue
	}
	if len(httpProtocol) > 0 {
		dm.DNSTap.HttpProtocol = httpProtocol
	}

	// Query Zone
	if len(queryZone) > 0 {
		qz, _, err := ParseLabels(0, queryZone, true)
		if err == nil {
			dm.DNSTap.QueryZone = qz
		}
	}

	return nil
}
