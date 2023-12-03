package dnsutils

import (
	"crypto/tls"
)

const (
	StrUnknown = "UNKNOWN"

	ProgName    = "dnscollector"
	LocalhostIP = "127.0.0.1"
	AnyIP       = "0.0.0.0"
	HTTPOK      = "HTTP/1.1 200 OK\r\n\r\n"

	ValidDomain       = "dnscollector.dev."
	BadDomainLabel    = "ultramegaverytoolonglabel-ultramegaverytoolonglabel-ultramegaverytoolonglabel.dnscollector.dev."
	badLongLabel      = "ultramegaverytoolonglabel-ultramegaverytoolonglabel-"
	BadVeryLongDomain = "ultramegaverytoolonglabel.dnscollector" +
		badLongLabel +
		badLongLabel +
		badLongLabel +
		badLongLabel +
		badLongLabel +
		".dev."

	ModeText     = "text"
	ModeJSON     = "json"
	ModeFlatJSON = "flat-json"
	ModePCAP     = "pcap"
	ModeDNSTap   = "dnstap"

	SASLMechanismPlain = "PLAIN"
	SASLMechanismScram = "SCRAM-SHA-512"

	DNSRcodeNXDomain = "NXDOMAIN"
	DNSRcodeServFail = "SERVFAIL"
	DNSRcodeTimeout  = "TIMEOUT"

	DNSTapOperationQuery = "QUERY"
	DNSTapOperationReply = "REPLY"

	DNSTapClientResponse = "CLIENT_RESPONSE"
	DNSTapClientQuery    = "CLIENT_QUERY"

	DNSTapIdentityTest = "test_id"

	ProtoInet  = "INET"
	ProtoInet6 = "INET6"
	ProtoIPv6  = "IPv6"
	ProtoIPv4  = "IPv4"

	ProtoUDP = "UDP"
	ProtoTCP = "TCP"
	ProtoDoT = "DOT"
	ProtoDoH = "DOH"

	SocketTCP  = "tcp"
	SocketUDP  = "udp"
	SocketUnix = "unix"
	SocketTLS  = "tcp+tls"

	TLSV10 = "1.0"
	TLSV11 = "1.1"
	TLSV12 = "1.2"
	TLSV13 = "1.3"

	CompressGzip   = "gzip"
	CompressSnappy = "snappy"
	CompressLz4    = "lz4"
	CompressZstd   = "ztd"
	CompressNone   = "none"
)

var (
	TLSVersion = map[string]uint16{
		TLSV10: tls.VersionTLS10,
		TLSV11: tls.VersionTLS11,
		TLSV12: tls.VersionTLS12,
		TLSV13: tls.VersionTLS13,
	}

	IPVersion = map[string]string{
		ProtoInet:  ProtoIPv4,
		ProtoInet6: ProtoIPv6,
	}

	IPToInet = map[string]string{
		ProtoIPv4: ProtoInet,
		ProtoIPv6: ProtoInet6,
	}
)
