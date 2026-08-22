package dnsutils

import (
	"bytes"
	"regexp"
	"sync"
	"sync/atomic"
	"time"
)

var (
	DNSQuery      = "QUERY"
	DNSQueryQuiet = "Q"
	DNSReply      = "REPLY"
	DNSReplyQuiet = "R"
)

type DNSAnswer struct {
	Name      string `json:"name"`
	Rdatatype string `json:"rdatatype"`
	Class     string `json:"class"`
	TTL       int    `json:"ttl"`
	Rdata     string `json:"rdata"`
}

type DNSFlags struct {
	QR bool `json:"qr"`
	TC bool `json:"tc"`
	AA bool `json:"aa"`
	RA bool `json:"ra"`
	AD bool `json:"ad"`
	RD bool `json:"rd"`
	CD bool `json:"cd"`
}

type DNSNetInfo struct {
	Family         string `json:"family"`
	Protocol       string `json:"protocol"`
	QueryIP        string `json:"query-ip"`
	QueryPort      string `json:"query-port"`
	ResponseIP     string `json:"response-ip"`
	ResponsePort   string `json:"response-port"`
	IPDefragmented bool   `json:"ip-defragmented"`
	TCPReassembled bool   `json:"tcp-reassembled"`

	QueryIPBuf    [16]byte `json:"-"`
	QueryIPLen    uint8    `json:"-"`
	ResponseIPBuf [16]byte `json:"-"`
	ResponseIPLen uint8    `json:"-"`
}

func (net *DNSNetInfo) GetQueryIP() string {
	if net.QueryIP == "-" && net.QueryIPLen > 0 {
		net.QueryIP = FastIPv4ToString(net.QueryIPBuf[:net.QueryIPLen])
	}
	return net.QueryIP
}

func (net *DNSNetInfo) GetResponseIP() string {
	if net.ResponseIP == "-" && net.ResponseIPLen > 0 {
		net.ResponseIP = FastIPv4ToString(net.ResponseIPBuf[:net.ResponseIPLen])
	}
	return net.ResponseIP
}

func (net *DNSNetInfo) SetQueryIPBytes(ip []byte) {
	n := copy(net.QueryIPBuf[:], ip)
	net.QueryIPLen = uint8(n)
	net.QueryIP = "-"
}

func (net *DNSNetInfo) SetResponseIPBytes(ip []byte) {
	n := copy(net.ResponseIPBuf[:], ip)
	net.ResponseIPLen = uint8(n)
	net.ResponseIP = "-"
}

func (net *DNSNetInfo) WriteQueryIPJSON(buf *bytes.Buffer) {
	switch {
	case net.QueryIPLen > 0:
		buf.WriteByte('"')
		WriteIP(buf, net.QueryIPBuf[:net.QueryIPLen])
		buf.WriteByte('"')
	case net.QueryIP != "-":
		WriteJSONString(buf, net.QueryIP)
	default:
		buf.WriteString(`"-"`)
	}
}

func (net *DNSNetInfo) WriteResponseIPJSON(buf *bytes.Buffer) {
	switch {
	case net.ResponseIPLen > 0:
		buf.WriteByte('"')
		WriteIP(buf, net.ResponseIPBuf[:net.ResponseIPLen])
		buf.WriteByte('"')
	case net.ResponseIP != "-":
		WriteJSONString(buf, net.ResponseIP)
	default:
		buf.WriteString(`"-"`)
	}
}

func (net *DNSNetInfo) WriteQueryIPText(buf *bytes.Buffer) {
	switch {
	case net.QueryIPLen > 0:
		WriteIP(buf, net.QueryIPBuf[:net.QueryIPLen])
	case len(net.QueryIP) > 0:
		buf.WriteString(net.QueryIP)
	default:
		buf.WriteByte('-')
	}
}

func (net *DNSNetInfo) WriteResponseIPText(buf *bytes.Buffer) {
	switch {
	case net.ResponseIPLen > 0:
		WriteIP(buf, net.ResponseIPBuf[:net.ResponseIPLen])
	case len(net.ResponseIP) > 0:
		buf.WriteString(net.ResponseIP)
	default:
		buf.WriteByte('-')
	}
}

type DNSRRs struct {
	Answers     []DNSAnswer `json:"an"`
	Nameservers []DNSAnswer `json:"ns"`
	Records     []DNSAnswer `json:"ar"`
}

type DNS struct {
	Type    string `json:"-"`
	Payload []byte `json:"-"`
	Length  int    `json:"length"`
	ID      int    `json:"id"`
	Opcode  int    `json:"opcode"`
	Rcode   string `json:"rcode"`
	Qname   string `json:"qname"`
	Qclass  string `json:"qclass"`

	QdCount int `json:"qdcount"`
	AnCount int `json:"ancount"`
	NsCount int `json:"nscount"`
	ArCount int `json:"arcount"`

	Qtype           string   `json:"qtype"`
	Flags           DNSFlags `json:"flags"`
	DNSRRs          DNSRRs   `json:"resource-records"`
	MalformedPacket bool     `json:"malformed-packet"`
}

type DNSOption struct {
	Code int    `json:"code"`
	Name string `json:"name"`
	Data string `json:"data"`
}

type DNSExtended struct {
	UDPSize       int         `json:"udp-size"`
	ExtendedRcode int         `json:"rcode"`
	Version       int         `json:"version"`
	Do            int         `json:"dnssec-ok"`
	Z             int         `json:"-"`
	Options       []DNSOption `json:"options"`
}

type DNSTap struct {
	Operation        string  `json:"operation"`
	Identity         string  `json:"identity"`
	Version          string  `json:"version"`
	TimestampRFC3339 string  `json:"timestamp-rfc3339ns"`
	Timestamp        int64   `json:"-"`
	TimeSec          int     `json:"-"`
	TimeNsec         int     `json:"-"`
	Latency          float64 `json:"latency"`
	LatencyMs        int     `json:"latency_ms"`
	Payload          []byte  `json:"-"`
	Extra            string  `json:"extra"`
	PolicyRule       string  `json:"policy-rule"`
	PolicyType       string  `json:"policy-type"`
	PolicyMatch      string  `json:"policy-match"`
	PolicyAction     string  `json:"policy-action"`
	PolicyValue      string  `json:"policy-value"`
	PeerName         string  `json:"peer-name"`
	QueryZone        string  `json:"query-zone"`
	HttpProtocol     string  `json:"http-protocol"`
}

type CollectorPowerDNS struct {
	Tags                  []string          `json:"tags"`
	OriginalRequestSubnet string            `json:"original-request-subnet"`
	AppliedPolicy         string            `json:"applied-policy"`
	AppliedPolicyHit      string            `json:"applied-policy-hit"`
	AppliedPolicyKind     string            `json:"applied-policy-kind"`
	AppliedPolicyTrigger  string            `json:"applied-policy-trigger"`
	AppliedPolicyType     string            `json:"applied-policy-type"`
	Metadata              map[string]string `json:"metadata"`
	HTTPVersion           string            `json:"http-version"`
	MessageID             string            `json:"message-id"`
	InitialRequestorID    string            `json:"initial-requestor-id"`
	RequestorID           string            `json:"requestor-id"`
	DeviceName            string            `json:"device-name"`
	DeviceID              string            `json:"device-id"`
	OpenTelemetryData     string            `json:"opentelemetry-data"`
	EdnsVersion           string            `json:"edns-version"`
}

type LoggerOpenTelemetry struct {
	TraceID string `json:"trace-id"`
}

type TransformDNSGeo struct {
	City                   string  `json:"city"`
	Continent              string  `json:"continent"`
	CountryIsoCode         string  `json:"country-isocode"`
	AutonomousSystemNumber string  `json:"as-number"`
	AutonomousSystemOrg    string  `json:"as-owner"`
	Latitude               float64 `json:"lat"`
	Longitude              float64 `json:"lon"`
}

type TransformSuspicious struct {
	Score                 float64 `json:"score"`
	MalformedPacket       bool    `json:"malformed-pkt"`
	LargePacket           bool    `json:"large-pkt"`
	LongDomain            bool    `json:"long-domain"`
	SlowDomain            bool    `json:"slow-domain"`
	UnallowedChars        bool    `json:"unallowed-chars"`
	UncommonQtypes        bool    `json:"uncommon-qtypes"`
	ExcessiveNumberLabels bool    `json:"excessive-number-labels"`
	Domain                string  `json:"domain,omitempty"`
}

type TransformPublicSuffix struct {
	QnamePublicSuffix        string `json:"tld"`
	QnameEffectiveTLDPlusOne string `json:"etld+1"`
	ManagedByICANN           bool   `json:"managed-icann"`
}

type TransformExtracted struct {
	Base64Payload []byte                 `json:"dns_payload"`
	Base64Fields  map[string]interface{} `json:"base64_fields,omitempty"`
	HexFields     map[string]interface{} `json:"hex_fields,omitempty"`
}

type TransformReducer struct {
	Occurrences      int `json:"occurrences"`
	CumulativeLength int `json:"cumulative-length"`
}

type TransformFiltering struct {
	SampleRate int `json:"sample-rate"`
}

type TransformML struct {
	Entropy               float64 `json:"entropy"`  // Entropy of query name
	Length                int     `json:"length"`   // Length of domain
	Labels                int     `json:"labels"`   // Number of labels in the query name  separated by dots
	Digits                int     `json:"digits"`   // Count of numerical characters
	Lowers                int     `json:"lowers"`   // Count of lowercase characters
	Uppers                int     `json:"uppers"`   // Count of uppercase characters
	Specials              int     `json:"specials"` // Number of special characters; special characters such as dash, underscore, equal sign,...
	Others                int     `json:"others"`
	RatioDigits           float64 `json:"ratio-digits"`
	RatioLetters          float64 `json:"ratio-letters"`
	RatioSpecials         float64 `json:"ratio-specials"`
	RatioOthers           float64 `json:"ratio-others"`
	ConsecutiveChars      int     `json:"consecutive-chars"`
	ConsecutiveVowels     int     `json:"consecutive-vowels"`
	ConsecutiveDigits     int     `json:"consecutive-digits"`
	ConsecutiveConsonants int     `json:"consecutive-consonants"`
	Size                  int     `json:"size"`
	Occurrences           int     `json:"occurrences"`
	UncommonQtypes        int     `json:"uncommon-qtypes"`
}

type TransformATags struct {
	Tags []string `json:"tags"`
}

type TransformRest struct {
	Failed   bool   `json:"failed"`
	Response string `json:"response"`
}

type RelabelingRule struct {
	Regex       *regexp.Regexp
	Replacement string
	Action      string
}

type TransformRelabeling struct {
	Rules []RelabelingRule
}

type DNSMessage struct {
	NetworkInfo     DNSNetInfo             `json:"network"`
	DNS             DNS                    `json:"dns"`
	EDNS            DNSExtended            `json:"edns"`
	DNSTap          DNSTap                 `json:"dnstap"`
	PowerDNS        *CollectorPowerDNS     `json:"powerdns,omitempty"`
	OpenTelemetry   *LoggerOpenTelemetry   `json:"opentelemetry,omitempty"`
	Geo             *TransformDNSGeo       `json:"geoip,omitempty"`
	Suspicious      *TransformSuspicious   `json:"suspicious,omitempty"`
	PublicSuffix    *TransformPublicSuffix `json:"publicsuffix,omitempty"`
	Extracted       *TransformExtracted    `json:"extracted,omitempty"`
	Reducer         *TransformReducer      `json:"reducer,omitempty"`
	MachineLearning *TransformML           `json:"ml,omitempty"`
	Filtering       *TransformFiltering    `json:"filtering,omitempty"`
	ATags           *TransformATags        `json:"atags,omitempty"`
	Rest            *TransformRest         `json:"rest,omitempty"`
	Relabeling      *TransformRelabeling   `json:"-"`
	RefCount        int32                  `json:"-"`
}

var DNSMessagePool = sync.Pool{
	New: func() interface{} {
		dm := &DNSMessage{}
		dm.Init()
		return dm
	},
}

type DNSMessageBatch struct {
	Messages []*DNSMessage
	RefCount int32
}

var DNSMessageBatchPool = sync.Pool{
	New: func() interface{} {
		return &DNSMessageBatch{
			Messages: make([]*DNSMessage, 0, 64),
		}
	},
}

func AcquireDNSMessageBatch(capacity int) *DNSMessageBatch {
	batch := DNSMessageBatchPool.Get().(*DNSMessageBatch)
	if capacity > cap(batch.Messages) {
		batch.Messages = make([]*DNSMessage, 0, capacity)
	} else {
		batch.Messages = batch.Messages[:0]
	}
	atomic.StoreInt32(&batch.RefCount, 1)
	return batch
}

func NewDNSMessageBatchFromMessage(dm *DNSMessage) *DNSMessageBatch {
	b := AcquireDNSMessageBatch(1)
	b.Messages = append(b.Messages, dm)
	return b
}

func (b *DNSMessageBatch) Retain(n int32) {
	if n > 0 {
		atomic.AddInt32(&b.RefCount, n)
	}
}

func (b *DNSMessageBatch) Release() {
	if b == nil {
		return
	}
	if atomic.AddInt32(&b.RefCount, -1) == 0 {
		for _, dm := range b.Messages {
			dm.Release()
		}
		b.Messages = b.Messages[:0]
		DNSMessageBatchPool.Put(b)
	}
}

func AcquireDNSMessage() *DNSMessage {
	dm := DNSMessagePool.Get().(*DNSMessage)
	atomic.StoreInt32(&dm.RefCount, 1)
	return dm
}

func (dm *DNSMessage) Retain(n int32) {
	if n > 0 {
		atomic.AddInt32(&dm.RefCount, n)
	}
}

func (dm *DNSMessage) Release() {
	if dm == nil {
		return
	}
	if atomic.AddInt32(&dm.RefCount, -1) == 0 {
		dm.Reset()
		DNSMessagePool.Put(dm)
	}
}

func (dm *DNSMessage) GetTimestampRFC3339() string {
	if len(dm.DNSTap.TimestampRFC3339) > 0 && dm.DNSTap.TimestampRFC3339 != "-" {
		return dm.DNSTap.TimestampRFC3339
	}
	if dm.DNSTap.Timestamp > 0 {
		dm.DNSTap.TimestampRFC3339 = time.Unix(0, dm.DNSTap.Timestamp).UTC().Format(time.RFC3339Nano)
		return dm.DNSTap.TimestampRFC3339
	}
	return "-"
}

func (dm *DNSMessage) Reset() {
	dm.PowerDNS = nil
	dm.OpenTelemetry = nil
	dm.Geo = nil
	dm.Suspicious = nil
	dm.PublicSuffix = nil
	dm.Extracted = nil
	dm.Reducer = nil
	dm.MachineLearning = nil
	dm.Filtering = nil
	dm.ATags = nil
	dm.Rest = nil
	dm.Relabeling = nil
	dm.Init()
}

var (
	emptyAnswers = []DNSAnswer{}
	emptyOptions = []DNSOption{}
)

func (dm *DNSMessage) Init() {
	if dm.DNS.DNSRRs.Answers != nil {
		dm.DNS.DNSRRs.Answers = dm.DNS.DNSRRs.Answers[:0]
	} else {
		dm.DNS.DNSRRs.Answers = emptyAnswers
	}
	if dm.DNS.DNSRRs.Nameservers != nil {
		dm.DNS.DNSRRs.Nameservers = dm.DNS.DNSRRs.Nameservers[:0]
	} else {
		dm.DNS.DNSRRs.Nameservers = emptyAnswers
	}
	if dm.DNS.DNSRRs.Records != nil {
		dm.DNS.DNSRRs.Records = dm.DNS.DNSRRs.Records[:0]
	} else {
		dm.DNS.DNSRRs.Records = emptyAnswers
	}
	if dm.EDNS.Options != nil {
		dm.EDNS.Options = dm.EDNS.Options[:0]
	} else {
		dm.EDNS.Options = emptyOptions
	}

	dm.NetworkInfo = DNSNetInfo{
		Family:         "-",
		Protocol:       "-",
		QueryIP:        "-",
		QueryPort:      "-",
		ResponseIP:     "-",
		ResponsePort:   "-",
		IPDefragmented: false,
		TCPReassembled: false,
	}

	dm.DNSTap = DNSTap{
		Operation:        "-",
		Identity:         "-",
		Version:          "-",
		TimestampRFC3339: "-",
		Extra:            "-",
		PolicyRule:       "-",
		PolicyType:       "-",
		PolicyMatch:      "-",
		PolicyAction:     "-",
		PolicyValue:      "-",
		PeerName:         "-",
		QueryZone:        "-",
		HttpProtocol:     "-",
	}

	answers := dm.DNS.DNSRRs.Answers
	nameservers := dm.DNS.DNSRRs.Nameservers
	records := dm.DNS.DNSRRs.Records

	dm.DNS = DNS{
		Type:            "-",
		MalformedPacket: false,
		Rcode:           "-",
		Qtype:           "-",
		Qname:           "-",
		Qclass:          "-",
		DNSRRs:          DNSRRs{Answers: answers, Nameservers: nameservers, Records: records},
	}

	options := dm.EDNS.Options
	dm.EDNS = DNSExtended{
		Options: options,
	}
}

func (dm *DNSMessage) InitTransforms() {
	if dm.ATags == nil {
		dm.ATags = &TransformATags{}
	} else {
		*dm.ATags = TransformATags{}
	}
	if dm.Rest == nil {
		dm.Rest = &TransformRest{}
	} else {
		*dm.Rest = TransformRest{}
	}
	if dm.Filtering == nil {
		dm.Filtering = &TransformFiltering{}
	} else {
		*dm.Filtering = TransformFiltering{}
	}
	if dm.MachineLearning == nil {
		dm.MachineLearning = &TransformML{}
	} else {
		*dm.MachineLearning = TransformML{}
	}
	if dm.Reducer == nil {
		dm.Reducer = &TransformReducer{}
	} else {
		*dm.Reducer = TransformReducer{}
	}
	if dm.Extracted == nil {
		dm.Extracted = &TransformExtracted{}
	} else {
		*dm.Extracted = TransformExtracted{}
	}
	if dm.PublicSuffix == nil {
		dm.PublicSuffix = &TransformPublicSuffix{}
	} else {
		*dm.PublicSuffix = TransformPublicSuffix{}
	}
	if dm.Suspicious == nil {
		dm.Suspicious = &TransformSuspicious{}
	} else {
		*dm.Suspicious = TransformSuspicious{}
	}
	if dm.Geo == nil {
		dm.Geo = &TransformDNSGeo{}
	} else {
		*dm.Geo = TransformDNSGeo{}
	}
	if dm.Relabeling == nil {
		dm.Relabeling = &TransformRelabeling{}
	} else {
		*dm.Relabeling = TransformRelabeling{}
	}
	if dm.PowerDNS == nil {
		dm.PowerDNS = &CollectorPowerDNS{}
	} else {
		*dm.PowerDNS = CollectorPowerDNS{}
	}
	if dm.OpenTelemetry == nil {
		dm.OpenTelemetry = &LoggerOpenTelemetry{}
	} else {
		*dm.OpenTelemetry = LoggerOpenTelemetry{}
	}
}
