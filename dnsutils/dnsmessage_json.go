package dnsutils

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"sync"
)

var jsonBufferPool = sync.Pool{
	New: func() interface{} {
		return bytes.NewBuffer(make([]byte, 0, 512))
	},
}

func (dm *DNSMessage) ToJSON() string {
	dm.GetTimestampRFC3339()
	buffer := jsonBufferPool.Get().(*bytes.Buffer)
	buffer.Reset()
	defer jsonBufferPool.Put(buffer)

	json.NewEncoder(buffer).Encode(dm)
	return buffer.String()
}

func (dm *DNSMessage) ToFlatJSON() (string, error) {
	dm.GetTimestampRFC3339()
	buffer := jsonBufferPool.Get().(*bytes.Buffer)
	buffer.Reset()
	defer jsonBufferPool.Put(buffer)

	if dm.Relabeling != nil {
		flat, err := dm.Flatten()
		if err != nil {
			return "", err
		}
		json.NewEncoder(buffer).Encode(flat)
		return buffer.String(), nil
	}

	dm.EncodeFlatJSON(buffer)
	buffer.WriteByte('\n')
	return buffer.String(), nil
}

func (dm *DNSMessage) EncodeFlatJSON(buffer *bytes.Buffer) {
	buffer.WriteByte('{')
	first := true

	writeKey := func(key string) {
		if !first {
			buffer.WriteByte(',')
		}
		first = false
		buffer.WriteByte('"')
		buffer.WriteString(key)
		buffer.WriteString(`":`)
	}

	writeBool := func(key string, val bool) {
		writeKey(key)
		if val {
			buffer.WriteString("true")
		} else {
			buffer.WriteString("false")
		}
	}

	writeInt := func(key string, val int) {
		writeKey(key)
		buffer.WriteString(strconv.Itoa(val))
	}

	writeFloat := func(key string, val float64) {
		writeKey(key)
		buffer.WriteString(strconv.FormatFloat(val, 'f', -1, 64))
	}

	writeString := func(key string, val string) {
		writeKey(key)
		WriteJSONString(buffer, val)
	}

	// Boolean flags
	writeBool("dns.flags.aa", dm.DNS.Flags.AA)
	writeBool("dns.flags.ad", dm.DNS.Flags.AD)
	writeBool("dns.flags.cd", dm.DNS.Flags.CD)
	writeBool("dns.flags.qr", dm.DNS.Flags.QR)
	writeBool("dns.flags.ra", dm.DNS.Flags.RA)
	writeBool("dns.flags.rd", dm.DNS.Flags.RD)
	writeBool("dns.flags.tc", dm.DNS.Flags.TC)

	// Ints & strings
	writeInt("dns.ancount", dm.DNS.AnCount)
	writeInt("dns.arcount", dm.DNS.ArCount)
	writeInt("dns.id", dm.DNS.ID)
	writeInt("dns.length", dm.DNS.Length)
	writeBool("dns.malformed-packet", dm.DNS.MalformedPacket)
	writeInt("dns.nscount", dm.DNS.NsCount)
	writeInt("dns.opcode", dm.DNS.Opcode)
	writeString("dns.qclass", dm.DNS.Qclass)
	writeInt("dns.qdcount", dm.DNS.QdCount)
	writeString("dns.qname", dm.DNS.Qname)
	writeString("dns.qtype", dm.DNS.Qtype)
	writeString("dns.rcode", dm.DNS.Rcode)

	// Resource Records (AN, AR, NS)
	buildRRFields := func(rrs []DNSAnswer) (names, rdatatypes, rdatas, ttls, classes string) {
		if len(rrs) == 0 {
			return "-", "-", "-", "-", "-"
		}
		var sbN, sbT, sbD, sbL, sbC strings.Builder
		for i, rr := range rrs {
			if i > 0 {
				sbN.WriteByte('|')
				sbT.WriteByte('|')
				sbD.WriteByte('|')
				sbL.WriteByte('|')
				sbC.WriteByte('|')
			}
			sbN.WriteString(rr.Name)
			sbT.WriteString(rr.Rdatatype)
			sbD.WriteString(rr.Rdata)
			sbL.WriteString(strconv.Itoa(rr.TTL))
			sbC.WriteString(rr.Class)
		}
		return sbN.String(), sbT.String(), sbD.String(), sbL.String(), sbC.String()
	}

	anN, anT, anD, anL, anC := buildRRFields(dm.DNS.DNSRRs.Answers)
	writeString("dns.resource-records.an.classes", anC)
	writeString("dns.resource-records.an.names", anN)
	writeString("dns.resource-records.an.rdatas", anD)
	writeString("dns.resource-records.an.rdatatypes", anT)
	writeString("dns.resource-records.an.ttls", anL)

	arN, arT, arD, arL, arC := buildRRFields(dm.DNS.DNSRRs.Records)
	writeString("dns.resource-records.ar.classes", arC)
	writeString("dns.resource-records.ar.names", arN)
	writeString("dns.resource-records.ar.rdatas", arD)
	writeString("dns.resource-records.ar.rdatatypes", arT)
	writeString("dns.resource-records.ar.ttls", arL)

	nsN, nsT, nsD, nsL, nsC := buildRRFields(dm.DNS.DNSRRs.Nameservers)
	writeString("dns.resource-records.ns.classes", nsC)
	writeString("dns.resource-records.ns.names", nsN)
	writeString("dns.resource-records.ns.rdatas", nsD)
	writeString("dns.resource-records.ns.rdatatypes", nsT)
	writeString("dns.resource-records.ns.ttls", nsL)

	// DNSTap fields
	writeString("dnstap.extra", dm.DNSTap.Extra)
	writeString("dnstap.identity", dm.DNSTap.Identity)
	writeFloat("dnstap.latency", dm.DNSTap.Latency)
	writeInt("dnstap.latency_ms", dm.DNSTap.LatencyMs)
	writeString("dnstap.operation", dm.DNSTap.Operation)
	writeString("dnstap.peer-name", dm.DNSTap.PeerName)
	writeString("dnstap.policy-action", dm.DNSTap.PolicyAction)
	writeString("dnstap.policy-match", dm.DNSTap.PolicyMatch)
	writeString("dnstap.policy-rule", dm.DNSTap.PolicyRule)
	writeString("dnstap.policy-type", dm.DNSTap.PolicyType)
	writeString("dnstap.policy-value", dm.DNSTap.PolicyValue)
	writeString("dnstap.query-zone", dm.DNSTap.QueryZone)
	writeString("dnstap.timestamp-rfc3339ns", dm.DNSTap.TimestampRFC3339)
	writeString("dnstap.version", dm.DNSTap.Version)

	// EDNS
	writeInt("edns.dnssec-ok", dm.EDNS.Do)
	if len(dm.EDNS.Options) == 0 {
		writeString("edns.options.codes", "-")
		writeString("edns.options.datas", "-")
		writeString("edns.options.names", "-")
	} else {
		var sbCodes, sbDatas, sbNames strings.Builder
		for i, opt := range dm.EDNS.Options {
			if i > 0 {
				sbCodes.WriteByte('|')
				sbDatas.WriteByte('|')
				sbNames.WriteByte('|')
			}
			sbCodes.WriteString(strconv.Itoa(opt.Code))
			sbDatas.WriteString(opt.Data)
			sbNames.WriteString(opt.Name)
		}
		writeString("edns.options.codes", sbCodes.String())
		writeString("edns.options.datas", sbDatas.String())
		writeString("edns.options.names", sbNames.String())
	}
	writeInt("edns.optionscount", len(dm.EDNS.Options))
	writeInt("edns.rcode", dm.EDNS.ExtendedRcode)
	writeInt("edns.udp-size", dm.EDNS.UDPSize)
	writeInt("edns.version", dm.EDNS.Version)

	// NetworkInfo
	writeString("network.family", dm.NetworkInfo.Family)
	writeBool("network.ip-defragmented", dm.NetworkInfo.IPDefragmented)
	writeString("network.protocol", dm.NetworkInfo.Protocol)
	writeString("network.query-ip", dm.NetworkInfo.QueryIP)
	writeString("network.query-port", dm.NetworkInfo.QueryPort)
	writeString("network.response-ip", dm.NetworkInfo.ResponseIP)
	writeString("network.response-port", dm.NetworkInfo.ResponsePort)
	writeBool("network.tcp-reassembled", dm.NetworkInfo.TCPReassembled)

	// Optional Transformer fields
	if dm.Geo != nil {
		writeString("geoip.as-number", dm.Geo.AutonomousSystemNumber)
		writeString("geoip.as-owner", dm.Geo.AutonomousSystemOrg)
		writeString("geoip.city", dm.Geo.City)
		writeString("geoip.continent", dm.Geo.Continent)
		writeString("geoip.country-isocode", dm.Geo.CountryIsoCode)
		writeFloat("geoip.lat", dm.Geo.Latitude)
		writeFloat("geoip.lon", dm.Geo.Longitude)
	}

	if dm.Suspicious != nil {
		writeString("suspicious.domain", dm.Suspicious.Domain)
		writeBool("suspicious.excessive-number-labels", dm.Suspicious.ExcessiveNumberLabels)
		writeBool("suspicious.large-pkt", dm.Suspicious.LargePacket)
		writeBool("suspicious.long-domain", dm.Suspicious.LongDomain)
		writeBool("suspicious.malformed-pkt", dm.Suspicious.MalformedPacket)
		writeFloat("suspicious.score", dm.Suspicious.Score)
		writeBool("suspicious.slow-domain", dm.Suspicious.SlowDomain)
		writeBool("suspicious.unallowed-chars", dm.Suspicious.UnallowedChars)
		writeBool("suspicious.uncommon-qtypes", dm.Suspicious.UncommonQtypes)
	}

	if dm.PublicSuffix != nil {
		writeString("publicsuffix.etld+1", dm.PublicSuffix.QnameEffectiveTLDPlusOne)
		writeBool("publicsuffix.managed-icann", dm.PublicSuffix.ManagedByICANN)
		writeString("publicsuffix.tld", dm.PublicSuffix.QnamePublicSuffix)
	}

	if dm.Extracted != nil {
		writeString("extracted.dns_payload", string(dm.Extracted.Base64Payload))
		for k, v := range dm.Extracted.Base64Fields {
			writeString("extracted.base64_fields."+k, fmt.Sprintf("%v", v))
		}
		for k, v := range dm.Extracted.HexFields {
			writeString("extracted.hex_fields."+k, fmt.Sprintf("%v", v))
		}
	}

	if dm.Reducer != nil {
		writeInt("reducer.cumulative-length", dm.Reducer.CumulativeLength)
		writeInt("reducer.occurrences", dm.Reducer.Occurrences)
	}

	if dm.Filtering != nil {
		writeInt("filtering.sample-rate", dm.Filtering.SampleRate)
	}

	if dm.MachineLearning != nil {
		writeInt("ml.consecutive-chars", dm.MachineLearning.ConsecutiveChars)
		writeInt("ml.consecutive-consonants", dm.MachineLearning.ConsecutiveConsonants)
		writeInt("ml.consecutive-digits", dm.MachineLearning.ConsecutiveDigits)
		writeInt("ml.consecutive-vowels", dm.MachineLearning.ConsecutiveVowels)
		writeInt("ml.digits", dm.MachineLearning.Digits)
		writeFloat("ml.entropy", dm.MachineLearning.Entropy)
		writeInt("ml.labels", dm.MachineLearning.Labels)
		writeInt("ml.length", dm.MachineLearning.Length)
		writeInt("ml.lowers", dm.MachineLearning.Lowers)
		writeInt("ml.occurrences", dm.MachineLearning.Occurrences)
		writeInt("ml.others", dm.MachineLearning.Others)
		writeFloat("ml.ratio-digits", dm.MachineLearning.RatioDigits)
		writeFloat("ml.ratio-letters", dm.MachineLearning.RatioLetters)
		writeFloat("ml.ratio-others", dm.MachineLearning.RatioOthers)
		writeFloat("ml.ratio-specials", dm.MachineLearning.RatioSpecials)
		writeInt("ml.size", dm.MachineLearning.Size)
		writeInt("ml.specials", dm.MachineLearning.Specials)
		writeInt("ml.uncommon-qtypes", dm.MachineLearning.UncommonQtypes)
		writeInt("ml.uppers", dm.MachineLearning.Uppers)
	}

	if dm.ATags != nil {
		if len(dm.ATags.Tags) == 0 {
			writeString("atags.tags", "-")
		}
		for i, tag := range dm.ATags.Tags {
			writeString("atags.tags."+strconv.Itoa(i), tag)
		}
	}

	if dm.PowerDNS != nil {
		writeString("powerdns.applied-policy", dm.PowerDNS.AppliedPolicy)
		writeString("powerdns.applied-policy-hit", dm.PowerDNS.AppliedPolicyHit)
		writeString("powerdns.applied-policy-kind", dm.PowerDNS.AppliedPolicyKind)
		writeString("powerdns.applied-policy-trigger", dm.PowerDNS.AppliedPolicyTrigger)
		writeString("powerdns.applied-policy-type", dm.PowerDNS.AppliedPolicyType)
		writeString("powerdns.device-id", dm.PowerDNS.DeviceID)
		writeString("powerdns.device-name", dm.PowerDNS.DeviceName)
		writeString("powerdns.edns-version", dm.PowerDNS.EdnsVersion)
		writeString("powerdns.http-version", dm.PowerDNS.HTTPVersion)
		writeString("powerdns.initial-requestor-id", dm.PowerDNS.InitialRequestorID)
		writeString("powerdns.message-id", dm.PowerDNS.MessageID)
		for mk, mv := range dm.PowerDNS.Metadata {
			writeString("powerdns.metadata."+mk, fmt.Sprintf("%v", mv))
		}
		writeString("powerdns.opentelemetry-data", dm.PowerDNS.OpenTelemetryData)
		writeString("powerdns.original-request-subnet", dm.PowerDNS.OriginalRequestSubnet)
		writeString("powerdns.requestor-id", dm.PowerDNS.RequestorID)
		if len(dm.PowerDNS.Tags) == 0 {
			writeString("powerdns.tags", "-")
		}
		for i, tag := range dm.PowerDNS.Tags {
			writeString("powerdns.tags."+strconv.Itoa(i), tag)
		}
	}

	buffer.WriteByte('}')
}

func (dm *DNSMessage) Flatten() (map[string]interface{}, error) {
	dnsFields := make(map[string]interface{}, 80)
	dnsFields["dns.flags.aa"] = dm.DNS.Flags.AA
	dnsFields["dns.flags.ad"] = dm.DNS.Flags.AD
	dnsFields["dns.flags.qr"] = dm.DNS.Flags.QR
	dnsFields["dns.flags.ra"] = dm.DNS.Flags.RA
	dnsFields["dns.flags.tc"] = dm.DNS.Flags.TC
	dnsFields["dns.flags.rd"] = dm.DNS.Flags.RD
	dnsFields["dns.flags.cd"] = dm.DNS.Flags.CD
	dnsFields["dns.length"] = dm.DNS.Length
	dnsFields["dns.malformed-packet"] = dm.DNS.MalformedPacket
	dnsFields["dns.id"] = dm.DNS.ID
	dnsFields["dns.opcode"] = dm.DNS.Opcode
	dnsFields["dns.qname"] = dm.DNS.Qname
	dnsFields["dns.qtype"] = dm.DNS.Qtype
	dnsFields["dns.qclass"] = dm.DNS.Qclass
	dnsFields["dns.rcode"] = dm.DNS.Rcode
	dnsFields["dns.qdcount"] = dm.DNS.QdCount
	dnsFields["dns.ancount"] = dm.DNS.AnCount
	dnsFields["dns.arcount"] = dm.DNS.ArCount
	dnsFields["dns.nscount"] = dm.DNS.NsCount
	dnsFields["dnstap.identity"] = dm.DNSTap.Identity
	dnsFields["dnstap.latency"] = dm.DNSTap.Latency
	dnsFields["dnstap.latency_ms"] = dm.DNSTap.LatencyMs
	dnsFields["dnstap.operation"] = dm.DNSTap.Operation
	dnsFields["dnstap.timestamp-rfc3339ns"] = dm.DNSTap.TimestampRFC3339
	dnsFields["dnstap.version"] = dm.DNSTap.Version
	dnsFields["dnstap.extra"] = dm.DNSTap.Extra
	dnsFields["dnstap.policy-rule"] = dm.DNSTap.PolicyRule
	dnsFields["dnstap.policy-type"] = dm.DNSTap.PolicyType
	dnsFields["dnstap.policy-action"] = dm.DNSTap.PolicyAction
	dnsFields["dnstap.policy-match"] = dm.DNSTap.PolicyMatch
	dnsFields["dnstap.policy-value"] = dm.DNSTap.PolicyValue
	dnsFields["dnstap.peer-name"] = dm.DNSTap.PeerName
	dnsFields["dnstap.query-zone"] = dm.DNSTap.QueryZone
	dnsFields["edns.optionscount"] = len(dm.EDNS.Options)
	dnsFields["edns.dnssec-ok"] = dm.EDNS.Do
	dnsFields["edns.rcode"] = dm.EDNS.ExtendedRcode
	dnsFields["edns.udp-size"] = dm.EDNS.UDPSize
	dnsFields["edns.version"] = dm.EDNS.Version
	dnsFields["network.family"] = dm.NetworkInfo.Family
	dnsFields["network.ip-defragmented"] = dm.NetworkInfo.IPDefragmented
	dnsFields["network.protocol"] = dm.NetworkInfo.Protocol
	dnsFields["network.query-ip"] = dm.NetworkInfo.QueryIP
	dnsFields["network.query-port"] = dm.NetworkInfo.QueryPort
	dnsFields["network.response-ip"] = dm.NetworkInfo.ResponseIP
	dnsFields["network.response-port"] = dm.NetworkInfo.ResponsePort
	dnsFields["network.tcp-reassembled"] = dm.NetworkInfo.TCPReassembled

	// Helper function to build RR fields
	buildRRFields := func(rrs []DNSAnswer) (names, rdatatypes, rdatas, ttls, classes string) {
		if len(rrs) == 0 {
			return "-", "-", "-", "-", "-"
		}
		var sbN, sbT, sbD, sbL, sbC strings.Builder
		for i, rr := range rrs {
			if i > 0 {
				sbN.WriteByte('|')
				sbT.WriteByte('|')
				sbD.WriteByte('|')
				sbL.WriteByte('|')
				sbC.WriteByte('|')
			}
			sbN.WriteString(rr.Name)
			sbT.WriteString(rr.Rdatatype)
			sbD.WriteString(rr.Rdata)
			sbL.WriteString(strconv.Itoa(rr.TTL))
			sbC.WriteString(rr.Class)
		}
		return sbN.String(), sbT.String(), sbD.String(), sbL.String(), sbC.String()
	}

	// AN
	anNames, anTypes, anDatas, anTTLs, anClasses := buildRRFields(dm.DNS.DNSRRs.Answers)
	dnsFields["dns.resource-records.an.names"] = anNames
	dnsFields["dns.resource-records.an.rdatatypes"] = anTypes
	dnsFields["dns.resource-records.an.rdatas"] = anDatas
	dnsFields["dns.resource-records.an.ttls"] = anTTLs
	dnsFields["dns.resource-records.an.classes"] = anClasses

	// NS
	nsNames, nsTypes, nsDatas, nsTTLs, nsClasses := buildRRFields(dm.DNS.DNSRRs.Nameservers)
	dnsFields["dns.resource-records.ns.names"] = nsNames
	dnsFields["dns.resource-records.ns.rdatatypes"] = nsTypes
	dnsFields["dns.resource-records.ns.rdatas"] = nsDatas
	dnsFields["dns.resource-records.ns.ttls"] = nsTTLs
	dnsFields["dns.resource-records.ns.classes"] = nsClasses

	// AR
	arNames, arTypes, arDatas, arTTLs, arClasses := buildRRFields(dm.DNS.DNSRRs.Records)
	dnsFields["dns.resource-records.ar.names"] = arNames
	dnsFields["dns.resource-records.ar.rdatatypes"] = arTypes
	dnsFields["dns.resource-records.ar.rdatas"] = arDatas
	dnsFields["dns.resource-records.ar.ttls"] = arTTLs
	dnsFields["dns.resource-records.ar.classes"] = arClasses

	// Add EDNSoptions fields: "edns.options.0.code": 10,
	if len(dm.EDNS.Options) == 0 {
		dnsFields["edns.options.codes"] = "-"
		dnsFields["edns.options.datas"] = "-"
		dnsFields["edns.options.names"] = "-"
	} else {
		var sbCodes, sbDatas, sbNames strings.Builder
		for i, opt := range dm.EDNS.Options {
			if i > 0 {
				sbCodes.WriteByte('|')
				sbDatas.WriteByte('|')
				sbNames.WriteByte('|')
			}
			sbCodes.WriteString(strconv.Itoa(opt.Code))
			sbDatas.WriteString(opt.Data)
			sbNames.WriteString(opt.Name)
		}
		dnsFields["edns.options.codes"] = sbCodes.String()
		dnsFields["edns.options.datas"] = sbDatas.String()
		dnsFields["edns.options.names"] = sbNames.String()
	}

	// Add TransformDNSGeo fields
	if dm.Geo != nil {
		dnsFields["geoip.city"] = dm.Geo.City
		dnsFields["geoip.continent"] = dm.Geo.Continent
		dnsFields["geoip.country-isocode"] = dm.Geo.CountryIsoCode
		dnsFields["geoip.as-number"] = dm.Geo.AutonomousSystemNumber
		dnsFields["geoip.as-owner"] = dm.Geo.AutonomousSystemOrg
		dnsFields["geoip.lat"] = dm.Geo.Latitude
		dnsFields["geoip.lon"] = dm.Geo.Longitude
	}

	// Add TransformSuspicious fields
	if dm.Suspicious != nil {
		dnsFields["suspicious.score"] = dm.Suspicious.Score
		dnsFields["suspicious.malformed-pkt"] = dm.Suspicious.MalformedPacket
		dnsFields["suspicious.large-pkt"] = dm.Suspicious.LargePacket
		dnsFields["suspicious.long-domain"] = dm.Suspicious.LongDomain
		dnsFields["suspicious.slow-domain"] = dm.Suspicious.SlowDomain
		dnsFields["suspicious.unallowed-chars"] = dm.Suspicious.UnallowedChars
		dnsFields["suspicious.uncommon-qtypes"] = dm.Suspicious.UncommonQtypes
		dnsFields["suspicious.excessive-number-labels"] = dm.Suspicious.ExcessiveNumberLabels
		dnsFields["suspicious.domain"] = dm.Suspicious.Domain
	}

	// Add TransformPublicSuffix fields
	if dm.PublicSuffix != nil {
		dnsFields["publicsuffix.tld"] = dm.PublicSuffix.QnamePublicSuffix
		dnsFields["publicsuffix.etld+1"] = dm.PublicSuffix.QnameEffectiveTLDPlusOne
		dnsFields["publicsuffix.managed-icann"] = dm.PublicSuffix.ManagedByICANN
	}

	// Add TransformExtracted fields
	if dm.Extracted != nil {
		dnsFields["extracted.dns_payload"] = dm.Extracted.Base64Payload
		for k, v := range dm.Extracted.Base64Fields {
			dnsFields["extracted.base64_fields."+k] = v
		}
		for k, v := range dm.Extracted.HexFields {
			dnsFields["extracted.hex_fields."+k] = v
		}
	}

	// Add TransformReducer fields
	if dm.Reducer != nil {
		dnsFields["reducer.occurrences"] = dm.Reducer.Occurrences
		dnsFields["reducer.cumulative-length"] = dm.Reducer.CumulativeLength
	}

	// Add TransformFiltering fields
	if dm.Filtering != nil {
		dnsFields["filtering.sample-rate"] = dm.Filtering.SampleRate
	}

	// Add TransformML fields
	if dm.MachineLearning != nil {
		dnsFields["ml.entropy"] = dm.MachineLearning.Entropy
		dnsFields["ml.length"] = dm.MachineLearning.Length
		dnsFields["ml.labels"] = dm.MachineLearning.Labels
		dnsFields["ml.digits"] = dm.MachineLearning.Digits
		dnsFields["ml.lowers"] = dm.MachineLearning.Lowers
		dnsFields["ml.uppers"] = dm.MachineLearning.Uppers
		dnsFields["ml.specials"] = dm.MachineLearning.Specials
		dnsFields["ml.others"] = dm.MachineLearning.Others
		dnsFields["ml.ratio-digits"] = dm.MachineLearning.RatioDigits
		dnsFields["ml.ratio-letters"] = dm.MachineLearning.RatioLetters
		dnsFields["ml.ratio-specials"] = dm.MachineLearning.RatioSpecials
		dnsFields["ml.ratio-others"] = dm.MachineLearning.RatioOthers
		dnsFields["ml.consecutive-chars"] = dm.MachineLearning.ConsecutiveChars
		dnsFields["ml.consecutive-vowels"] = dm.MachineLearning.ConsecutiveVowels
		dnsFields["ml.consecutive-digits"] = dm.MachineLearning.ConsecutiveDigits
		dnsFields["ml.consecutive-consonants"] = dm.MachineLearning.ConsecutiveConsonants
		dnsFields["ml.size"] = dm.MachineLearning.Size
		dnsFields["ml.occurrences"] = dm.MachineLearning.Occurrences
		dnsFields["ml.uncommon-qtypes"] = dm.MachineLearning.UncommonQtypes
	}

	// Add TransformATags fields
	if dm.ATags != nil {
		if len(dm.ATags.Tags) == 0 {
			dnsFields["atags.tags"] = "-"
		}
		for i, tag := range dm.ATags.Tags {
			dnsFields["atags.tags."+strconv.Itoa(i)] = tag
		}
	}

	// Add PowerDNS collectors fields
	if dm.PowerDNS != nil {
		if len(dm.PowerDNS.Tags) == 0 {
			dnsFields["powerdns.tags"] = "-"
		}
		for i, tag := range dm.PowerDNS.Tags {
			dnsFields["powerdns.tags."+strconv.Itoa(i)] = tag
		}
		dnsFields["powerdns.original-request-subnet"] = dm.PowerDNS.OriginalRequestSubnet
		dnsFields["powerdns.applied-policy"] = dm.PowerDNS.AppliedPolicy
		dnsFields["powerdns.applied-policy-hit"] = dm.PowerDNS.AppliedPolicyHit
		dnsFields["powerdns.applied-policy-kind"] = dm.PowerDNS.AppliedPolicyKind
		dnsFields["powerdns.applied-policy-trigger"] = dm.PowerDNS.AppliedPolicyTrigger
		dnsFields["powerdns.applied-policy-type"] = dm.PowerDNS.AppliedPolicyType
		for mk, mv := range dm.PowerDNS.Metadata {
			dnsFields["powerdns.metadata."+mk] = mv
		}
		dnsFields["powerdns.http-version"] = dm.PowerDNS.HTTPVersion
		dnsFields["powerdns.message-id"] = dm.PowerDNS.MessageID
		dnsFields["powerdns.requestor-id"] = dm.PowerDNS.RequestorID
		dnsFields["powerdns.device-id"] = dm.PowerDNS.DeviceID
		dnsFields["powerdns.device-name"] = dm.PowerDNS.DeviceName
		dnsFields["powerdns.initial-requestor-id"] = dm.PowerDNS.InitialRequestorID
		dnsFields["powerdns.edns-version"] = dm.PowerDNS.EdnsVersion
		dnsFields["powerdns.opentelemetry-data"] = dm.PowerDNS.OpenTelemetryData
	}

	// relabeling ?
	if dm.Relabeling != nil {
		err := dm.ApplyRelabeling(dnsFields)
		if err != nil {
			return nil, err
		}
	}

	return dnsFields, nil
}

func WriteJSONString(buf *bytes.Buffer, s string) {
	buf.WriteByte('"')
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch c {
		case '"', '\\':
			buf.WriteByte('\\')
			buf.WriteByte(c)
		case '\n':
			buf.WriteString(`\n`)
		case '\r':
			buf.WriteString(`\r`)
		case '\t':
			buf.WriteString(`\t`)
		default:
			if c < 0x20 {
				buf.WriteString(`\u00`)
				const hexDigit = "0123456789abcdef"
				buf.WriteByte(hexDigit[c>>4])
				buf.WriteByte(hexDigit[c&0xf])
			} else {
				buf.WriteByte(c)
			}
		}
	}
	buf.WriteByte('"')
}
