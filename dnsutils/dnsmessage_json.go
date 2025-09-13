package dnsutils

import (
	"bytes"
	"encoding/json"
	"strconv"
	"strings"
)

func (dm *DNSMessage) ToJSON() string {
	buffer := new(bytes.Buffer)
	json.NewEncoder(buffer).Encode(dm)
	return buffer.String()
}

func (dm *DNSMessage) ToFlatJSON() (string, error) {
	buffer := new(bytes.Buffer)
	flat, err := dm.Flatten()
	if err != nil {
		return "", err
	}
	json.NewEncoder(buffer).Encode(flat)
	return buffer.String(), nil
}

func (dm *DNSMessage) Flatten() (map[string]interface{}, error) {
	dnsFields := map[string]interface{}{
		"dns.flags.aa":               dm.DNS.Flags.AA,
		"dns.flags.ad":               dm.DNS.Flags.AD,
		"dns.flags.qr":               dm.DNS.Flags.QR,
		"dns.flags.ra":               dm.DNS.Flags.RA,
		"dns.flags.tc":               dm.DNS.Flags.TC,
		"dns.flags.rd":               dm.DNS.Flags.RD,
		"dns.flags.cd":               dm.DNS.Flags.CD,
		"dns.length":                 dm.DNS.Length,
		"dns.malformed-packet":       dm.DNS.MalformedPacket,
		"dns.id":                     dm.DNS.ID,
		"dns.opcode":                 dm.DNS.Opcode,
		"dns.qname":                  dm.DNS.Qname,
		"dns.qtype":                  dm.DNS.Qtype,
		"dns.qclass":                 dm.DNS.Qclass,
		"dns.rcode":                  dm.DNS.Rcode,
		"dns.qdcount":                dm.DNS.QdCount,
		"dns.ancount":                dm.DNS.AnCount,
		"dns.arcount":                dm.DNS.ArCount,
		"dns.nscount":                dm.DNS.NsCount,
		"dnstap.identity":            dm.DNSTap.Identity,
		"dnstap.latency":             dm.DNSTap.Latency,
		"dnstap.operation":           dm.DNSTap.Operation,
		"dnstap.timestamp-rfc3339ns": dm.DNSTap.TimestampRFC3339,
		"dnstap.version":             dm.DNSTap.Version,
		"dnstap.extra":               dm.DNSTap.Extra,
		"dnstap.policy-rule":         dm.DNSTap.PolicyRule,
		"dnstap.policy-type":         dm.DNSTap.PolicyType,
		"dnstap.policy-action":       dm.DNSTap.PolicyAction,
		"dnstap.policy-match":        dm.DNSTap.PolicyMatch,
		"dnstap.policy-value":        dm.DNSTap.PolicyValue,
		"dnstap.peer-name":           dm.DNSTap.PeerName,
		"dnstap.query-zone":          dm.DNSTap.QueryZone,
		"edns.optionscount":          len(dm.EDNS.Options),
		"edns.dnssec-ok":             dm.EDNS.Do,
		"edns.rcode":                 dm.EDNS.ExtendedRcode,
		"edns.udp-size":              dm.EDNS.UDPSize,
		"edns.version":               dm.EDNS.Version,
		"network.family":             dm.NetworkInfo.Family,
		"network.ip-defragmented":    dm.NetworkInfo.IPDefragmented,
		"network.protocol":           dm.NetworkInfo.Protocol,
		"network.query-ip":           dm.NetworkInfo.QueryIP,
		"network.query-port":         dm.NetworkInfo.QueryPort,
		"network.response-ip":        dm.NetworkInfo.ResponseIP,
		"network.response-port":      dm.NetworkInfo.ResponsePort,
		"network.tcp-reassembled":    dm.NetworkInfo.TCPReassembled,
	}

	// Helper function to build RR fields
	buildRRFields := func(rrs []DNSAnswer) (names, rdatatypes, rdatas, ttls, classes string) {
		var n, t, d, l, c []string
		for _, rr := range rrs {
			n = append(n, rr.Name)
			t = append(t, rr.Rdatatype)
			d = append(d, rr.Rdata)
			l = append(l, strconv.Itoa(rr.TTL))
			c = append(c, rr.Class)
		}
		joinOrDash := func(arr []string) string {
			if len(arr) == 0 {
				return "-"
			}
			return strings.Join(arr, "|")
		}
		return joinOrDash(n), joinOrDash(t), joinOrDash(d), joinOrDash(l), joinOrDash(c)
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
	var optCodes, optDatas, optNames []string
	for _, opt := range dm.EDNS.Options {
		optCodes = append(optCodes, strconv.Itoa(opt.Code))
		optDatas = append(optDatas, opt.Data)
		optNames = append(optNames, opt.Name)
	}
	joinOrDash := func(arr []string) string {
		if len(arr) == 0 {
			return "-"
		}
		return strings.Join(arr, "|")
	}
	dnsFields["edns.options.codes"] = joinOrDash(optCodes)
	dnsFields["edns.options.datas"] = joinOrDash(optDatas)
	dnsFields["edns.options.names"] = joinOrDash(optNames)

	// Add TransformDNSGeo fields
	if dm.Geo != nil {
		dnsFields["geoip.city"] = dm.Geo.City
		dnsFields["geoip.continent"] = dm.Geo.Continent
		dnsFields["geoip.country-isocode"] = dm.Geo.CountryIsoCode
		dnsFields["geoip.as-number"] = dm.Geo.AutonomousSystemNumber
		dnsFields["geoip.as-owner"] = dm.Geo.AutonomousSystemOrg
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
