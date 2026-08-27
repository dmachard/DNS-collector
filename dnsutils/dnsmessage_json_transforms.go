package dnsutils

import (
	"bytes"
)

func (t *TransformDNSGeo) EncodeJSON(buf *bytes.Buffer) {
	buf.WriteString(`{"city":`)
	WriteJSONString(buf, t.City)
	buf.WriteString(`,"continent":`)
	WriteJSONString(buf, t.Continent)
	buf.WriteString(`,"country-isocode":`)
	WriteJSONString(buf, t.CountryIsoCode)
	buf.WriteString(`,"as-number":`)
	WriteJSONString(buf, t.AutonomousSystemNumber)
	buf.WriteString(`,"as-owner":`)
	WriteJSONString(buf, t.AutonomousSystemOrg)
	buf.WriteString(`,"lat":`)
	writeJSONFloat(buf, t.Latitude)
	buf.WriteString(`,"lon":`)
	writeJSONFloat(buf, t.Longitude)
	buf.WriteByte('}')
}

func (t *TransformBGP) EncodeJSON(buf *bytes.Buffer) {
	buf.WriteString(`{"origin-asn":`)
	WriteJSONString(buf, t.OriginASN)
	buf.WriteString(`,"as-path":`)
	WriteJSONString(buf, t.ASPath)
	buf.WriteString(`,"prefix":`)
	WriteJSONString(buf, t.Prefix)
	buf.WriteByte('}')
}

func (t *TransformSuspicious) EncodeJSON(buf *bytes.Buffer) {
	buf.WriteString(`{"score":`)
	writeJSONFloat(buf, t.Score)
	buf.WriteString(`,"malformed-pkt":`)
	if t.MalformedPacket {
		buf.WriteString("true")
	} else {
		buf.WriteString("false")
	}
	buf.WriteString(`,"large-pkt":`)
	if t.LargePacket {
		buf.WriteString("true")
	} else {
		buf.WriteString("false")
	}
	buf.WriteString(`,"long-domain":`)
	if t.LongDomain {
		buf.WriteString("true")
	} else {
		buf.WriteString("false")
	}
	buf.WriteString(`,"slow-domain":`)
	if t.SlowDomain {
		buf.WriteString("true")
	} else {
		buf.WriteString("false")
	}
	buf.WriteString(`,"unallowed-chars":`)
	if t.UnallowedChars {
		buf.WriteString("true")
	} else {
		buf.WriteString("false")
	}
	buf.WriteString(`,"uncommon-qtypes":`)
	if t.UncommonQtypes {
		buf.WriteString("true")
	} else {
		buf.WriteString("false")
	}
	buf.WriteString(`,"excessive-number-labels":`)
	if t.ExcessiveNumberLabels {
		buf.WriteString("true")
	} else {
		buf.WriteString("false")
	}
	if len(t.Domain) > 0 {
		buf.WriteString(`,"domain":`)
		WriteJSONString(buf, t.Domain)
	}
	buf.WriteByte('}')
}

func (t *TransformPublicSuffix) EncodeJSON(buf *bytes.Buffer) {
	buf.WriteString(`{"tld":`)
	WriteJSONString(buf, t.QnamePublicSuffix)
	buf.WriteString(`,"etld+1":`)
	WriteJSONString(buf, t.QnameEffectiveTLDPlusOne)
	buf.WriteString(`,"managed-icann":`)
	if t.ManagedByICANN {
		buf.WriteString("true")
	} else {
		buf.WriteString("false")
	}
	buf.WriteByte('}')
}

func (t *TransformExtracted) EncodeJSON(buf *bytes.Buffer) {
	buf.WriteString(`{"dns_payload":`)
	if t.Base64Payload != nil {
		buf.WriteByte('"')
		writeBase64(buf, t.Base64Payload)
		buf.WriteByte('"')
	} else {
		buf.WriteString("null")
	}
	if len(t.Base64Fields) > 0 {
		buf.WriteString(`,"base64_fields":`)
		encodeInterfaceMap(buf, t.Base64Fields)
	}
	if len(t.HexFields) > 0 {
		buf.WriteString(`,"hex_fields":`)
		encodeInterfaceMap(buf, t.HexFields)
	}
	buf.WriteByte('}')
}

func (t *TransformReducer) EncodeJSON(buf *bytes.Buffer) {
	buf.WriteString(`{"occurrences":`)
	writeJSONInt(buf, t.Occurrences)
	buf.WriteString(`,"cumulative-length":`)
	writeJSONInt(buf, t.CumulativeLength)
	buf.WriteByte('}')
}

func (t *TransformML) EncodeJSON(buf *bytes.Buffer) {
	buf.WriteString(`{"entropy":`)
	writeJSONFloat(buf, t.Entropy)
	buf.WriteString(`,"length":`)
	writeJSONInt(buf, t.Length)
	buf.WriteString(`,"labels":`)
	writeJSONInt(buf, t.Labels)
	buf.WriteString(`,"digits":`)
	writeJSONInt(buf, t.Digits)
	buf.WriteString(`,"lowers":`)
	writeJSONInt(buf, t.Lowers)
	buf.WriteString(`,"uppers":`)
	writeJSONInt(buf, t.Uppers)
	buf.WriteString(`,"specials":`)
	writeJSONInt(buf, t.Specials)
	buf.WriteString(`,"others":`)
	writeJSONInt(buf, t.Others)
	buf.WriteString(`,"ratio-digits":`)
	writeJSONFloat(buf, t.RatioDigits)
	buf.WriteString(`,"ratio-letters":`)
	writeJSONFloat(buf, t.RatioLetters)
	buf.WriteString(`,"ratio-specials":`)
	writeJSONFloat(buf, t.RatioSpecials)
	buf.WriteString(`,"ratio-others":`)
	writeJSONFloat(buf, t.RatioOthers)
	buf.WriteString(`,"consecutive-chars":`)
	writeJSONInt(buf, t.ConsecutiveChars)
	buf.WriteString(`,"consecutive-vowels":`)
	writeJSONInt(buf, t.ConsecutiveVowels)
	buf.WriteString(`,"consecutive-digits":`)
	writeJSONInt(buf, t.ConsecutiveDigits)
	buf.WriteString(`,"consecutive-consonants":`)
	writeJSONInt(buf, t.ConsecutiveConsonants)
	buf.WriteString(`,"size":`)
	writeJSONInt(buf, t.Size)
	buf.WriteString(`,"occurrences":`)
	writeJSONInt(buf, t.Occurrences)
	buf.WriteString(`,"uncommon-qtypes":`)
	writeJSONInt(buf, t.UncommonQtypes)
	buf.WriteByte('}')
}

func (t *TransformFiltering) EncodeJSON(buf *bytes.Buffer) {
	buf.WriteString(`{"sample-rate":`)
	writeJSONInt(buf, t.SampleRate)
	buf.WriteByte('}')
}

func (t *TransformATags) EncodeJSON(buf *bytes.Buffer) {
	buf.WriteString(`{"tags":`)
	encodeStringSlice(buf, t.Tags)
	buf.WriteByte('}')
}

func (t *TransformRest) EncodeJSON(buf *bytes.Buffer) {
	buf.WriteString(`{"failed":`)
	if t.Failed {
		buf.WriteString("true")
	} else {
		buf.WriteString("false")
	}
	buf.WriteString(`,"response":`)
	WriteJSONString(buf, t.Response)
	buf.WriteByte('}')
}

func (t *TransformFrequency) EncodeJSON(buf *bytes.Buffer) {
	buf.WriteString(`{"count":`)
	writeJSONInt(buf, t.Count)
	buf.WriteString(`,"is_heavy_hitter":`)
	if t.IsHeavyHitter {
		buf.WriteString("true")
	} else {
		buf.WriteString("false")
	}
	buf.WriteString(`,"tracked_key":`)
	WriteJSONString(buf, t.TrackedKey)
	buf.WriteByte('}')
}
