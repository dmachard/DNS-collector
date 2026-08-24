package dnsutils

import (
	"bytes"
)

func (c *CollectorPowerDNS) EncodeJSON(buf *bytes.Buffer) {
	buf.WriteString(`{"tags":`)
	encodeStringSlice(buf, c.Tags)
	buf.WriteString(`,"original-request-subnet":`)
	WriteJSONString(buf, c.OriginalRequestSubnet)
	buf.WriteString(`,"applied-policy":`)
	WriteJSONString(buf, c.AppliedPolicy)
	buf.WriteString(`,"applied-policy-hit":`)
	WriteJSONString(buf, c.AppliedPolicyHit)
	buf.WriteString(`,"applied-policy-kind":`)
	WriteJSONString(buf, c.AppliedPolicyKind)
	buf.WriteString(`,"applied-policy-trigger":`)
	WriteJSONString(buf, c.AppliedPolicyTrigger)
	buf.WriteString(`,"applied-policy-type":`)
	WriteJSONString(buf, c.AppliedPolicyType)
	buf.WriteString(`,"metadata":`)
	encodeStringMap(buf, c.Metadata)
	buf.WriteString(`,"http-version":`)
	WriteJSONString(buf, c.HTTPVersion)
	buf.WriteString(`,"message-id":`)
	WriteJSONString(buf, c.MessageID)
	buf.WriteString(`,"initial-requestor-id":`)
	WriteJSONString(buf, c.InitialRequestorID)
	buf.WriteString(`,"requestor-id":`)
	WriteJSONString(buf, c.RequestorID)
	buf.WriteString(`,"device-name":`)
	WriteJSONString(buf, c.DeviceName)
	buf.WriteString(`,"device-id":`)
	WriteJSONString(buf, c.DeviceID)
	buf.WriteString(`,"opentelemetry-data":`)
	WriteJSONString(buf, c.OpenTelemetryData)
	buf.WriteString(`,"edns-version":`)
	WriteJSONString(buf, c.EdnsVersion)
	buf.WriteString(`,"ede":`)
	if c.Ede != nil {
		writeJSONInt(buf, *c.Ede)
	} else {
		buf.WriteString("null")
	}
	buf.WriteString(`,"ede-text":`)
	WriteJSONString(buf, c.EdeText)
	buf.WriteString(`,"opentelemetry-trace-id":`)
	WriteJSONString(buf, c.OpenTelemetryTraceID)
	buf.WriteByte('}')
}

func (l *LoggerOpenTelemetry) EncodeJSON(buf *bytes.Buffer) {
	buf.WriteString(`{"trace-id":`)
	WriteJSONString(buf, l.TraceID)
	buf.WriteByte('}')
}
