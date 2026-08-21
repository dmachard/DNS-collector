package dnsutils

import (
	"encoding/json"
	"reflect"
	"testing"
)

// Tests for JSON format
func TestDnsMessage_Json_Reference(t *testing.T) {
	dm := DNSMessage{}
	dm.Init()

	refJSON := `
			{
				"network": {
				  "family": "-",
				  "protocol": "-",
				  "query-ip": "-",
				  "query-port": "-",
				  "response-ip": "-",
				  "response-port": "-",
				  "ip-defragmented": false,
				  "tcp-reassembled": false
				},
				"dns": {
				  "id": 0,
				  "length": 0,
				  "opcode": 0,
				  "rcode": "-",
				  "qname": "-",
				  "qtype": "-",
				  "qclass": "-",
				  "qdcount": 0,
				  "ancount": 0,
				  "nscount": 0,
				  "arcount": 0,
				  "flags": {
					"qr": false,
					"tc": false,
					"aa": false,
					"ra": false,
					"ad": false,
					"rd": false,
					"cd": false
				  },
				  "resource-records": {
					"an": [],
					"ns": [],
					"ar": []
				  },
				  "malformed-packet": false
				},
				"edns": {
				  "udp-size": 0,
				  "rcode": 0,
				  "version": 0,
				  "dnssec-ok": 0,
				  "options": []
				},
				"dnstap": {
				  "operation": "-",
				  "identity": "-",
				  "version": "-",
				  "timestamp-rfc3339ns": "-",
				  "latency": 0,
				  "latency_ms": 0,
				  "extra": "-",
				  "policy-type": "-",
				  "policy-action": "-",
				  "policy-match": "-",
				  "policy-value": "-",
				  "policy-rule": "-",
				  "peer-name": "-",
				  "query-zone": "-",
				  "http-protocol": "-"
				}
			}
			`

	var dmMap map[string]interface{}
	err := json.Unmarshal([]byte(dm.ToJSON()), &dmMap)
	if err != nil {
		t.Fatalf("could not unmarshal dm json: %s\n", err)
	}

	var refMap map[string]interface{}
	err = json.Unmarshal([]byte(refJSON), &refMap)
	if err != nil {
		t.Fatalf("could not unmarshal ref json: %s\n", err)
	}

	if !reflect.DeepEqual(dmMap, refMap) {
		t.Errorf("json format different from reference %v", dmMap)
	}
}

// Tests for Flat JSON format
func TestDnsMessage_JsonFlatten_Reference(t *testing.T) {
	testcases := []struct {
		name    string
		setup   func(dm *DNSMessage)
		refJSON string
	}{
		{
			name: "single answer, single edns option",
			setup: func(dm *DNSMessage) {
				dm.DNS.DNSRRs.Answers = append(dm.DNS.DNSRRs.Answers, DNSAnswer{Name: "google.nl", Rdata: "142.251.39.99", Rdatatype: "A", TTL: 300, Class: "IN"})
				dm.EDNS.Options = append(dm.EDNS.Options, DNSOption{Code: 10, Data: "aaaabbbbcccc", Name: "COOKIE"})
			},
			refJSON: `{
			       "dns.flags.aa": false,
			       "dns.flags.ad": false,
			       "dns.flags.qr": false,
			       "dns.flags.ra": false,
			       "dns.flags.tc": false,
			       "dns.flags.rd": false,
			       "dns.flags.cd": false,
			       "dns.length": 0,
			       "dns.malformed-packet": false,
			       "dns.id": 0,
			       "dns.opcode": 0,
			       "dns.qname": "-",
			       "dns.qtype": "-",
			       "dns.rcode": "-",
			       "dns.qclass": "-",
			       "dns.qdcount": 0,
			       "dns.ancount": 0,
			       "dns.arcount": 0,
			       "dns.nscount": 0,
			       "dns.resource-records.an.names": "google.nl",
			       "dns.resource-records.an.rdatas": "142.251.39.99",
			       "dns.resource-records.an.rdatatypes": "A",
			       "dns.resource-records.an.ttls": "300",
			       "dns.resource-records.an.classes": "IN",
			       "dns.resource-records.ar.names": "-",
			       "dns.resource-records.ar.rdatas": "-",
			       "dns.resource-records.ar.rdatatypes": "-",
			       "dns.resource-records.ar.ttls": "-",
			       "dns.resource-records.ar.classes": "-",
			       "dns.resource-records.ns.names": "-",
			       "dns.resource-records.ns.rdatas": "-",
			       "dns.resource-records.ns.rdatatypes": "-",
			       "dns.resource-records.ns.ttls": "-",
			       "dns.resource-records.ns.classes": "-",
			       "dnstap.identity": "-",
			       "dnstap.latency": 0,
				   "dnstap.latency_ms": 0,
			       "dnstap.operation": "-",
			       "dnstap.timestamp-rfc3339ns": "-",
			       "dnstap.version": "-",
			       "dnstap.extra": "-",
			       "dnstap.policy-rule": "-",
			       "dnstap.policy-type": "-",
			       "dnstap.policy-action": "-",
			       "dnstap.policy-match": "-",
			       "dnstap.policy-value": "-",
			       "dnstap.peer-name": "-",
			       "dnstap.query-zone": "-",
			       "edns.dnssec-ok": 0,
			       "edns.optionscount": 1,
			       "edns.options.codes": "10",
			       "edns.options.datas": "aaaabbbbcccc",
			       "edns.options.names": "COOKIE",
			       "edns.rcode": 0,
			       "edns.udp-size": 0,
			       "edns.version": 0,
			       "network.family": "-",
			       "network.ip-defragmented": false,
			       "network.protocol": "-",
			       "network.query-ip": "-",
			       "network.query-port": "-",
			       "network.response-ip": "-",
			       "network.response-port": "-",
			       "network.tcp-reassembled": false
		       }`,
		},
		{
			name: "multiple answers, multiple edns options",
			setup: func(dm *DNSMessage) {
				dm.DNS.DNSRRs.Answers = append(dm.DNS.DNSRRs.Answers,
					DNSAnswer{Name: "a1.com", Rdata: "1.1.1.1", Rdatatype: "A", TTL: 100, Class: "IN"},
					DNSAnswer{Name: "a2.com", Rdata: "2.2.2.2", Rdatatype: "A", TTL: 200, Class: "IN"},
				)
				dm.EDNS.Options = append(dm.EDNS.Options,
					DNSOption{Code: 1, Data: "data1", Name: "OPT1"},
					DNSOption{Code: 2, Data: "data2", Name: "OPT2"},
				)
			},
			refJSON: `{
			       "dns.flags.aa": false,
			       "dns.flags.ad": false,
			       "dns.flags.qr": false,
			       "dns.flags.ra": false,
			       "dns.flags.tc": false,
			       "dns.flags.rd": false,
			       "dns.flags.cd": false,
			       "dns.length": 0,
			       "dns.malformed-packet": false,
			       "dns.id": 0,
			       "dns.opcode": 0,
			       "dns.qname": "-",
			       "dns.qtype": "-",
			       "dns.rcode": "-",
			       "dns.qclass": "-",
			       "dns.qdcount": 0,
			       "dns.ancount": 0,
			       "dns.arcount": 0,
			       "dns.nscount": 0,
			       "dns.resource-records.an.names": "a1.com|a2.com",
			       "dns.resource-records.an.rdatas": "1.1.1.1|2.2.2.2",
			       "dns.resource-records.an.rdatatypes": "A|A",
			       "dns.resource-records.an.ttls": "100|200",
			       "dns.resource-records.an.classes": "IN|IN",
			       "dns.resource-records.ar.names": "-",
			       "dns.resource-records.ar.rdatas": "-",
			       "dns.resource-records.ar.rdatatypes": "-",
			       "dns.resource-records.ar.ttls": "-",
			       "dns.resource-records.ar.classes": "-",
			       "dns.resource-records.ns.names": "-",
			       "dns.resource-records.ns.rdatas": "-",
			       "dns.resource-records.ns.rdatatypes": "-",
			       "dns.resource-records.ns.ttls": "-",
			       "dns.resource-records.ns.classes": "-",
			       "dnstap.identity": "-",
			       "dnstap.latency": 0,
				   "dnstap.latency_ms": 0,
			       "dnstap.operation": "-",
			       "dnstap.timestamp-rfc3339ns": "-",
			       "dnstap.version": "-",
			       "dnstap.extra": "-",
			       "dnstap.policy-rule": "-",
			       "dnstap.policy-type": "-",
			       "dnstap.policy-action": "-",
			       "dnstap.policy-match": "-",
			       "dnstap.policy-value": "-",
			       "dnstap.peer-name": "-",
			       "dnstap.query-zone": "-",
			       "edns.dnssec-ok": 0,
			       "edns.optionscount": 2,
			       "edns.options.codes": "1|2",
			       "edns.options.datas": "data1|data2",
			       "edns.options.names": "OPT1|OPT2",
			       "edns.rcode": 0,
			       "edns.udp-size": 0,
			       "edns.version": 0,
			       "network.family": "-",
			       "network.ip-defragmented": false,
			       "network.protocol": "-",
			       "network.query-ip": "-",
			       "network.query-port": "-",
			       "network.response-ip": "-",
			       "network.response-port": "-",
			       "network.tcp-reassembled": false
		       }`,
		},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			dm := DNSMessage{}
			dm.Init()
			tc.setup(&dm)

			var dmFlat map[string]interface{}
			dmJSON, err := dm.ToFlatJSON()
			if err != nil {
				t.Fatalf("could not convert dm to flat json: %s\n", err)
			}
			err = json.Unmarshal([]byte(dmJSON), &dmFlat)
			if err != nil {
				t.Fatalf("could not unmarshal dm json: %s\n", err)
			}

			var refMap map[string]interface{}
			err = json.Unmarshal([]byte(tc.refJSON), &refMap)
			if err != nil {
				t.Fatalf("could not unmarshal ref json: %s\n", err)
			}

			for k, vRef := range refMap {
				vFlat, ok := dmFlat[k]
				if !ok {
					t.Fatalf("Missing key %s in flatten message according to reference", k)
				}
				if vRef != vFlat {
					t.Errorf("Invalid value for key=%s get=%v expected=%v", k, vFlat, vRef)
				}
			}

			for k := range dmFlat {
				_, ok := refMap[k]
				if !ok {
					t.Errorf("This key %s should not be in the flat message", k)
				}
			}
		})
	}
}
