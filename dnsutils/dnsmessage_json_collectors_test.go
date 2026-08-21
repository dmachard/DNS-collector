package dnsutils

import (
	"encoding/json"
	"reflect"
	"testing"
)

func TestDnsMessage_Json_Collectors_Reference(t *testing.T) {
	testcases := []struct {
		collector string
		dmRef     DNSMessage
		jsonRef   string
	}{
		{
			collector: "powerdns",
			dmRef: DNSMessage{PowerDNS: &CollectorPowerDNS{
				OriginalRequestSubnet: "subnet",
				AppliedPolicy:         "basicrpz",
				AppliedPolicyHit:      "hit",
				AppliedPolicyKind:     "kind",
				AppliedPolicyTrigger:  "trigger",
				AppliedPolicyType:     "type",
				Tags:                  []string{"tag1"},
				Metadata:              map[string]string{"stream_id": "collector"},
				HTTPVersion:           "http3",
				MessageID:             "27c3e94ad6284eec9a50cfc5bd7384d6",
				InitialRequestorID:    "5e006236c8a74f7eafc6af126e6d0689",
				RequestorID:           "f7c3e94ad6284eec9a50cfc5bd7384d6",
				DeviceID:              "ffffffffffffffffeaaeaeae",
				DeviceName:            "foobar",
				EdnsVersion:           "0",
				OpenTelemetryData:     "5e006236c8a74f7eafc6af126e6d0689",
			}},

			jsonRef: `{
						"powerdns": {
							"original-request-subnet": "subnet",
							"applied-policy": "basicrpz",
							"applied-policy-hit": "hit",
							"applied-policy-kind": "kind",
							"applied-policy-trigger": "trigger",
							"applied-policy-type": "type",
							"tags": ["tag1"],
							"metadata": {
								"stream_id": "collector"
							},
							"http-version": "http3",
							"message-id": "27c3e94ad6284eec9a50cfc5bd7384d6",
							"initial-requestor-id": "5e006236c8a74f7eafc6af126e6d0689",
							"requestor-id": "f7c3e94ad6284eec9a50cfc5bd7384d6",
							"device-id": "ffffffffffffffffeaaeaeae",
							"device-name": "foobar",
							"edns-version": "0",
							"opentelemetry-data": "5e006236c8a74f7eafc6af126e6d0689"
						}
					}`,
		},
	}
	for _, tc := range testcases {
		t.Run(tc.collector, func(t *testing.T) {
			tc.dmRef.Init()

			var dmMap map[string]interface{}
			err := json.Unmarshal([]byte(tc.dmRef.ToJSON()), &dmMap)
			if err != nil {
				t.Fatalf("could not unmarshal dm json: %s\n", err)
			}

			var refMap map[string]interface{}
			err = json.Unmarshal([]byte(tc.jsonRef), &refMap)
			if err != nil {
				t.Fatalf("could not unmarshal ref json: %s\n", err)
			}

			if !reflect.DeepEqual(dmMap[tc.collector], refMap[tc.collector]) {
				t.Errorf("json format different from reference, Get=%s Want=%s", dmMap[tc.collector], refMap[tc.collector])
			}
		})
	}
}

func TestDnsMessage_Json_Loggers_Reference(t *testing.T) {
	testcases := []struct {
		logger  string
		dmRef   DNSMessage
		jsonRef string
	}{
		{
			logger: "otel",
			dmRef: DNSMessage{OpenTelemetry: &LoggerOpenTelemetry{
				TraceID: "27c3e94ad6284eec9a50cfc5bd7384d6",
			}},

			jsonRef: `{
						"opentelemetry": {
							"trace-id": "27c3e94ad6284eec9a50cfc5bd7384d6"
						}
					}`,
		},
	}
	for _, tc := range testcases {
		t.Run(tc.logger, func(t *testing.T) {
			tc.dmRef.Init()

			var dmMap map[string]interface{}
			err := json.Unmarshal([]byte(tc.dmRef.ToJSON()), &dmMap)
			if err != nil {
				t.Fatalf("could not unmarshal dm json: %s\n", err)
			}

			var refMap map[string]interface{}
			err = json.Unmarshal([]byte(tc.jsonRef), &refMap)
			if err != nil {
				t.Fatalf("could not unmarshal ref json: %s\n", err)
			}

			if !reflect.DeepEqual(dmMap[tc.logger], refMap[tc.logger]) {
				t.Errorf("json format different from reference, Get=%s Want=%s", dmMap[tc.logger], refMap[tc.logger])
			}
		})
	}
}

func TestDnsMessage_JsonFlatten_Collectors_Reference(t *testing.T) {
	testcases := []struct {
		collector string
		dm        DNSMessage
		jsonRef   string
	}{
		{
			collector: "powerdns",
			dm: DNSMessage{PowerDNS: &CollectorPowerDNS{
				OriginalRequestSubnet: "subnet",
				AppliedPolicy:         "basicrpz",
				AppliedPolicyHit:      "hit",
				AppliedPolicyKind:     "kind",
				AppliedPolicyTrigger:  "trigger",
				AppliedPolicyType:     "type",
				Tags:                  []string{"tag1"},
				Metadata:              map[string]string{"stream_id": "collector"},
				HTTPVersion:           "http3",
				EdnsVersion:           "0",
				OpenTelemetryData:     "5e006236c8a74f7eafc6af126e6d0689",
			}},

			jsonRef: `{
						"powerdns.original-request-subnet": "subnet",
						"powerdns.applied-policy": "basicrpz",
						"powerdns.applied-policy-hit": "hit",
						"powerdns.applied-policy-kind": "kind",
						"powerdns.applied-policy-trigger": "trigger",
						"powerdns.applied-policy-type": "type",
						"powerdns.tags.0": "tag1",
						"powerdns.metadata.stream_id": "collector",
						"powerdns.http-version": "http3",
						"powerdns.edns-version": "0",
						"powerdns.opentelemetry-data": "5e006236c8a74f7eafc6af126e6d0689"
					}`,
		},
	}
	for _, tc := range testcases {
		t.Run(tc.collector, func(t *testing.T) {
			tc.dm.Init()

			var dmFlat map[string]interface{}
			dmJSON, err := tc.dm.ToFlatJSON()
			if err != nil {
				t.Fatalf("could not convert dm to flat json: %s\n", err)
			}
			err = json.Unmarshal([]byte(dmJSON), &dmFlat)
			if err != nil {
				t.Fatalf("could not unmarshal dm json: %s\n", err)
			}

			var refMap map[string]interface{}
			err = json.Unmarshal([]byte(tc.jsonRef), &refMap)
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
		})
	}
}
