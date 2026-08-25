package dnsutils

import (
	"encoding/json"
	"reflect"
	"testing"
)

func TestDnsMessage_Json_Transforms_Reference(t *testing.T) {
	testcases := []struct {
		transform string
		dmRef     DNSMessage
		jsonRef   string
	}{
		{
			transform: "filtering",
			dmRef:     DNSMessage{Filtering: &TransformFiltering{SampleRate: 22}},
			jsonRef: `{
						"filtering": {
						"sample-rate": 22
						}
					}`,
		},
		{
			transform: "reducer",
			dmRef:     DNSMessage{Reducer: &TransformReducer{Occurrences: 10, CumulativeLength: 47}},
			jsonRef: `{
						"reducer": {
							"occurrences": 10,
							"cumulative-length": 47
						}
					}`,
		},
		{
			transform: "normalize",
			dmRef: DNSMessage{
				PublicSuffix: &TransformPublicSuffix{
					QnamePublicSuffix:        "com",
					QnameEffectiveTLDPlusOne: "hello.com",
					ManagedByICANN:           true,
				},
			},
			jsonRef: `{
						"publicsuffix": {
							"tld": "com",
							"etld+1": "hello.com",
							"managed-icann": true
						}
					}`,
		},
		{
			transform: "geoip",
			dmRef: DNSMessage{
				Geo: &TransformDNSGeo{
					City:                   "Paris",
					Continent:              "Europe",
					CountryIsoCode:         "FR",
					AutonomousSystemNumber: "1234",
					AutonomousSystemOrg:    "Internet",
				},
			},
			jsonRef: `{
						"geoip": {
							"city": "Paris",
							"continent": "Europe",
							"country-isocode": "FR",
							"as-number": "1234",
							"as-owner": "Internet",
							"lat": 0,
							"lon": 0
						}
					}`,
		},
		{
			transform: "bgp",
			dmRef: DNSMessage{
				BGP: &TransformBGP{
					OriginASN: "19281",
					ASPath:    "174 2914 19281",
					Prefix:    "149.112.112.0/24",
				},
			},
			jsonRef: `{
						"bgp": {
							"origin-asn": "19281",
							"as-path": "174 2914 19281",
							"prefix": "149.112.112.0/24"
						}
					}`,
		},
		{
			transform: "atags",
			dmRef:     DNSMessage{ATags: &TransformATags{Tags: []string{"test0", "test1"}}},
			jsonRef: `{
						"atags": {
							"tags": [ "test0", "test1" ]
						}
					}`,
		},
	}

	for _, tc := range testcases {
		t.Run(tc.transform, func(t *testing.T) {
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

			if !reflect.DeepEqual(dmMap[tc.transform], refMap[tc.transform]) {
				t.Errorf("json format different from reference, Get=%s Want=%s", dmMap[tc.transform], refMap[tc.transform])
			}
		})
	}
}

func TestDnsMessage_JsonFlatten_Transforms_Reference(t *testing.T) {
	testcases := []struct {
		transform string
		dm        DNSMessage
		jsonRef   string
	}{
		{
			transform: "filtering",
			dm:        DNSMessage{Filtering: &TransformFiltering{SampleRate: 22}},
			jsonRef: `{
						"filtering.sample-rate": 22
					  }`,
		},
		{
			transform: "reducer",
			dm:        DNSMessage{Reducer: &TransformReducer{Occurrences: 10, CumulativeLength: 47}},
			jsonRef: `{
						"reducer.occurrences": 10,
						"reducer.cumulative-length": 47
					  }`,
		},
		{
			transform: "publicsuffix",
			dm: DNSMessage{
				PublicSuffix: &TransformPublicSuffix{
					QnamePublicSuffix:        "com",
					QnameEffectiveTLDPlusOne: "hello.com",
				},
			},
			jsonRef: `{
						"publicsuffix.tld": "com",
						"publicsuffix.etld+1": "hello.com"
					  }`,
		},
		{
			transform: "geoip",
			dm: DNSMessage{
				Geo: &TransformDNSGeo{
					City:                   "Paris",
					Continent:              "Europe",
					CountryIsoCode:         "FR",
					AutonomousSystemNumber: "1234",
					AutonomousSystemOrg:    "Internet",
				},
			},
			jsonRef: `{
						"geoip.city": "Paris",
						"geoip.continent": "Europe",
						"geoip.country-isocode": "FR",
						"geoip.as-number": "1234",
						"geoip.as-owner": "Internet",
						"geoip.lat": 0,
						"geoip.lon": 0
					}`,
		},
		{
			transform: "bgp",
			dm: DNSMessage{
				BGP: &TransformBGP{
					OriginASN: "19281",
					ASPath:    "174 2914 19281",
					Prefix:    "149.112.112.0/24",
				},
			},
			jsonRef: `{
						"bgp.origin-asn": "19281",
						"bgp.as-path": "174 2914 19281",
						"bgp.prefix": "149.112.112.0/24"
					}`,
		},
		{
			transform: "suspicious",
			dm: DNSMessage{Suspicious: &TransformSuspicious{Score: 1.0,
				MalformedPacket:       false,
				LargePacket:           true,
				LongDomain:            true,
				SlowDomain:            false,
				UnallowedChars:        true,
				UncommonQtypes:        false,
				ExcessiveNumberLabels: true,
				Domain:                "gogle.co",
			}},
			jsonRef: `{
						"suspicious.score": 1.0,
						"suspicious.malformed-pkt": false,
						"suspicious.large-pkt": true,
						"suspicious.long-domain": true,
						"suspicious.slow-domain": false,
						"suspicious.unallowed-chars": true,
						"suspicious.uncommon-qtypes": false,
						"suspicious.excessive-number-labels": true,
						"suspicious.domain": "gogle.co"
					  }`,
		},
		{
			transform: "extracted",
			dm:        DNSMessage{Extracted: &TransformExtracted{Base64Payload: []byte{}}},
			jsonRef: `{
						"extracted.dns_payload": ""
					  }`,
		},
		{
			transform: "machinelearning",
			dm: DNSMessage{MachineLearning: &TransformML{
				Entropy:               10.0,
				Length:                2,
				Labels:                2,
				Digits:                1,
				Lowers:                35,
				Uppers:                23,
				Specials:              2,
				Others:                1,
				RatioDigits:           1.0,
				RatioLetters:          1.0,
				RatioSpecials:         1.0,
				RatioOthers:           1.0,
				ConsecutiveChars:      10,
				ConsecutiveVowels:     10,
				ConsecutiveDigits:     10,
				ConsecutiveConsonants: 10,
				Size:                  11,
				Occurrences:           10,
				UncommonQtypes:        1,
			}},
			jsonRef: `{
						"ml.entropy": 10.0,
						"ml.length": 2,
						"ml.labels": 2,
						"ml.digits": 1,
						"ml.lowers": 35,
						"ml.uppers": 23,
						"ml.specials": 2,
						"ml.others": 1,
						"ml.ratio-digits": 1.0,
						"ml.ratio-letters": 1.0,
						"ml.ratio-specials": 1.0,
						"ml.ratio-others": 1.0,
						"ml.consecutive-chars": 10,
						"ml.consecutive-vowels": 10,
						"ml.consecutive-digits": 10,
						"ml.consecutive-consonants": 10,
						"ml.size": 11,
						"ml.occurrences": 10,
						"ml.uncommon-qtypes": 1
					  }`,
		},
		{
			transform: "atags",
			dm:        DNSMessage{ATags: &TransformATags{Tags: []string{"test0", "test1"}}},
			jsonRef: `{
						"atags.tags.0": "test0",
						"atags.tags.1": "test1"
					  }`,
		},
	}

	for _, tc := range testcases {
		t.Run(tc.transform, func(t *testing.T) {
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
