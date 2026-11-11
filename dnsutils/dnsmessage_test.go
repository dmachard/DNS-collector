package dnsutils

import (
	"bytes"
	"fmt"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"
	"unsafe"
)

func TestDNSNetInfo_GetAndSetIPBytes(t *testing.T) {
	dm := DNSMessage{}
	dm.Init()

	// Initial default values
	if dm.NetworkInfo.GetQueryIP() != "-" {
		t.Errorf("expected default QueryIP '-', got %s", dm.NetworkInfo.GetQueryIP())
	}
	if dm.NetworkInfo.GetResponseIP() != "-" {
		t.Errorf("expected default ResponseIP '-', got %s", dm.NetworkInfo.GetResponseIP())
	}

	// Set IPv4 bytes
	dm.NetworkInfo.SetQueryIPBytes([]byte{192, 168, 1, 50})
	dm.NetworkInfo.SetResponseIPBytes([]byte{8, 8, 8, 8})

	if dm.NetworkInfo.GetQueryIP() != "192.168.1.50" {
		t.Errorf("expected QueryIP 192.168.1.50, got %s", dm.NetworkInfo.GetQueryIP())
	}
	if dm.NetworkInfo.GetResponseIP() != "8.8.8.8" {
		t.Errorf("expected ResponseIP 8.8.8.8, got %s", dm.NetworkInfo.GetResponseIP())
	}
}

func TestDNSNetInfo_WriteIPJSON(t *testing.T) {
	tests := []struct {
		name      string
		setup     func(net *DNSNetInfo)
		wantQuery string
		wantResp  string
	}{
		{
			name: "From raw bytes",
			setup: func(net *DNSNetInfo) {
				net.SetQueryIPBytes([]byte{10, 0, 0, 1})
				net.SetResponseIPBytes([]byte{10, 0, 0, 2})
			},
			wantQuery: `"10.0.0.1"`,
			wantResp:  `"10.0.0.2"`,
		},
		{
			name: "From custom string override",
			setup: func(net *DNSNetInfo) {
				net.QueryIP = "1.2.3.4"
				net.ResponseIP = "5.6.7.8"
			},
			wantQuery: `"1.2.3.4"`,
			wantResp:  `"5.6.7.8"`,
		},
		{
			name: "Default uninitialized",
			setup: func(net *DNSNetInfo) {
				net.QueryIP = "-"
				net.ResponseIP = "-"
			},
			wantQuery: `"-"`,
			wantResp:  `"-"`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			net := &DNSNetInfo{QueryIP: "-", ResponseIP: "-"}
			tt.setup(net)

			var qbuf bytes.Buffer
			net.WriteQueryIPJSON(&qbuf)
			if got := qbuf.String(); got != tt.wantQuery {
				t.Errorf("WriteQueryIPJSON() = %q, want %q", got, tt.wantQuery)
			}

			var rbuf bytes.Buffer
			net.WriteResponseIPJSON(&rbuf)
			if got := rbuf.String(); got != tt.wantResp {
				t.Errorf("WriteResponseIPJSON() = %q, want %q", got, tt.wantResp)
			}
		})
	}
}

func TestDNSNetInfo_WriteIPText(t *testing.T) {
	tests := []struct {
		name      string
		setup     func(net *DNSNetInfo)
		wantQuery string
		wantResp  string
	}{
		{
			name: "From raw bytes",
			setup: func(net *DNSNetInfo) {
				net.SetQueryIPBytes([]byte{172, 16, 0, 1})
				net.SetResponseIPBytes([]byte{172, 16, 0, 254})
			},
			wantQuery: "172.16.0.1",
			wantResp:  "172.16.0.254",
		},
		{
			name: "From custom string override",
			setup: func(net *DNSNetInfo) {
				net.QueryIP = "anonymized-ip"
				net.ResponseIP = "anonymized-resp"
			},
			wantQuery: "anonymized-ip",
			wantResp:  "anonymized-resp",
		},
		{
			name: "Default uninitialized",
			setup: func(net *DNSNetInfo) {
				net.QueryIP = ""
				net.ResponseIP = ""
			},
			wantQuery: "-",
			wantResp:  "-",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			net := &DNSNetInfo{}
			tt.setup(net)

			var qbuf bytes.Buffer
			net.WriteQueryIPText(&qbuf)
			if got := qbuf.String(); got != tt.wantQuery {
				t.Errorf("WriteQueryIPText() = %q, want %q", got, tt.wantQuery)
			}

			var rbuf bytes.Buffer
			net.WriteResponseIPText(&rbuf)
			if got := rbuf.String(); got != tt.wantResp {
				t.Errorf("WriteResponseIPText() = %q, want %q", got, tt.wantResp)
			}
		})
	}
}

// Bench to init DNS message
func BenchmarkDnsMessage_Init(b *testing.B) {
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		dm := DNSMessage{}
		dm.Init()
		dm.InitTransforms()
	}
}

func TestDNSMessage_Size(t *testing.T) {
	size := unsafe.Sizeof(DNSMessage{})
	t.Logf("Sizeof(DNSMessage): %d bytes", size)
	if size > 1024 {
		t.Errorf("DNSMessage struct size bloated: %d bytes (threshold: 1024)", size)
	}
}

func TestDNSMessage_TimestampRace(t *testing.T) {
	dm := AcquireDNSMessage()
	defer dm.Release()

	dm.DNSTap.Timestamp = time.Now().UnixNano()
	dm.DNSTap.TimestampRFC3339 = "-" // as processFrame sets it

	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		var buf bytes.Buffer
		dm.GetTimestampRFC3339()
		dm.EncodeJSON(&buf)
	}()

	go func() {
		defer wg.Done()
		dm.GetTimestampRFC3339()
	}()

	wg.Wait()
}

func TestDNSMessage_TimestampCorruptionRepro(t *testing.T) {
	stopGC := make(chan struct{})
	go func() {
		for {
			select {
			case <-stopGC:
				return
			default:
				runtime.GC()
			}
		}
	}()
	defer close(stopGC)

	corrupted := 0
	iterations := 500000

	for i := 0; i < iterations; i++ {
		dm := AcquireDNSMessage()
		dm.DNSTap.Timestamp = time.Now().UnixNano()
		dm.DNSTap.TimestampRFC3339 = "-"

		var wg sync.WaitGroup
		var jsonBuf bytes.Buffer
		var textTS string

		wg.Add(2)
		go func() {
			defer wg.Done()
			dm.GetTimestampRFC3339()
			dm.EncodeJSON(&jsonBuf)
		}()
		go func() {
			defer wg.Done()
			textTS = dm.GetTimestampRFC3339()
		}()
		wg.Wait()

		if len(textTS) > 1 && strings.HasPrefix(textTS, "-") {
			corrupted++
			t.Logf("Found corrupted text timestamp at iter %d: %q", i, textTS)
			break
		}
		jsonStr := jsonBuf.String()
		if strings.Contains(jsonStr, `"timestamp-rfc3339ns":"-`) && !strings.Contains(jsonStr, `"timestamp-rfc3339ns":"-"`) {
			corrupted++
			t.Logf("Found corrupted json timestamp at iter %d: %s", i, jsonStr)
			break
		}

		dm.Release()
	}

	if corrupted > 0 {
		t.Errorf("Detected %d corrupted timestamp occurrences due to data race", corrupted)
	}
}

func TestDNSMessage_QueryIPRace(t *testing.T) {
	dm := AcquireDNSMessage()
	defer dm.Release()

	dm.NetworkInfo.SetQueryIPBytes([]byte{192, 0, 2, 1})

	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		dm.NetworkInfo.GetQueryIP()
	}()

	go func() {
		defer wg.Done()
		dm.NetworkInfo.GetQueryIP()
	}()

	wg.Wait()
}

func TestDNSMessage_QueryIPCorruptionRepro(t *testing.T) {
	stopGC := make(chan struct{})
	go func() {
		for {
			select {
			case <-stopGC:
				return
			default:
				runtime.GC()
			}
		}
	}()
	defer close(stopGC)

	corrupted := 0
	iterations := 500000

	for i := 0; i < iterations; i++ {
		net := &DNSNetInfo{}
		net.SetQueryIPBytes([]byte{192, 0, 2, 1})

		var wg sync.WaitGroup
		var ip1, ip2 string

		wg.Add(2)
		go func() {
			defer wg.Done()
			ip1 = net.GetQueryIP()
		}()
		go func() {
			defer wg.Done()
			ip2 = net.GetQueryIP()
		}()
		wg.Wait()

		if len(ip1) > 1 && strings.HasPrefix(ip1, "-") {
			corrupted++
			t.Logf("Found corrupted QueryIP (ip1) at iter %d: %q", i, ip1)
			break
		}
		if len(ip2) > 1 && strings.HasPrefix(ip2, "-") {
			corrupted++
			t.Logf("Found corrupted QueryIP (ip2) at iter %d: %q", i, ip2)
			break
		}
	}

	if corrupted > 0 {
		t.Errorf("Detected %d corrupted QueryIP occurrences due to data race", corrupted)
	}
}

func TestDNSMessage_ResponseIPRace(t *testing.T) {
	dm := AcquireDNSMessage()
	defer dm.Release()

	dm.NetworkInfo.SetResponseIPBytes([]byte{8, 8, 8, 8})

	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		dm.NetworkInfo.GetResponseIP()
	}()

	go func() {
		defer wg.Done()
		dm.NetworkInfo.GetResponseIP()
	}()

	wg.Wait()
}

func TestDNSMessage_ResponseIPCorruptionRepro(t *testing.T) {
	stopGC := make(chan struct{})
	go func() {
		for {
			select {
			case <-stopGC:
				return
			default:
				runtime.GC()
			}
		}
	}()
	defer close(stopGC)

	corrupted := 0
	iterations := 500000

	for i := 0; i < iterations; i++ {
		net := &DNSNetInfo{}
		net.SetResponseIPBytes([]byte{8, 8, 8, 8})

		var wg sync.WaitGroup
		var ip1, ip2 string

		wg.Add(2)
		go func() {
			defer wg.Done()
			ip1 = net.GetResponseIP()
		}()
		go func() {
			defer wg.Done()
			ip2 = net.GetResponseIP()
		}()
		wg.Wait()

		if len(ip1) > 1 && strings.HasPrefix(ip1, "-") {
			corrupted++
			t.Logf("Found corrupted ResponseIP (ip1) at iter %d: %q", i, ip1)
			break
		}
		if len(ip2) > 1 && strings.HasPrefix(ip2, "-") {
			corrupted++
			t.Logf("Found corrupted ResponseIP (ip2) at iter %d: %q", i, ip2)
			break
		}
	}

	if corrupted > 0 {
		t.Errorf("Detected %d corrupted ResponseIP occurrences due to data race", corrupted)
	}
}

func TestDNSMessage_Clone(t *testing.T) {
	dm := AcquireDNSMessage()
	defer dm.Release()

	dm.NetworkInfo.SetQueryIPBytes([]byte{192, 168, 1, 1})
	dm.DNS.Qname = "example.com"
	dm.DNS.Payload = []byte{1, 2, 3, 4}
	dm.DNS.DNSRRs.Answers = []DNSAnswer{{Name: "example.com", Rdata: "93.184.216.34"}}
	dm.Rest = &TransformRest{Failed: false, Response: "orig"}

	clone := dm.Clone()
	defer clone.Release()

	if clone.RefCount != 1 {
		t.Errorf("expected clone RefCount 1, got %d", clone.RefCount)
	}
	if clone.DNS.Qname != "example.com" {
		t.Errorf("expected clone Qname example.com, got %s", clone.DNS.Qname)
	}
	if len(clone.DNS.DNSRRs.Answers) != 1 || clone.DNS.DNSRRs.Answers[0].Rdata != "93.184.216.34" {
		t.Errorf("clone Answers slice mismatch")
	}

	// Mutate clone Rest and payload, verify original unaffected
	clone.Rest = &TransformRest{Failed: true, Response: "cloned"}
	clone.DNS.Payload[0] = 99

	if dm.Rest.Response != "orig" || dm.Rest.Failed != false {
		t.Errorf("mutating clone mutated original Rest")
	}
	if dm.DNS.Payload[0] != 1 {
		t.Errorf("mutating clone mutated original DNS.Payload")
	}
}

func TestDNSMessage_Clone_DeepCopyPointers(t *testing.T) {
	// Reproduce Bug C:
	// DNSMessage.Clone() shallow copies pointer extension fields.
	// Mutating fields inside clone.ATags, clone.Extracted, clone.BGP, clone.Geo, etc.
	// corrupts the original dm!
	dm := AcquireDNSMessage()
	defer dm.Release()

	dm.ATags = &TransformATags{Tags: []string{"tag1", "tag2"}}
	dm.BGP = &TransformBGP{OriginASN: "65001", ASPath: "100 200", Prefix: "192.0.2.0/24"}
	dm.Geo = &TransformDNSGeo{City: "Paris", CountryIsoCode: "FR"}
	dm.Extracted = &TransformExtracted{
		Base64Payload: []byte("payload"),
		Base64Fields:  map[string]interface{}{"field1": "val1"},
		HexFields:     map[string]interface{}{"hfield1": "hval1"},
	}
	dm.PowerDNS = &CollectorPowerDNS{Tags: []string{"pdns1"}, Metadata: map[string]string{"k1": "v1"}}

	clone := dm.Clone()
	defer clone.Release()

	// Mutate clone extensions
	clone.ATags.Tags = append(clone.ATags.Tags, "tag3_mutated")
	clone.BGP.OriginASN = "65999_mutated"
	clone.Geo.City = "London_mutated"
	clone.Extracted.Base64Fields["field1"] = "val1_mutated"
	clone.PowerDNS.Tags = append(clone.PowerDNS.Tags, "pdns_mutated")
	clone.PowerDNS.Metadata["k1"] = "v1_mutated"

	// Verify original is NOT mutated
	if len(dm.ATags.Tags) != 2 {
		t.Errorf("SHALLOW COPY CORRUPTION: dm.ATags.Tags was mutated via clone! Got %v, want 2 items", dm.ATags.Tags)
	}
	if dm.BGP.OriginASN != "65001" {
		t.Errorf("SHALLOW COPY CORRUPTION: dm.BGP.OriginASN was mutated via clone! Got %s, want 65001", dm.BGP.OriginASN)
	}
	if dm.Geo.City != "Paris" {
		t.Errorf("SHALLOW COPY CORRUPTION: dm.Geo.City was mutated via clone! Got %s, want Paris", dm.Geo.City)
	}
	if dm.Extracted.Base64Fields["field1"] != "val1" {
		t.Errorf("SHALLOW COPY CORRUPTION: dm.Extracted.Base64Fields was mutated via clone! Got %v, want val1", dm.Extracted.Base64Fields["field1"])
	}
	if len(dm.PowerDNS.Tags) != 1 || dm.PowerDNS.Metadata["k1"] != "v1" {
		t.Errorf("SHALLOW COPY CORRUPTION: dm.PowerDNS was mutated via clone!")
	}
}

func TestDNSMessage_Clone_ConcurrentMapWrite_Panic(t *testing.T) {
	// Reproduce Bug C: concurrent map writes on Extracted.Base64Fields
	// When dm is cloned, clone.Extracted points to the SAME struct with the SAME map.
	// Two sibling workers running in parallel and modifying/extracting fields
	// will write to the same map concurrently -> Go fatal runtime panic!
	dm := AcquireDNSMessage()
	defer dm.Release()

	dm.Extracted = &TransformExtracted{
		Base64Fields: make(map[string]interface{}),
	}
	dm.Extracted.Base64Fields["init"] = "val"

	clone := dm.Clone()
	defer clone.Release()

	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		for i := 0; i < 500; i++ {
			dm.Extracted.Base64Fields[fmt.Sprintf("k_%d", i)] = i
		}
	}()

	go func() {
		defer wg.Done()
		for i := 0; i < 500; i++ {
			clone.Extracted.Base64Fields[fmt.Sprintf("k_clone_%d", i)] = i
		}
	}()

	wg.Wait()
}

func TestDNSNetInfo_SetQueryIP_OverridesBinaryBuffer(t *testing.T) {
	dm := DNSMessage{}
	dm.Init()

	// 1. Initial binary ingress
	dm.NetworkInfo.SetQueryIPBytes([]byte{192, 168, 1, 50})
	dm.NetworkInfo.SetResponseIPBytes([]byte{8, 8, 8, 8})

	if dm.NetworkInfo.GetQueryIP() != "192.168.1.50" {
		t.Fatalf("setup failed: expected 192.168.1.50, got %s", dm.NetworkInfo.GetQueryIP())
	}
	if dm.NetworkInfo.GetResponseIP() != "8.8.8.8" {
		t.Fatalf("setup failed: expected 8.8.8.8, got %s", dm.NetworkInfo.GetResponseIP())
	}

	// 2. Override with string (e.g., hash SHA or rewrite)
	dm.NetworkInfo.SetQueryIP("hash-sha-query-ip")
	dm.NetworkInfo.SetResponseIP("10.0.0.1")

	// Ensure binary length is reset
	if dm.NetworkInfo.QueryIPLen != 0 {
		t.Errorf("expected QueryIPLen 0, got %d", dm.NetworkInfo.QueryIPLen)
	}
	if dm.NetworkInfo.ResponseIPLen != 0 {
		t.Errorf("expected ResponseIPLen 0, got %d", dm.NetworkInfo.ResponseIPLen)
	}

	// Ensure getters return updated string
	if dm.NetworkInfo.GetQueryIP() != "hash-sha-query-ip" {
		t.Errorf("expected QueryIP 'hash-sha-query-ip', got %s", dm.NetworkInfo.GetQueryIP())
	}
	if dm.NetworkInfo.GetResponseIP() != "10.0.0.1" {
		t.Errorf("expected ResponseIP '10.0.0.1', got %s", dm.NetworkInfo.GetResponseIP())
	}

	// Ensure JSON serializer uses the string
	var jsonBuf bytes.Buffer
	dm.NetworkInfo.WriteQueryIPJSON(&jsonBuf)
	if jsonBuf.String() != `"hash-sha-query-ip"` {
		t.Errorf("expected JSON `\"hash-sha-query-ip\"`, got %s", jsonBuf.String())
	}

	jsonBuf.Reset()
	dm.NetworkInfo.WriteResponseIPJSON(&jsonBuf)
	if jsonBuf.String() != `"10.0.0.1"` {
		t.Errorf("expected JSON `\"10.0.0.1\"`, got %s", jsonBuf.String())
	}

	// Ensure Text serializer uses the string
	var textBuf bytes.Buffer
	dm.NetworkInfo.WriteQueryIPText(&textBuf)
	if textBuf.String() != "hash-sha-query-ip" {
		t.Errorf("expected Text 'hash-sha-query-ip', got %s", textBuf.String())
	}

	textBuf.Reset()
	dm.NetworkInfo.WriteResponseIPText(&textBuf)
	if textBuf.String() != "10.0.0.1" {
		t.Errorf("expected Text '10.0.0.1', got %s", textBuf.String())
	}
}

func TestDNSMessage_Init_ClearsAndCapsSlices(t *testing.T) {
	dm := DNSMessage{}
	dm.Init()

	// 1. Small slices (cap <= maxPooledSliceCap): backing array is reused and elements are zeroed
	answers := make([]DNSAnswer, 1, 16)
	answers[0] = DNSAnswer{Name: "leaked.example.com", Rdata: "1.2.3.4"}
	options := make([]DNSOption, 1, 8)
	options[0] = DNSOption{Code: 8, Name: "CSUBNET", Data: "1.2.3.0/24"}

	dm.DNS.DNSRRs.Answers = answers
	dm.EDNS.Options = options

	dm.Init()

	if cap(dm.DNS.DNSRRs.Answers) != 16 || len(dm.DNS.DNSRRs.Answers) != 0 {
		t.Fatalf("expected Answers cap=16 len=0, got cap=%d len=%d", cap(dm.DNS.DNSRRs.Answers), len(dm.DNS.DNSRRs.Answers))
	}
	if answers[0] != (DNSAnswer{}) {
		t.Errorf("expected backing array element to be cleared, got %+v", answers[0])
	}
	if cap(dm.EDNS.Options) != 8 || len(dm.EDNS.Options) != 0 {
		t.Fatalf("expected Options cap=8 len=0, got cap=%d len=%d", cap(dm.EDNS.Options), len(dm.EDNS.Options))
	}
	if options[0] != (DNSOption{}) {
		t.Errorf("expected Options backing array element to be cleared, got %+v", options[0])
	}

	// 2. Oversized slices (cap > maxPooledSliceCap): backing array is dropped so pool cannot stay bloated
	dm.DNS.DNSRRs.Answers = make([]DNSAnswer, 100, 1024)
	dm.DNS.DNSRRs.Nameservers = make([]DNSAnswer, 100, 1024)
	dm.DNS.DNSRRs.Records = make([]DNSAnswer, 100, 1024)
	dm.EDNS.Options = make([]DNSOption, 100, 1024)

	dm.Init()

	if cap(dm.DNS.DNSRRs.Answers) != 0 || cap(dm.DNS.DNSRRs.Nameservers) != 0 || cap(dm.DNS.DNSRRs.Records) != 0 || cap(dm.EDNS.Options) != 0 {
		t.Fatalf(
			"expected oversized slices to be released (cap=0), got Answers=%d Nameservers=%d Records=%d Options=%d",
			cap(dm.DNS.DNSRRs.Answers), cap(dm.DNS.DNSRRs.Nameservers), cap(dm.DNS.DNSRRs.Records), cap(dm.EDNS.Options),
		)
	}
}
