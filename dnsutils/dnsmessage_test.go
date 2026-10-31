package dnsutils

import (
	"bytes"
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
