package dnsutils

import (
	"bytes"
	"testing"
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
