package dnsutils

import (
	"strconv"
	"testing"

	dnstap "github.com/dmachard/go-dnstap-protobuf"
	"google.golang.org/protobuf/proto"
)

func TestDecodeDNSTapWire_QueryAndReply(t *testing.T) {
	// 1. Test Query message
	dmQuery := GetFakeDNSMessageWithPayload()
	dmQuery.DNSTap.Identity = "node-alpha"
	dmQuery.DNSTap.Version = "dnstap-1.0"
	dmQuery.DNSTap.Extra = "test-extra"
	dmQuery.DNS.Type = DNSQuery

	rawQuery, err := dmQuery.ToDNSTap(false)
	if err != nil {
		t.Fatalf("failed to encode dnstap query: %v", err)
	}

	decodedQuery := &DNSMessage{}
	decodedQuery.Init()
	if err := DecodeDNSTapWire(rawQuery, decodedQuery); err != nil {
		t.Fatalf("DecodeDNSTapWire failed on query: %v", err)
	}

	if decodedQuery.DNSTap.Identity != dmQuery.DNSTap.Identity {
		t.Errorf("expected identity %s, got %s", dmQuery.DNSTap.Identity, decodedQuery.DNSTap.Identity)
	}
	if decodedQuery.DNSTap.Operation != dmQuery.DNSTap.Operation {
		t.Errorf("expected operation %s, got %s", dmQuery.DNSTap.Operation, decodedQuery.DNSTap.Operation)
	}
	if decodedQuery.NetworkInfo.Family != "INET" {
		t.Errorf("expected family INET, got %s", decodedQuery.NetworkInfo.Family)
	}
	if decodedQuery.NetworkInfo.Protocol != dmQuery.NetworkInfo.Protocol {
		t.Errorf("expected protocol %s, got %s", dmQuery.NetworkInfo.Protocol, decodedQuery.NetworkInfo.Protocol)
	}
	if decodedQuery.NetworkInfo.QueryIP != dmQuery.NetworkInfo.QueryIP {
		t.Errorf("expected query IP %s, got %s", dmQuery.NetworkInfo.QueryIP, decodedQuery.NetworkInfo.QueryIP)
	}
	if decodedQuery.NetworkInfo.ResponseIP != dmQuery.NetworkInfo.ResponseIP {
		t.Errorf("expected response IP %s, got %s", dmQuery.NetworkInfo.ResponseIP, decodedQuery.NetworkInfo.ResponseIP)
	}
	if decodedQuery.NetworkInfo.QueryPort != dmQuery.NetworkInfo.QueryPort {
		t.Errorf("expected query port %s, got %s", dmQuery.NetworkInfo.QueryPort, decodedQuery.NetworkInfo.QueryPort)
	}
	if decodedQuery.DNS.Type != DNSQuery {
		t.Errorf("expected DNS type %s, got %s", DNSQuery, decodedQuery.DNS.Type)
	}

	// 2. Test Reply message with latency
	dmReply := GetFakeDNSMessageWithPayload()
	dmReply.DNS.Type = DNSReply
	dmReply.DNSTap.Operation = DNSTapClientResponse
	rawReply, err := dmReply.ToDNSTap(false)
	if err != nil {
		t.Fatalf("failed to encode dnstap reply: %v", err)
	}

	decodedReply := &DNSMessage{}
	decodedReply.Init()
	if err := DecodeDNSTapWire(rawReply, decodedReply); err != nil {
		t.Fatalf("DecodeDNSTapWire failed on reply: %v", err)
	}

	if decodedReply.DNS.Type != DNSReply {
		t.Errorf("expected DNS type %s, got %s", DNSReply, decodedReply.DNS.Type)
	}
}

func BenchmarkDecodeDNSTapWire(b *testing.B) {
	dm := GetFakeDNSMessageWithPayload()
	dm.DNSTap.Identity = "collector-node-01"
	dm.DNSTap.Version = "v1.0"
	dm.DNSTap.Extra = "subnet=192.168.1.0/24"
	raw, err := dm.ToDNSTap(false)
	if err != nil {
		b.Fatalf("failed to marshal: %v", err)
	}

	dmDecoded := &DNSMessage{}
	dmDecoded.Init()

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		if err := DecodeDNSTapWire(raw, dmDecoded); err != nil {
			b.Fatalf("decode failed: %v", err)
		}
	}
}

func BenchmarkDecodeDNSTapStandardProtobuf(b *testing.B) {
	dm := GetFakeDNSMessageWithPayload()
	dm.DNSTap.Identity = "collector-node-01"
	dm.DNSTap.Version = "v1.0"
	dm.DNSTap.Extra = "subnet=192.168.1.0/24"
	raw, err := dm.ToDNSTap(false)
	if err != nil {
		b.Fatalf("failed to marshal: %v", err)
	}

	dmDecoded := &DNSMessage{}
	dmDecoded.Init()
	dt := &dnstap.Dnstap{}

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		if err := proto.Unmarshal(raw, dt); err != nil {
			b.Fatalf("unmarshal failed: %v", err)
		}
		dmDecoded.DNSTap.Identity = string(dt.GetIdentity())
		dmDecoded.DNSTap.Version = string(dt.GetVersion())
		dmDecoded.DNSTap.Extra = string(dt.GetExtra())
		dmDecoded.DNSTap.Operation = DnstapOperationToString(int(dt.GetMessage().GetType()))
		queryip := dt.GetMessage().GetQueryAddress()
		if len(queryip) > 0 {
			dmDecoded.NetworkInfo.QueryIP = FastIPv4ToString(queryip)
		}
		responseip := dt.GetMessage().GetResponseAddress()
		if len(responseip) > 0 {
			dmDecoded.NetworkInfo.ResponseIP = FastIPv4ToString(responseip)
		}
		qport := dt.GetMessage().GetQueryPort()
		if qport > 0 {
			dmDecoded.NetworkInfo.QueryPort = strconv.FormatUint(uint64(qport), 10)
		}
		rport := dt.GetMessage().GetResponsePort()
		if rport > 0 {
			dmDecoded.NetworkInfo.ResponsePort = strconv.FormatUint(uint64(rport), 10)
		}
		dmDecoded.DNS.Payload = dt.GetMessage().GetQueryMessage()
		dmDecoded.DNS.Length = len(dmDecoded.DNS.Payload)
	}
}
