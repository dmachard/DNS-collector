package workers

import (
	"net"
	"testing"

	"github.com/dmachard/go-dnscollector/v3/pkg/config"
	"github.com/dmachard/go-logger"
	powerdns_protobuf "github.com/dmachard/go-powerdns-protobuf"
	"google.golang.org/protobuf/proto"
)

func getFakePowerDNSQuery() []byte {
	dnsQname := config.ValidDomain
	dnsQuestion := powerdns_protobuf.PBDNSMessage_DNSQuestion{QName: &dnsQname}

	dm := &powerdns_protobuf.PBDNSMessage{}
	dm.ServerIdentity = []byte(config.ExpectedIdentity)
	dm.Type = powerdns_protobuf.PBDNSMessage_DNSQueryType.Enum()
	dm.SocketProtocol = powerdns_protobuf.PBDNSMessage_DNSCryptUDP.Enum()
	dm.SocketFamily = powerdns_protobuf.PBDNSMessage_INET.Enum()
	dm.From = net.ParseIP("192.168.1.1").To4()
	dm.To = net.ParseIP("192.168.1.2").To4()
	dm.Question = &dnsQuestion

	data, _ := proto.Marshal(dm)
	return data
}

func getFakePowerDNSResponse() []byte {
	dnsQname := config.ValidDomain
	dnsQuestion := powerdns_protobuf.PBDNSMessage_DNSQuestion{QName: &dnsQname}

	rrName := config.ValidDomain
	rr := powerdns_protobuf.PBDNSMessage_DNSResponse_DNSRR{
		Name:  &rrName,
		Class: proto.Uint32(1),
		Type:  proto.Uint32(1),
		Rdata: []byte{0x01, 0x02, 0x03, 0x04},
	}

	dnsResponse := powerdns_protobuf.PBDNSMessage_DNSResponse{
		Rcode: proto.Uint32(0),
		Rrs:   []*powerdns_protobuf.PBDNSMessage_DNSResponse_DNSRR{&rr},
	}

	dm := &powerdns_protobuf.PBDNSMessage{}
	dm.ServerIdentity = []byte(config.ExpectedIdentity)
	dm.Type = powerdns_protobuf.PBDNSMessage_DNSResponseType.Enum()
	dm.SocketProtocol = powerdns_protobuf.PBDNSMessage_DNSCryptUDP.Enum()
	dm.SocketFamily = powerdns_protobuf.PBDNSMessage_INET.Enum()
	dm.From = net.ParseIP("192.168.1.1").To4()
	dm.To = net.ParseIP("192.168.1.2").To4()
	dm.Question = &dnsQuestion
	dm.Response = &dnsResponse

	data, _ := proto.Marshal(dm)
	return data
}

func Benchmark_PdnsProcessor_Query(b *testing.B) {
	cfg := config.GetDefaultConfig()
	cfg.Global.Worker.ChannelBufferSize = 65536

	devNull := NewDevNull(cfg, logger.New(false), "devnull")
	go devNull.StartCollect()
	defer devNull.Stop()

	consumer := NewPdnsProcessor(0, "peername", cfg, logger.New(false), "bench-pdns", 65536)
	consumer.AddDefaultRoute(devNull)
	go consumer.StartCollect()
	defer consumer.Stop()

	data := getFakePowerDNSQuery()
	dataChan := consumer.GetDataChannel()

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		dataChan <- data
	}
}

func Benchmark_PdnsProcessor_Response(b *testing.B) {
	cfg := config.GetDefaultConfig()
	cfg.Global.Worker.ChannelBufferSize = 65536

	devNull := NewDevNull(cfg, logger.New(false), "devnull")
	go devNull.StartCollect()
	defer devNull.Stop()

	consumer := NewPdnsProcessor(0, "peername", cfg, logger.New(false), "bench-pdns", 65536)
	consumer.AddDefaultRoute(devNull)
	go consumer.StartCollect()
	defer consumer.Stop()

	data := getFakePowerDNSResponse()
	dataChan := consumer.GetDataChannel()

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		dataChan <- data
	}
}

func Benchmark_PdnsProcessor_AddDNSPayload(b *testing.B) {
	cfg := config.GetDefaultConfig()
	cfg.Global.Worker.ChannelBufferSize = 65536
	cfg.Collectors.PowerDNS.AddDNSPayload = true

	devNull := NewDevNull(cfg, logger.New(false), "devnull")
	go devNull.StartCollect()
	defer devNull.Stop()

	consumer := NewPdnsProcessor(0, "peername", cfg, logger.New(false), "bench-pdns", 65536)
	consumer.AddDefaultRoute(devNull)
	go consumer.StartCollect()
	defer consumer.Stop()

	data := getFakePowerDNSResponse()
	dataChan := consumer.GetDataChannel()

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		dataChan <- data
	}
}
