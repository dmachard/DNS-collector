package workers

import (
	"fmt"
	"net"
	"regexp"
	"testing"
	"time"

	"github.com/dmachard/go-dnscollector/v2/pkgconfig"
	"github.com/dmachard/go-logger"
	"github.com/dmachard/go-netutils"
	powerdns_protobuf "github.com/dmachard/go-powerdns-protobuf"
	"github.com/miekg/dns"
	"google.golang.org/protobuf/proto"
)

func TestPowerDNS_Run(t *testing.T) {
	g := GetWorkerForTest(pkgconfig.DefaultBufferSize)

	c := NewPdnsServer([]Worker{g}, pkgconfig.GetDefaultConfig(), logger.New(false), "test")
	go c.StartCollect()

	// wait before to connect
	time.Sleep(1 * time.Second)
	conn, err := net.Dial(netutils.SocketTCP, ":6001")
	if err != nil {
		t.Error("could not connect to TCP server: ", err)
	}
	defer conn.Close()
}

func Test_PowerDNSProcessor(t *testing.T) {

	fl := GetWorkerForTest(pkgconfig.DefaultBufferSize)

	// init the dnstap consumer
	consumer := NewPdnsProcessor(0, "peername", pkgconfig.GetDefaultConfig(), logger.New(false), "test", 512)
	consumer.AddDefaultRoute(fl)
	consumer.AddDroppedRoute(fl)

	// init the powerdns processor
	dnsQname := pkgconfig.ValidDomain
	dnsQuestion := powerdns_protobuf.PBDNSMessage_DNSQuestion{QName: &dnsQname}

	dm := &powerdns_protobuf.PBDNSMessage{}
	dm.ServerIdentity = []byte(pkgconfig.ExpectedIdentity)
	dm.Type = powerdns_protobuf.PBDNSMessage_DNSQueryType.Enum()
	dm.SocketProtocol = powerdns_protobuf.PBDNSMessage_DNSCryptUDP.Enum()
	dm.SocketFamily = powerdns_protobuf.PBDNSMessage_INET.Enum()
	dm.Question = &dnsQuestion

	data, _ := proto.Marshal(dm)

	// run the consumer with a fake logger
	go consumer.StartCollect()

	// add packet to consumer
	consumer.GetDataChannel() <- data

	// read dns message from dnstap consumer
	batch := <-fl.GetInputChannel()
	if len(batch.Messages) == 0 || batch.Messages[0].DNSTap.Identity != pkgconfig.ExpectedIdentity {
		t.Errorf("invalid identity in dns message: %v", batch.Messages)
	}
}

func Test_PowerDNSProcessor_AddDNSPayload_Valid(t *testing.T) {
	// run the consumer with a fake logger
	fl := GetWorkerForTest(pkgconfig.DefaultBufferSize)

	cfg := pkgconfig.GetDefaultConfig()
	cfg.Collectors.PowerDNS.AddDNSPayload = true

	// init the powerdns processor
	consumer := NewPdnsProcessor(0, "peername", cfg, logger.New(false), "test", 512)
	consumer.AddDefaultRoute(fl)
	consumer.AddDroppedRoute(fl)

	// prepare powerdns message
	dnsQname := pkgconfig.ValidDomain
	dnsQuestion := powerdns_protobuf.PBDNSMessage_DNSQuestion{QName: &dnsQname}

	dm := &powerdns_protobuf.PBDNSMessage{}
	dm.ServerIdentity = []byte(pkgconfig.ExpectedIdentity)
	dm.Id = proto.Uint32(2000)
	dm.Type = powerdns_protobuf.PBDNSMessage_DNSQueryType.Enum()
	dm.SocketProtocol = powerdns_protobuf.PBDNSMessage_DNSCryptUDP.Enum()
	dm.SocketFamily = powerdns_protobuf.PBDNSMessage_INET.Enum()
	dm.Question = &dnsQuestion

	data, _ := proto.Marshal(dm)

	// start the consumer and add packet
	go consumer.StartCollect()

	consumer.GetDataChannel() <- data

	// read dns message
	batch := <-fl.GetInputChannel()
	if len(batch.Messages) == 0 {
		t.Fatalf("expected message in batch")
	}
	msg := batch.Messages[0]
	if msg.DNS.Length == 0 {
		t.Errorf("invalid length got %d", msg.DNS.Length)
	}
	if len(msg.DNS.Payload) == 0 {
		t.Errorf("invalid payload length %d", len(msg.DNS.Payload))
	}

	// valid dns payload ?
	var decodedPayload dns.Msg
	err := decodedPayload.Unpack(msg.DNS.Payload)
	if err != nil {
		t.Errorf("unpack error %s", err)
	}
	if decodedPayload.Question[0].Name != pkgconfig.ValidDomain {
		t.Errorf("invalid qname in payload: %s", decodedPayload.Question[0].Name)
	}
}

func Test_PowerDNSProcessor_AddDNSPayload_InvalidLabelLength(t *testing.T) {

	fl := GetWorkerForTest(pkgconfig.DefaultBufferSize)

	cfg := pkgconfig.GetDefaultConfig()
	cfg.Collectors.PowerDNS.AddDNSPayload = true

	// init the dnstap consumer
	consumer := NewPdnsProcessor(0, "peername", cfg, logger.New(false), "test", 512)
	consumer.AddDefaultRoute(fl)
	consumer.AddDroppedRoute(fl)

	// prepare dnstap
	dnsQname := pkgconfig.BadDomainLabel
	dnsQuestion := powerdns_protobuf.PBDNSMessage_DNSQuestion{QName: &dnsQname}

	dm := &powerdns_protobuf.PBDNSMessage{}
	dm.ServerIdentity = []byte("powerdnspb")
	dm.Id = proto.Uint32(2000)
	dm.Type = powerdns_protobuf.PBDNSMessage_DNSQueryType.Enum()
	dm.SocketProtocol = powerdns_protobuf.PBDNSMessage_DNSCryptUDP.Enum()
	dm.SocketFamily = powerdns_protobuf.PBDNSMessage_INET.Enum()
	dm.Question = &dnsQuestion

	data, _ := proto.Marshal(dm)

	// run the consumer with a fake logger
	go consumer.StartCollect()

	// add packet to consumer
	consumer.GetDataChannel() <- data

	// read dns message from dnstap consumer
	batch := <-fl.GetInputChannel()
	if len(batch.Messages) == 0 || !batch.Messages[0].DNS.MalformedPacket {
		t.Errorf("DNS message should malformed")
	}
}

func Test_PowerDNSProcessor_AddDNSPayload_QnameTooLongDomain(t *testing.T) {

	fl := GetWorkerForTest(pkgconfig.DefaultBufferSize)

	cfg := pkgconfig.GetDefaultConfig()
	cfg.Collectors.PowerDNS.AddDNSPayload = true

	// init the dnstap consumer
	consumer := NewPdnsProcessor(0, "peername", cfg, logger.New(false), "test", 512)
	consumer.AddDefaultRoute(fl)
	consumer.AddDroppedRoute(fl)

	// prepare dnstap
	dnsQname := pkgconfig.BadVeryLongDomain
	dnsQuestion := powerdns_protobuf.PBDNSMessage_DNSQuestion{QName: &dnsQname}

	dm := &powerdns_protobuf.PBDNSMessage{}
	dm.ServerIdentity = []byte("powerdnspb")
	dm.Type = powerdns_protobuf.PBDNSMessage_DNSQueryType.Enum()
	dm.SocketProtocol = powerdns_protobuf.PBDNSMessage_DNSCryptUDP.Enum()
	dm.SocketFamily = powerdns_protobuf.PBDNSMessage_INET.Enum()
	dm.Question = &dnsQuestion

	data, _ := proto.Marshal(dm)

	// run the consumer with a fake logger
	go consumer.StartCollect()

	// add packet to consumer
	consumer.GetDataChannel() <- data

	// read dns message from dnstap consumer
	batch := <-fl.GetInputChannel()
	if len(batch.Messages) == 0 || !batch.Messages[0].DNS.MalformedPacket {
		t.Errorf("DNS message should malformed because of qname too long")
	}
}

func Test_PowerDNSProcessor_AddDNSPayload_AnswersTooLongDomain(t *testing.T) {

	fl := GetWorkerForTest(pkgconfig.DefaultBufferSize)

	cfg := pkgconfig.GetDefaultConfig()
	cfg.Collectors.PowerDNS.AddDNSPayload = true

	// init the dnstap consumer
	consumer := NewPdnsProcessor(0, "peername", cfg, logger.New(false), "test", 512)
	consumer.AddDefaultRoute(fl)
	consumer.AddDroppedRoute(fl)

	// prepare dnstap
	dnsQname := pkgconfig.ValidDomain
	dnsQuestion := powerdns_protobuf.PBDNSMessage_DNSQuestion{QName: &dnsQname}

	rrQname := pkgconfig.BadVeryLongDomain
	rrDNS := powerdns_protobuf.PBDNSMessage_DNSResponse_DNSRR{
		Name:  &rrQname,
		Class: proto.Uint32(1),
		Type:  proto.Uint32(1),
		Rdata: []byte{0x01, 0x00, 0x00, 0x01},
	}
	dnsReply := powerdns_protobuf.PBDNSMessage_DNSResponse{}
	dnsReply.Rrs = append(dnsReply.Rrs, &rrDNS)

	dm := &powerdns_protobuf.PBDNSMessage{}
	dm.ServerIdentity = []byte("powerdnspb")
	dm.Type = powerdns_protobuf.PBDNSMessage_DNSResponseType.Enum()
	dm.SocketProtocol = powerdns_protobuf.PBDNSMessage_DNSCryptUDP.Enum()
	dm.SocketFamily = powerdns_protobuf.PBDNSMessage_INET.Enum()
	dm.Question = &dnsQuestion
	dm.Response = &dnsReply

	data, _ := proto.Marshal(dm)

	// run the consumer with a fake logger
	go consumer.StartCollect()

	// add packet to consumer
	consumer.GetDataChannel() <- data

	// read dns message from dnstap consumer
	batch := <-fl.GetInputChannel()
	if len(batch.Messages) == 0 || !batch.Messages[0].DNS.MalformedPacket {
		t.Errorf("DNS message is not malformed")
	}
}

// test for issue https://github.com/dmachard/go-dnscollector/v2/issues/568
func Test_PowerDNSProcessor_BufferLoggerIsFull(t *testing.T) {

	fl := GetWorkerForTest(pkgconfig.DefaultBufferOne)

	// redirect stdout output to bytes buffer
	logsChan := make(chan logger.LogEntry, 512)
	lg := logger.New(true)
	lg.SetOutputChannel((logsChan))

	// init the dnstap consumer
	cfg := pkgconfig.GetDefaultConfig()
	cfg.Global.Worker.BatchSize = 1
	cfg.Global.Worker.InternalMonitor = 1
	consumer := NewPdnsProcessor(0, "peername", cfg, lg, "test", 512)
	consumer.AddDefaultRoute(fl)
	consumer.AddDroppedRoute(fl)

	// init the powerdns processor
	dnsQname := pkgconfig.ValidDomain
	dnsQuestion := powerdns_protobuf.PBDNSMessage_DNSQuestion{QName: &dnsQname}

	dm := &powerdns_protobuf.PBDNSMessage{}
	dm.ServerIdentity = []byte(pkgconfig.ExpectedIdentity)
	dm.Type = powerdns_protobuf.PBDNSMessage_DNSQueryType.Enum()
	dm.SocketProtocol = powerdns_protobuf.PBDNSMessage_DNSCryptUDP.Enum()
	dm.SocketFamily = powerdns_protobuf.PBDNSMessage_INET.Enum()
	dm.Question = &dnsQuestion

	data, _ := proto.Marshal(dm)

	// run the consumer with a fake logger
	go consumer.StartCollect()
	defer consumer.Stop()

	// add packets to consumer
	for i := 0; i < 512; i++ {
		consumer.GetDataChannel() <- data
	}

	// waiting monitor to run in consumer
	time.Sleep(2 * time.Second)

	for entry := range logsChan {
		fmt.Println(entry)
		pattern := regexp.MustCompile(pkgconfig.ExpectedBufferMsg511)
		if pattern.MatchString(entry.Message) {
			break
		}
	}

	// read dns message from dnstap consumer
	batch := <-fl.GetInputChannel()
	if len(batch.Messages) == 0 || batch.Messages[0].DNSTap.Identity != pkgconfig.ExpectedIdentity {
		t.Errorf("invalid identity in dns message: %v", batch.Messages)
	}

	// send second shot of packets to consumer
	for i := 0; i < 1024; i++ {
		consumer.GetDataChannel() <- data
	}

	// waiting monitor to run in consumer
	time.Sleep(2 * time.Second)
	for entry := range logsChan {
		fmt.Println(entry)
		pattern := regexp.MustCompile(pkgconfig.ExpectedBufferMsg1023)
		if pattern.MatchString(entry.Message) {
			break
		}
	}

	// read just one dns message from dnstap consumer
	batch2 := <-fl.GetInputChannel()
	if len(batch2.Messages) == 0 || batch2.Messages[0].DNSTap.Identity != pkgconfig.ExpectedIdentity {
		t.Errorf("invalid identity in second dns message: %v", batch2.Messages)
	}
}

func Test_PowerDNSProcessor_NewFields_AuthRequest_Ede_TraceID(t *testing.T) {
	fl := GetWorkerForTest(pkgconfig.DefaultBufferSize)

	consumer := NewPdnsProcessor(0, "peername", pkgconfig.GetDefaultConfig(), logger.New(false), "test", 512)
	consumer.AddDefaultRoute(fl)

	dnsQname := pkgconfig.ValidDomain
	dnsQuestion := powerdns_protobuf.PBDNSMessage_DNSQuestion{QName: &dnsQname}

	authReqType := powerdns_protobuf.PBDNSMessage_AuthRequest
	edeCode := uint32(15)
	edeText := "Blocked by RPZ"
	traceID := []byte{0x4b, 0xf9, 0x2f, 0x35, 0x77, 0xb3, 0x4d, 0xa6, 0xa3, 0xce, 0x92, 0x9d, 0x0e, 0x0e, 0x47, 0x36}

	dm := &powerdns_protobuf.PBDNSMessage{
		ServerIdentity:       []byte(pkgconfig.ExpectedIdentity),
		Type:                 (*powerdns_protobuf.PBDNSMessage_Type)(&authReqType),
		SocketProtocol:       powerdns_protobuf.PBDNSMessage_DNSCryptUDP.Enum(),
		SocketFamily:         powerdns_protobuf.PBDNSMessage_INET.Enum(),
		Question:             &dnsQuestion,
		Ede:                  &edeCode,
		EdeText:              &edeText,
		OpenTelemetryTraceID: traceID,
	}

	data, err := proto.Marshal(dm)
	if err != nil {
		t.Fatalf("could not marshal powerdns proto: %v", err)
	}

	go consumer.StartCollect()
	consumer.GetDataChannel() <- data

	batch := <-fl.GetInputChannel()
	if len(batch.Messages) == 0 {
		t.Fatal("no message received")
	}

	msg := batch.Messages[0]
	if msg.DNSTap.Operation != "AUTH_QUERY" {
		t.Errorf("expected operation AUTH_QUERY, got %s", msg.DNSTap.Operation)
	}
	if msg.PowerDNS == nil {
		t.Fatal("expected PowerDNS struct to be non-nil")
	}
	if msg.PowerDNS.Ede == nil || *msg.PowerDNS.Ede != 15 {
		t.Errorf("expected Ede 15, got %v", msg.PowerDNS.Ede)
	}
	if msg.PowerDNS.EdeText != "Blocked by RPZ" {
		t.Errorf("expected EdeText 'Blocked by RPZ', got %s", msg.PowerDNS.EdeText)
	}
	if msg.PowerDNS.OpenTelemetryTraceID != "4bf92f3577b34da6a3ce929d0e0e4736" {
		t.Errorf("expected OpenTelemetryTraceID '4bf92f3577b34da6a3ce929d0e0e4736', got %s", msg.PowerDNS.OpenTelemetryTraceID)
	}
}
