package workers

import (
	"bufio"
	"net"
	"testing"
	"time"

	"github.com/dmachard/go-dnscollector/v2/dnsutils"
	"github.com/dmachard/go-dnscollector/v2/pkgconfig"
	"github.com/dmachard/go-framestream"
	"github.com/dmachard/go-logger"
	"google.golang.org/protobuf/proto"
)

func Benchmark_DNSTapProcessor(b *testing.B) {
	config := pkgconfig.GetDefaultConfig()
	config.Collectors.Dnstap.DisableDNSParser = false
	config.Collectors.Dnstap.ChannelBufferSize = 65536

	devNull := NewDevNull(config, logger.New(false), "devnull")
	go devNull.StartCollect()
	defer devNull.Stop()

	dnsquery, err := dnsutils.GetFakeDNS()
	if err != nil {
		b.Fatalf("dns question pack error: %v", err)
	}

	dtQuery := GetFakeDNSTap(dnsquery)
	data, err := proto.Marshal(dtQuery)
	if err != nil {
		b.Fatalf("dnstap proto marshal error: %v", err)
	}

	proc := NewDNSTapProcessor(1, "bench-peer", config, logger.New(false), "bench-proc", config.Collectors.Dnstap.ChannelBufferSize)
	proc.SetDefaultRoutes([]Worker{devNull})
	go proc.StartCollect()
	defer proc.Stop()

	dataChan := proc.GetDataChannel()

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		dataChan <- data
	}
}

func benchmarkDnstapServerReadBuf(b *testing.B, readBufSize int) {
	config := pkgconfig.GetDefaultConfig()
	config.Collectors.Dnstap.ListenPort = 6001
	config.Collectors.Dnstap.ReadBufferSize = readBufSize
	config.Collectors.Dnstap.ChannelBufferSize = 100000

	devNull := NewDevNull(config, logger.New(false), "devnull")
	go devNull.StartCollect()
	defer devNull.Stop()

	server := NewDnstapServer([]Worker{devNull}, config, logger.New(false), "bench-server")
	go server.StartCollect()
	time.Sleep(200 * time.Millisecond)

	conn, err := net.Dial("tcp", ":6001")
	if err != nil {
		b.Fatalf("could not connect: %v", err)
	}
	defer conn.Close()

	r := bufio.NewReader(conn)
	w := bufio.NewWriter(conn)
	fs := framestream.NewFstrm(r, w, conn, 5*time.Second, []byte("protobuf:dnstap.Dnstap"), true)
	if err := fs.InitSender(); err != nil {
		b.Fatalf("framestream init error: %v", err)
	}

	dnsquery, err := dnsutils.GetFakeDNS()
	if err != nil {
		b.Fatalf("dns question pack error: %v", err)
	}

	dtQuery := GetFakeDNSTap(dnsquery)
	data, err := proto.Marshal(dtQuery)
	if err != nil {
		b.Fatalf("dnstap proto marshal error: %v", err)
	}

	frame := &framestream.Frame{}
	frame.Write(data)

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		if err := fs.SendFrame(frame); err != nil {
			b.Fatalf("send frame error: %v", err)
		}
	}

	server.Stop()
}

func Benchmark_DnstapServer_ReadBuffer_4KB(b *testing.B) {
	benchmarkDnstapServerReadBuf(b, 4096)
}

func Benchmark_DnstapServer_ReadBuffer_64KB(b *testing.B) {
	benchmarkDnstapServerReadBuf(b, 65536)
}
