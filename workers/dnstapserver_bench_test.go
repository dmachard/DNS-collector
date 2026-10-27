package workers

import (
	"bufio"
	"fmt"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/dmachard/go-dnscollector/v3/dnsutils"
	"github.com/dmachard/go-dnscollector/v3/pkg/config"
	"github.com/dmachard/go-framestream"
	"github.com/dmachard/go-logger"
	"google.golang.org/protobuf/proto"
)

func benchmarkDNSTapProcessorWithWorkers(b *testing.B, numWorkers int) {
	cfg := config.GetDefaultConfig()
	cfg.Collectors.Dnstap.DisableDNSParser = false
	cfg.Global.Worker.ChannelBufferSize = 65536
	cfg.Collectors.Dnstap.NumWorkers = numWorkers

	devNull := NewDevNull(cfg, logger.New(false), "devnull")
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

	proc := NewDNSTapProcessor(1, "bench-peer", cfg, logger.New(false), "bench-proc", cfg.Global.Worker.ChannelBufferSize)
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

func Benchmark_DNSTapProcessor(b *testing.B) {
	benchmarkDNSTapProcessorWithWorkers(b, 0)
}

func Benchmark_DNSTapProcessor_MonoThread(b *testing.B) {
	benchmarkDNSTapProcessorWithWorkers(b, 0)
}

func Benchmark_DNSTapProcessor_WorkerPool_4(b *testing.B) {
	benchmarkDNSTapProcessorWithWorkers(b, 4)
}

func Benchmark_DNSTapProcessor_WorkerPool_8(b *testing.B) {
	benchmarkDNSTapProcessorWithWorkers(b, 8)
}

func Test_DNSTapProcessor_FramestreamBehavior(t *testing.T) {
	cfg := config.GetDefaultConfig()
	cfg.Collectors.Dnstap.DisableDNSParser = false
	cfg.Global.Worker.ChannelBufferSize = 1000

	devNull := NewDevNull(cfg, logger.New(false), "devnull")
	go devNull.StartCollect()
	defer devNull.Stop()

	dnsquery, err := dnsutils.GetFakeDNS()
	if err != nil {
		t.Fatalf("dns question pack error: %v", err)
	}

	dtQuery := GetFakeDNSTap(dnsquery)
	data, err := proto.Marshal(dtQuery)
	if err != nil {
		t.Fatalf("dnstap proto marshal error: %v", err)
	}

	proc := NewDNSTapProcessor(1, "test-peer", cfg, logger.New(false), "test-proc", 1000)
	proc.SetDefaultRoutes([]Worker{devNull})
	go proc.StartCollect()
	defer proc.Stop()

	dataChan := proc.GetDataChannel()

	var wg sync.WaitGroup
	wg.Add(1)

	go func() {
		defer wg.Done()

		for i := 0; i < 500; i++ {
			buf := make([]byte, len(data))
			copy(buf, data)
			dataChan <- buf
			time.Sleep(10 * time.Microsecond)
		}
	}()

	wg.Wait()
}

func benchmarkDnstapServerReadBuf(b *testing.B, readBufSize int) {
	cfg := config.GetDefaultConfig()
	cfg.Collectors.Dnstap.ListenPort = 6001
	cfg.Collectors.Dnstap.ReadBufferSize = readBufSize
	cfg.Global.Worker.ChannelBufferSize = 100000

	devNull := NewDevNull(cfg, logger.New(false), "devnull")
	go devNull.StartCollect()
	defer devNull.Stop()

	server := NewDnstapServer([]Worker{devNull}, cfg, logger.New(false), "bench-server")
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

func getFreePort(b *testing.B) int {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		b.Fatalf("failed to get free port: %v", err)
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}

func benchmarkDnstapServerTCP(b *testing.B, burstSize int, numWorkers int, bufferSize int) {
	port := getFreePort(b)
	cfg := config.GetDefaultConfig()
	cfg.Collectors.Dnstap.ListenPort = port
	cfg.Collectors.Dnstap.UpstreamBatching = true
	cfg.Collectors.Dnstap.NumWorkers = numWorkers
	cfg.Global.Worker.ChannelBufferSize = bufferSize

	devNull := NewDevNull(cfg, logger.New(false), "devnull")
	go devNull.StartCollect()
	defer devNull.Stop()

	server := NewDnstapServer([]Worker{devNull}, cfg, logger.New(false), "bench-server")
	go server.StartCollect()
	defer server.Stop()
	time.Sleep(50 * time.Millisecond)

	conn, err := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", port))
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

	if burstSize <= 0 {
		for i := 0; i < b.N; i++ {
			if err := fs.SendFrame(frame); err != nil {
				b.Fatalf("send frame error: %v", err)
			}
		}
		_ = w.Flush()
	} else {
		for i := 0; i < b.N; i += burstSize {
			count := burstSize
			if i+count > b.N {
				count = b.N - i
			}
			for j := 0; j < count; j++ {
				if err := fs.SendFrame(frame); err != nil {
					b.Fatalf("send frame error: %v", err)
				}
			}
			if err := w.Flush(); err != nil {
				b.Fatalf("flush error: %v", err)
			}
		}
	}
}

// End-to-end Framestream/TCP with UpstreamBatching and single worker (num-workers: 0)
func Benchmark_DnstapServer_TCP_MonoWorker_Continuous(b *testing.B) {
	benchmarkDnstapServerTCP(b, 0, 0, 2048)
}

func Benchmark_DnstapServer_TCP_MonoWorker_MicroBurst_1(b *testing.B) {
	benchmarkDnstapServerTCP(b, 1, 0, 2048)
}

func Benchmark_DnstapServer_TCP_MonoWorker_MicroBurst_10(b *testing.B) {
	benchmarkDnstapServerTCP(b, 10, 0, 2048)
}

func Benchmark_DnstapServer_TCP_MonoWorker_MicroBurst_50(b *testing.B) {
	benchmarkDnstapServerTCP(b, 50, 0, 2048)
}

func Benchmark_DnstapServer_TCP_WorkerPool4_MicroBurst_1(b *testing.B) {
	benchmarkDnstapServerTCP(b, 1, 4, 2048)
}
