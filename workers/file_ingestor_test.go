package workers

import (
	"encoding/binary"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/dmachard/go-dnscollector/v3/dnsutils"
	"github.com/dmachard/go-dnscollector/v3/pkg/config"
	"github.com/dmachard/go-logger"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
	"github.com/miekg/dns"
)

func createTestPcapLinuxSLL(t *testing.T, dir string, qname string) string {
	t.Helper()
	pcapPath := filepath.Join(dir, "test_sll.pcap")
	f, err := os.Create(pcapPath)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	pcapWriter := pcapgo.NewWriter(f)
	if err := pcapWriter.WriteFileHeader(65536, layers.LinkTypeLinuxSLL); err != nil {
		t.Fatal(err)
	}

	msg := new(dns.Msg)
	msg.SetQuestion(dns.Fqdn(qname), dns.TypeA)
	dnsPayload, err := msg.Pack()
	if err != nil {
		t.Fatal(err)
	}

	udp := &layers.UDP{
		SrcPort: 53533,
		DstPort: 53,
	}
	ip := &layers.IPv4{
		Version:  4,
		IHL:      5,
		TTL:      64,
		Protocol: layers.IPProtocolUDP,
		SrcIP:    net.ParseIP("192.0.2.1"),
		DstIP:    net.ParseIP("192.0.2.53"),
	}
	udp.SetNetworkLayerForChecksum(ip)

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		ComputeChecksums: true,
		FixLengths:       true,
	}

	if err := gopacket.SerializeLayers(buf, opts, ip, udp, gopacket.Payload(dnsPayload)); err != nil {
		t.Fatal(err)
	}

	// Linux SLL header (16 bytes)
	sllHdr := make([]byte, 16)
	binary.BigEndian.PutUint16(sllHdr[0:2], 0) // PacketType: Host
	binary.BigEndian.PutUint16(sllHdr[2:4], 1) // ARPHRD_ETHER
	binary.BigEndian.PutUint16(sllHdr[4:6], 6) // Link layer address length
	copy(sllHdr[6:12], []byte{0x00, 0x11, 0x22, 0x33, 0x44, 0x55})
	binary.BigEndian.PutUint16(sllHdr[14:16], uint16(layers.EthernetTypeIPv4))

	sllHdr = append(sllHdr, buf.Bytes()...)
	ci := gopacket.CaptureInfo{
		Timestamp:     time.Now(),
		CaptureLength: len(sllHdr),
		Length:        len(sllHdr),
	}
	if err := pcapWriter.WritePacket(ci, sllHdr); err != nil {
		t.Fatal(err)
	}

	return pcapPath
}

func Test_FileIngestor(t *testing.T) {
	tests := []struct {
		name      string
		watchMode string
		watchDir  string
	}{
		{
			name:      "Pcap",
			watchMode: "pcap",
			watchDir:  "./../tests/testsdata/pcap/",
		},
		{
			name:      "Dnstap",
			watchMode: "dnstap",
			watchDir:  "./../tests/testsdata/dnstap/",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g := GetWorkerForTest(config.DefaultBufferSize)
			cfg := config.GetDefaultConfig()

			// watch tests data folder
			cfg.Collectors.FileIngestor.WatchMode = tt.watchMode
			cfg.Collectors.FileIngestor.WatchDir = tt.watchDir

			// init collector
			c := NewFileIngestor([]Worker{g}, cfg, logger.New(false), "test")
			go c.StartCollect()
			defer c.Stop()

			// waiting message in channel
			for {
				// read dns message from channel
				batch := <-g.GetInputChannel()

				// check qname
				if len(batch.Messages) > 0 && batch.Messages[0].DNSTap.Operation == dnsutils.DNSTapClientQuery {
					break
				}
			}
		})
	}
}

func Test_FileIngestor_LinuxSLL(t *testing.T) {
	tempDir := t.TempDir()
	expectedQname := "sll.example.com"
	createTestPcapLinuxSLL(t, tempDir, expectedQname)

	g := GetWorkerForTest(config.DefaultBufferSize)
	cfg := config.GetDefaultConfig()
	cfg.Collectors.FileIngestor.WatchMode = "pcap"
	cfg.Collectors.FileIngestor.WatchDir = tempDir

	c := NewFileIngestor([]Worker{g}, cfg, logger.New(false), "test-sll")
	go c.StartCollect()
	defer c.Stop()

	// waiting message in channel
	timeout := time.After(5 * time.Second)
	found := false
	for !found {
		select {
		case batch := <-g.GetInputChannel():
			for _, msg := range batch.Messages {
				if msg.DNS.Qname == expectedQname {
					if msg.NetworkInfo.GetQueryIP() != "192.0.2.1" {
						t.Errorf("expected QueryIP 192.0.2.1, got %s", msg.NetworkInfo.GetQueryIP())
					}
					if msg.NetworkInfo.GetResponseIP() != "192.0.2.53" {
						t.Errorf("expected ResponseIP 192.0.2.53, got %s", msg.NetworkInfo.GetResponseIP())
					}
					found = true
					break
				}
			}
		case <-timeout:
			t.Fatal("timeout waiting for SLL cooked pcap message")
		}
	}
}

func Test_FileIngestor_UnsupportedLinkType(t *testing.T) {
	tempDir := t.TempDir()
	pcapPath := filepath.Join(tempDir, "test_unsupported.pcap")
	f, err := os.Create(pcapPath)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	// Write header with an unsupported link type (e.g. AX25 = 3)
	pcapWriter := pcapgo.NewWriter(f)
	if err := pcapWriter.WriteFileHeader(65536, layers.LinkTypeAX25); err != nil {
		t.Fatal(err)
	}

	g := GetWorkerForTest(config.DefaultBufferSize)
	cfg := config.GetDefaultConfig()
	cfg.Collectors.FileIngestor.WatchMode = "pcap"
	cfg.Collectors.FileIngestor.WatchDir = tempDir

	c := NewFileIngestor([]Worker{g}, cfg, logger.New(false), "test-unsupported")
	go c.StartCollect()
	defer c.Stop()

	// Should ignore without crashing
	select {
	case <-g.GetInputChannel():
		t.Error("unexpected packet received from unsupported link type")
	case <-time.After(1 * time.Second):
		// Expected: ignored gracefully
	}
}

func Test_FileIngestor_IgnoreTempFiles(t *testing.T) {
	tempDir := t.TempDir()
	tmpPcap := filepath.Join(tempDir, "test.pcap.tmp")
	createTestPcapLinuxSLL(t, tempDir, "temp.example.com")
	_ = os.Rename(filepath.Join(tempDir, "test_sll.pcap"), tmpPcap)

	g := GetWorkerForTest(config.DefaultBufferSize)
	cfg := config.GetDefaultConfig()
	cfg.Collectors.FileIngestor.WatchMode = "pcap"
	cfg.Collectors.FileIngestor.WatchDir = tempDir

	c := NewFileIngestor([]Worker{g}, cfg, logger.New(false), "test-tmp")
	go c.StartCollect()
	defer c.Stop()

	select {
	case <-g.GetInputChannel():
		t.Error("unexpected packet received from temporary .tmp file")
	case <-time.After(1 * time.Second):
		// Expected: ignored gracefully
	}
}

func Test_FileIngestor_PartialRead_NoDuplicate(t *testing.T) {
	tempDir := t.TempDir()
	pcapPath := filepath.Join(tempDir, "partial.pcap")

	// 1. Create PCAP with packet1 + trailing truncated bytes
	createPcapWithPackets(t, pcapPath, []string{"packet1.example.com"}, true)

	g := GetWorkerForTest(config.DefaultBufferSize)
	cfg := config.GetDefaultConfig()
	cfg.Collectors.FileIngestor.WatchMode = "pcap"
	cfg.Collectors.FileIngestor.WatchDir = tempDir

	c := NewFileIngestor([]Worker{g}, cfg, logger.New(false), "test-partial")
	go c.StartCollect()
	defer c.Stop()

	// Wait for packet1
	select {
	case batch := <-g.GetInputChannel():
		if len(batch.Messages) == 0 || batch.Messages[0].DNS.Qname != "packet1.example.com" {
			t.Fatalf("expected packet1.example.com, got %+v", batch.Messages)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timeout waiting for packet1")
	}

	// 2. Rewrite/complete PCAP with packet1 and packet2 (clean file)
	createPcapWithPackets(t, pcapPath, []string{"packet1.example.com", "packet2.example.com"}, false)

	// Trigger processing
	c.ProcessFile(pcapPath)

	// We MUST receive packet2, and NOT packet1 again!
	select {
	case batch := <-g.GetInputChannel():
		for _, msg := range batch.Messages {
			if msg.DNS.Qname == "packet1.example.com" {
				t.Fatalf("duplicate detected! received packet1.example.com a second time")
			}
			if msg.DNS.Qname == "packet2.example.com" {
				// Success!
				return
			}
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timeout waiting for packet2")
	}
}

func createPcapWithPackets(t *testing.T, filePath string, qnames []string, appendCorruptedBytes bool) {
	t.Helper()
	f, err := os.Create(filePath)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	pcapWriter := pcapgo.NewWriter(f)
	if err := pcapWriter.WriteFileHeader(65536, layers.LinkTypeLinuxSLL); err != nil {
		t.Fatal(err)
	}

	for _, qname := range qnames {
		msg := new(dns.Msg)
		msg.SetQuestion(dns.Fqdn(qname), dns.TypeA)
		dnsPayload, err := msg.Pack()
		if err != nil {
			t.Fatal(err)
		}

		udp := &layers.UDP{SrcPort: 53533, DstPort: 53}
		ip := &layers.IPv4{
			Version: 4, IHL: 5, TTL: 64, Protocol: layers.IPProtocolUDP,
			SrcIP: net.ParseIP("192.0.2.1"), DstIP: net.ParseIP("192.0.2.53"),
		}
		udp.SetNetworkLayerForChecksum(ip)

		buf := gopacket.NewSerializeBuffer()
		opts := gopacket.SerializeOptions{ComputeChecksums: true, FixLengths: true}
		_ = gopacket.SerializeLayers(buf, opts, ip, udp, gopacket.Payload(dnsPayload))

		sllHdr := make([]byte, 16)
		binary.BigEndian.PutUint16(sllHdr[0:2], 0)
		binary.BigEndian.PutUint16(sllHdr[2:4], 1)
		binary.BigEndian.PutUint16(sllHdr[4:6], 6)
		copy(sllHdr[6:12], []byte{0x00, 0x11, 0x22, 0x33, 0x44, 0x55})
		binary.BigEndian.PutUint16(sllHdr[14:16], uint16(layers.EthernetTypeIPv4))
		sllHdr = append(sllHdr, buf.Bytes()...)

		ci := gopacket.CaptureInfo{
			Timestamp:     time.Now(),
			CaptureLength: len(sllHdr),
			Length:        len(sllHdr),
		}
		if err := pcapWriter.WritePacket(ci, sllHdr); err != nil {
			t.Fatal(err)
		}
	}

	if appendCorruptedBytes {
		_, _ = f.Write([]byte{0xFF, 0xFE, 0xFD})
	}
}

func Benchmark_FileIngestor_LinuxSLL(b *testing.B) {
	tempDir := b.TempDir()
	expectedQname := "bench.sll.com"

	// Create test PCAP with SLL header containing 100 packets
	pcapPath := filepath.Join(tempDir, "bench_sll.pcap")
	f, err := os.Create(pcapPath)
	if err != nil {
		b.Fatal(err)
	}

	pcapWriter := pcapgo.NewWriter(f)
	if err := pcapWriter.WriteFileHeader(65536, layers.LinkTypeLinuxSLL); err != nil {
		b.Fatal(err)
	}

	msg := new(dns.Msg)
	msg.SetQuestion(dns.Fqdn(expectedQname), dns.TypeA)
	dnsPayload, err := msg.Pack()
	if err != nil {
		b.Fatal(err)
	}

	udp := &layers.UDP{SrcPort: 53533, DstPort: 53}
	ip := &layers.IPv4{
		Version: 4, IHL: 5, TTL: 64, Protocol: layers.IPProtocolUDP,
		SrcIP: net.ParseIP("192.0.2.1"), DstIP: net.ParseIP("192.0.2.53"),
	}
	udp.SetNetworkLayerForChecksum(ip)

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{ComputeChecksums: true, FixLengths: true}
	_ = gopacket.SerializeLayers(buf, opts, ip, udp, gopacket.Payload(dnsPayload))

	sllHdr := make([]byte, 16)
	binary.BigEndian.PutUint16(sllHdr[0:2], 0)
	binary.BigEndian.PutUint16(sllHdr[2:4], 1)
	binary.BigEndian.PutUint16(sllHdr[4:6], 6)
	copy(sllHdr[6:12], []byte{0x00, 0x11, 0x22, 0x33, 0x44, 0x55})
	binary.BigEndian.PutUint16(sllHdr[14:16], uint16(layers.EthernetTypeIPv4))
	sllHdr = append(sllHdr, buf.Bytes()...)

	ci := gopacket.CaptureInfo{
		Timestamp:     time.Now(),
		CaptureLength: len(sllHdr),
		Length:        len(sllHdr),
	}
	for i := 0; i < 100; i++ {
		_ = pcapWriter.WritePacket(ci, sllHdr)
	}
	f.Close()

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		g := GetWorkerForTest(config.DefaultBufferSize)
		cfg := config.GetDefaultConfig()
		cfg.Collectors.FileIngestor.WatchMode = "pcap"
		cfg.Collectors.FileIngestor.WatchDir = tempDir

		c := NewFileIngestor([]Worker{g}, cfg, logger.New(false), "bench-sll")
		go c.StartCollect()

		received := 0
		for received < 100 {
			batch := <-g.GetInputChannel()
			received += len(batch.Messages)
		}
		c.Stop()
	}
}
