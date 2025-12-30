package workers

import (
	"fmt"
	"log"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/dmachard/go-dnscollector/dnsutils"
	"github.com/dmachard/go-dnscollector/pkgconfig"
	"github.com/dmachard/go-logger"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

func Test_LogFileText(t *testing.T) {
	testcases := []struct {
		mode    string
		pattern string
	}{
		{
			mode:    pkgconfig.ModeText,
			pattern: "0b dns.collector A",
		},
		{
			mode:    pkgconfig.ModeJSON,
			pattern: "\"qname\":\"dns.collector\"",
		},
		{
			mode:    pkgconfig.ModeFlatJSON,
			pattern: "\"dns.qname\":\"dns.collector\"",
		},
	}

	for i, tc := range testcases {
		t.Run(tc.mode, func(t *testing.T) {

			// create a temp file
			f, err := os.CreateTemp("", fmt.Sprintf("temp_logfile%d", i))
			if err != nil {
				log.Fatal(err)
			}
			defer os.Remove(f.Name()) // clean up

			// config
			config := pkgconfig.GetDefaultConfig()
			config.Loggers.LogFile.FilePath = f.Name()
			config.Loggers.LogFile.Mode = tc.mode
			config.Loggers.LogFile.FlushInterval = 0

			// init generator in testing mode
			g := NewLogFile(config, logger.New(false), "test")

			// start the logger
			go g.StartCollect()

			// send fake dns message to logger
			dm := dnsutils.GetFakeDNSMessage()
			dm.DNSTap.Identity = dnsutils.DNSTapIdentityTest
			g.GetInputChannel() <- dm

			time.Sleep(time.Second)
			g.Stop()

			// read temp file and check content
			data := make([]byte, 1024)
			count, err := f.Read(data)
			if err != nil {
				log.Fatal(err)
			}

			pattern := regexp.MustCompile(tc.pattern)
			if !pattern.MatchString(string(data[:count])) {
				t.Errorf("logfile test error want %s, got: %s", tc.pattern, string(data[:count]))
			}
		})
	}
}

func Test_LogFileWrite_PcapMode(t *testing.T) {
	// create a temp file
	f, err := os.CreateTemp("", "temp_pcapfile")
	if err != nil {
		log.Fatal(err)
	}
	defer os.Remove(f.Name()) // clean up

	// config
	config := pkgconfig.GetDefaultConfig()
	config.Loggers.LogFile.FilePath = f.Name()
	config.Loggers.LogFile.Mode = pkgconfig.ModePCAP

	// init generator in testing mode
	g := NewLogFile(config, logger.New(false), "test")

	// init fake dm
	dm := dnsutils.GetFakeDNSMessage()

	// fake network packet
	pkt := []gopacket.SerializableLayer{}

	eth := &layers.Ethernet{SrcMAC: net.HardwareAddr{0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
		DstMAC: net.HardwareAddr{0x00, 0x00, 0x00, 0x00, 0x00, 0x00}}
	eth.EthernetType = layers.EthernetTypeIPv4

	ip4 := &layers.IPv4{Version: 4, TTL: 64}
	ip4.SrcIP = net.ParseIP("127.0.0.1")
	ip4.DstIP = net.ParseIP("127.0.0.1")
	ip4.Protocol = layers.IPProtocolUDP

	udp := &layers.UDP{}
	udp.SrcPort = layers.UDPPort(1000)
	udp.DstPort = layers.UDPPort(53)
	udp.SetNetworkLayerForChecksum(ip4)

	pkt = append(pkt, gopacket.Payload(dm.DNS.Payload), udp, ip4, eth)

	// write fake dns message and network packet
	g.WriteToPcap(dm, pkt)

	// read temp file and check content
	data := make([]byte, 100)
	count, err := f.Read(data)
	if err != nil {
		t.Errorf("unexpected error: %e", err)
	}

	if count == 0 {
		t.Errorf("no data in pcap file")
	}
}

func removeLogFiles(fileDir string, filePattern string) error {
	entries, err := os.ReadDir(fileDir)

	if err != nil {
		return err
	}

	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		if !strings.Contains(entry.Name(), filePattern) {
			continue
		}

		os.Remove(filepath.Join(fileDir, entry.Name()))
	}

	return nil
}

func getLogFiles(fileDir string, filePattern string) (map[string][]string, error) {
	entries, err := os.ReadDir(fileDir)
	logFiles := make(map[string][]string)

	if err != nil {
		return logFiles, err
	}

	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		if !strings.Contains(entry.Name(), filePattern) {
			continue
		}

		parts := strings.Split(entry.Name(), ".")

		ext := parts[len(parts)-1]

		if _, found := logFiles[ext]; !found {
			logFiles[ext] = []string{}
		}
		logFiles[ext] = append(logFiles[ext], entry.Name())
	}

	return logFiles, nil
}

func TestRotation(t *testing.T) {
	filePattern := "dnscollectortest"
	removeLogFiles(os.TempDir(), filePattern)

	tests := []struct {
		test             string
		rotationInterval int
		maxSize          int
		queries          int
		expectedFiles    int
	}{
		{"size-no-queries", 0, 1, 1, 1},   /* no rotation expected */
		{"size-rotation", 0, 1, 1500, 3},  /* two size based rotations expected */
		{"timer-only", 1, 100, 1500, 2},   /* one timer based rotation expected */
		{"timer-and-size", 1, 1, 1500, 4}, /* one timer and two size based rotations expected */
	}

	wg := sync.WaitGroup{}

	for _, testCase := range tests {
		wg.Add(1)
		t.Run(testCase.test, func(t *testing.T) {
			go func() {
				config := pkgconfig.GetDefaultConfig()
				config.Loggers.LogFile.FilePath = os.TempDir() + "/" + filePattern + "." + testCase.test
				config.Loggers.LogFile.Mode = pkgconfig.ModeFlatJSON
				config.Loggers.LogFile.MaxSize = testCase.maxSize
				config.Loggers.LogFile.RotationInterval = testCase.rotationInterval
				config.Loggers.LogFile.ChannelBufferSize = 1

				w := NewLogFile(config, logger.New(false), "testrotation")

				go w.StartCollect()

				for i := 0; i < testCase.queries; i++ {
					w.GetInputChannel() <- dnsutils.GetFakeDNSMessage()
				}
				time.Sleep(1100 * time.Millisecond)

				w.Stop()
				wg.Done()
			}()
		})
	}

	wg.Wait()

	/* check if we have the expected number of files in tmp directory */
	logFiles, err := getLogFiles(os.TempDir(), filePattern)
	if err != nil {
		t.Error(err)
	}

	for _, testCase := range tests {
		if testCase.expectedFiles != len(logFiles[testCase.test]) {
			t.Error("number of rotation files does not match", testCase.test)
		}
	}
}
