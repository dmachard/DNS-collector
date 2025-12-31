package workers

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/dmachard/go-dnscollector/dnsutils"
	"github.com/dmachard/go-dnscollector/pkgconfig"
	"github.com/dmachard/go-logger"
	"github.com/google/gopacket/pcapgo"
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
			content, err := os.ReadFile(f.Name())
			if err != nil {
				t.Fatal(err)
			}
			pattern := regexp.MustCompile(tc.pattern)
			if !pattern.MatchString(string(content)) {
				t.Errorf("logfile test error want %s, got: %s", tc.pattern, string(content))
			}
		})
	}
}

func Test_LogFilePcap_ContentVerification(t *testing.T) {
	// create a temp file
	f, err := os.CreateTemp("", "test_pcap_content")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(f.Name())

	// Config
	config := pkgconfig.GetDefaultConfig()
	config.Loggers.LogFile.FilePath = f.Name()
	config.Loggers.LogFile.Mode = pkgconfig.ModePCAP
	config.Loggers.LogFile.FlushInterval = 0

	// init Worker
	g := NewLogFile(config, logger.New(true), "test-pcap")
	go g.StartCollect()

	// send fake dns message to logger
	dm := dnsutils.GetFakeDNSMessage()
	dm.DNSTap.Identity = dnsutils.DNSTapIdentityTest
	fmt.Println(dm.NetworkInfo.Family)
	dm.DNS.Payload = []byte{
		0xaa, 0xbb, // ID
		0x01, 0x00, // Flags (Standard Query)
		0x00, 0x01, // Questions: 1
		0x00, 0x00, // Answer RRs: 0
		0x00, 0x00, // Authority RRs: 0
		0x00, 0x00, // Additional RRs: 0
		0x03, 'd', 'n', 's', // Label: dns
		0x09, 'c', 'o', 'l', 'l', 'e', 'c', 't', 'o', 'r', // Label: collector
		0x00,       // End of QName
		0x00, 0x01, // Type: A
		0x00, 0x01, // Class: IN
	}
	g.GetInputChannel() <- dm

	// stop worker
	time.Sleep(time.Second)
	g.Stop()

	// read the pcap file and verify content
	file, err := os.Open(f.Name())
	if err != nil {
		t.Fatalf("unable to open file: %v", err)
	}
	defer file.Close()

	pcapReader, err := pcapgo.NewReader(file)
	if err != nil {
		t.Fatalf("erreur lors de la lecture du header PCAP: %v", err)
	}

	// read packet
	data, ci, err := pcapReader.ReadPacketData()
	if err != nil {
		t.Fatalf("no data in pcap file: %v", err)
	}

	// assertions
	if ci.CaptureLength == 0 {
		t.Errorf("no data captured in pcap file")
	}

	// check if it's a DNS packet
	if !strings.Contains(string(data), "dns") && !strings.Contains(string(data), "collector") {
		t.Errorf("the packet does not contain DNS data")
	}
}

func removeLogFiles(tempDir string, pattern string) {
	files, _ := filepath.Glob(filepath.Join(tempDir, pattern+"*"))
	for _, f := range files {
		os.Remove(f)
	}
}

func countLogFiles(tempDir string, pattern string) int {
	files, _ := filepath.Glob(filepath.Join(tempDir, "*"+pattern+"*"))
	return len(files)
}

// how to debug logs
// $ ls -alrt | grep dnscollectortest
/*
-rw-r--r--  1 denis denis    1874 Dec 31 11:43 dnscollectortest.size-no-queries
-rw-r--r--  1 denis denis 1047566 Dec 31 11:43 dnscollectortest-1767177818392000411.size-rotation
-rw-r--r--  1 denis denis 1047566 Dec 31 11:43 dnscollectortest-1767177818400410547.size-rotation
-rw-r--r--  1 denis denis  715868 Dec 31 11:43 dnscollectortest.size-rotation
-rw-r--r--  1 denis denis       0 Dec 31 11:43 dnscollectortest.timer-only
-rw-r--r--  1 denis denis 2811000 Dec 31 11:43 dnscollectortest-1767177822411676876.timer-only
-rw-r--r--  1 denis denis 1047566 Dec 31 11:43 dnscollectortest-1767177825440587419.timer-and-size
-rw-r--r--  1 denis denis 1047566 Dec 31 11:43 dnscollectortest-1767177825450963345.timer-and-size
-rw-r--r--  1 denis denis  715868 Dec 31 11:43 dnscollectortest-1767177826452070773.timer-and-size
-rw-r--r--  1 denis denis       0 Dec 31 11:43 dnscollectortest.timer-and-size
-rw-r--r--  1 denis denis 1047566 Dec 31 11:43 dnscollectortest-1767177829468644159.max-files-limit
-rw-r--r--  1 denis denis  715868 Dec 31 11:43 dnscollectortest.max-files-limit
*/
func Test_LogFileRotation(t *testing.T) {
	filePattern := "dnscollectortest"
	tempDir := os.TempDir()
	removeLogFiles(tempDir, filePattern)

	tests := []struct {
		test             string
		rotationInterval int
		maxSize          int
		maxFiles         int
		queries          int
		expectedFiles    int
	}{
		{"size-no-queries", 0, 1, 10, 1, 1},   /* no rotation expected */
		{"size-rotation", 0, 1, 10, 1500, 3},  /* two size based rotations expected */
		{"timer-only", 1, 100, 10, 1500, 2},   /* one timer based rotation expected */
		{"timer-and-size", 1, 1, 10, 1500, 4}, /* one timer and two size based rotations expected */
		{"max-files-limit", 0, 1, 3, 1500, 3}, /* should rotate many times but only keep 2 files */
	}

	for _, tc := range tests {
		t.Run(tc.test, func(t *testing.T) {
			errChan := make(chan error, 1)
			go func() {
				testPrefix := filePattern + "." + tc.test

				config := pkgconfig.GetDefaultConfig()
				config.Loggers.LogFile.FilePath = filepath.Join(tempDir, testPrefix)
				config.Loggers.LogFile.Mode = pkgconfig.ModeJSON
				config.Loggers.LogFile.MaxSize = tc.maxSize
				config.Loggers.LogFile.MaxFiles = tc.maxFiles
				config.Loggers.LogFile.RotationInterval = tc.rotationInterval
				config.Loggers.LogFile.ChannelBufferSize = 1

				t.Logf("\n[Rotation Config - %s]\n"+
					" ├─ Interval (s): %d\n"+
					" ├─ Max Size:     %d MB\n"+
					" └─ Max Files:    %d",
					tc.test,
					config.Loggers.LogFile.RotationInterval,
					config.Loggers.LogFile.MaxSize,
					config.Loggers.LogFile.MaxFiles,
				)

				// init worker
				w := NewLogFile(config, logger.New(false), "testrotation")
				go w.StartCollect()

				// send dns queries
				for i := 0; i < tc.queries; i++ {
					dm := dnsutils.GetFakeDNSMessage()
					dm.DNS.Qname = strings.Repeat("a", 1000) // Adds 1KB per message
					w.GetInputChannel() <- dm
				}

				// Ensure we wait enough for the timer-based rotations
				time.Sleep(time.Duration(tc.rotationInterval+3) * time.Second)

				// stop worker
				w.Stop()

				// Check the results
				actualCount := countLogFiles(tempDir, tc.test)

				if actualCount != tc.expectedFiles {
					// List files to debug if it fails
					found, _ := filepath.Glob(filepath.Join(tempDir, "*"+tc.test+"*"))
					t.Errorf("[%s] expected %d files, got %d. Files: %v",
						tc.test, tc.expectedFiles, actualCount, found)
				}

				errChan <- nil
			}()

			if err := <-errChan; err != nil {
				t.Fatal(err)
			}
		})
	}
}

func Test_LogFileBatchProcessing(t *testing.T) {
	// Setup temporary file
	f, err := os.CreateTemp("", "test_batch_multiple")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(f.Name())

	// Configuration: 1 second flush interval
	config := pkgconfig.GetDefaultConfig()
	config.Loggers.LogFile.FilePath = f.Name()
	config.Loggers.LogFile.Mode = pkgconfig.ModeText
	config.Loggers.LogFile.FlushInterval = 1

	g := NewLogFile(config, logger.New(false), "test-batch")
	go g.StartCollect()

	// send multiple DNS messages (e.g., 50 messages)
	numMessages := 50
	for i := range numMessages {
		dm := dnsutils.GetFakeDNSMessage()
		dm.DNS.Qname = fmt.Sprintf("message-%d.batch.test", i)
		g.GetInputChannel() <- dm
	}

	// wait to ensure all messages are processed
	time.Sleep(2 * time.Second)
	g.Stop()

	// read file and count lines
	content, err := os.ReadFile(f.Name())
	if err != nil {
		t.Fatal(err)
	}

	lines := strings.Split(strings.TrimSpace(string(content)), "\n")

	// Check if we have all our messages
	if len(lines) != numMessages {
		t.Errorf("Batch count mismatch: expected %d lines, got %d", numMessages, len(lines))
	}

	// Check the last message to ensure data integrity
	expectedLast := fmt.Sprintf("message-%d.batch.test", numMessages-1)
	if !strings.Contains(lines[len(lines)-1], expectedLast) {
		t.Errorf("Last message integrity failed: expected %s", expectedLast)
	}
}
