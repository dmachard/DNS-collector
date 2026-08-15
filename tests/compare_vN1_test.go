package tests

import (
	"bufio"
	"bytes"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/dmachard/go-dnstap-protobuf"
	"github.com/golang/protobuf/proto"
)

// ProcessStats holds CPU and memory metrics measured during execution.
type ProcessStats struct {
	Tag           string
	Duration      time.Duration
	UserCPUTime   time.Duration
	SystemCPUTime time.Duration
	MaxRSSKb      int64
	MsgProcessed  int
	Throughput    float64
}

// TestCompare_VersionN1 compares the current workspace build against the latest N-1 git tag.
func TestCompare_VersionN1(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping comparison test in short mode")
	}

	// 1. Determine N-1 Tag
	prevTag := os.Getenv("PREV_TAG")
	if prevTag == "" {
		out, err := exec.Command("git", "describe", "--tags", "--abbrev=0").Output()
		if err != nil {
			t.Fatalf("failed to detect git tag: %v", err)
		}
		prevTag = strings.TrimSpace(string(out))
	}
	t.Logf("Comparing Current Workspace against Tag: %s", prevTag)

	// 2. Setup temporary directory
	tempDir, err := os.MkdirTemp("", "dnscollector_bench_*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	binCurrent := filepath.Join(tempDir, "dnscollector_current")
	binPrev := filepath.Join(tempDir, "dnscollector_prev")

	// 3. Build current workspace binary
	t.Log("Building current workspace binary...")
	cmdBuildCurrent := exec.Command("/usr/local/go/bin/go", "build", "-o", binCurrent, ".")
	cmdBuildCurrent.Dir = ".."
	if out, err := cmdBuildCurrent.CombinedOutput(); err != nil {
		t.Fatalf("failed to build current binary: %v\nOutput: %s", err, string(out))
	}

	// 4. Build N-1 binary from git tag
	t.Logf("Cloning & building N-1 tag (%s)...", prevTag)
	repoDir := filepath.Join(tempDir, "repo_prev")
	if out, err := exec.Command("git", "clone", "--quiet", "--branch", prevTag, "--depth", "1", "file://"+getRepoRoot(t), repoDir).CombinedOutput(); err != nil {
		t.Fatalf("failed to clone tag %s: %v\nOutput: %s", prevTag, err, string(out))
	}
	cmdBuildPrev := exec.Command("/usr/local/go/bin/go", "build", "-o", binPrev, ".")
	cmdBuildPrev.Dir = repoDir
	if out, err := cmdBuildPrev.CombinedOutput(); err != nil {
		t.Fatalf("failed to build prev binary (%s): %v\nOutput: %s", prevTag, err, string(out))
	}

	// 5. Generate benchmark config
	listenPort := 60053
	configPath := filepath.Join(tempDir, "config_bench.yml")
	configContent := fmt.Sprintf(`
global:
  trace:
    verbose: false

pipelines:
  - name: tap
    dnstap:
      listen-ip: "127.0.0.1"
      listen-port: %d
    routing-policy:
      forward: [ devnull_logger ]

  - name: devnull_logger
    devnull: {}
`, listenPort)

	if err := os.WriteFile(configPath, []byte(configContent), 0644); err != nil {
		t.Fatalf("failed to write bench config: %v", err)
	}

	// 6. Generate test payload frame
	payloadFrame := prepareDnstapFrame(t)

	// Number of DNSTap frames to send per benchmark run (default: 1,000,000)
	numFrames := 1000000
	if envFrames := os.Getenv("NUM_FRAMES"); envFrames != "" {
		if n, err := strconv.Atoi(envFrames); err == nil && n > 0 {
			numFrames = n
		}
	}

	// 7. Run Benchmark for Prev Version (N-1)
	t.Logf("Running benchmark for Version N-1 (%s)...", prevTag)
	statsPrev := runBenchmark(t, binPrev, configPath, listenPort, payloadFrame, numFrames, prevTag)

	time.Sleep(1 * time.Second)

	// 8. Run Benchmark for Current Version
	t.Log("Running benchmark for Current Version...")
	statsCurrent := runBenchmark(t, binCurrent, configPath, listenPort, payloadFrame, numFrames, "Current (Refactored)")

	// 9. Report Results
	t.Log("\n" + formatComparisonReport(statsPrev, statsCurrent))
}

func getRepoRoot(t *testing.T) string {
	out, err := exec.Command("git", "rev-parse", "--show-toplevel").Output()
	if err != nil {
		t.Fatalf("failed to find git repo root: %v", err)
	}
	return strings.TrimSpace(string(out))
}

func prepareDnstapFrame(t *testing.T) []byte {
	dt := &dnstap.Dnstap{
		Type: dnstap.Dnstap_MESSAGE.Enum(),
		Message: &dnstap.Message{
			Type:            dnstap.Message_CLIENT_QUERY.Enum(),
			SocketFamily:    dnstap.SocketFamily_INET.Enum(),
			SocketProtocol:  dnstap.SocketProtocol_UDP.Enum(),
			QueryAddress:    net.ParseIP("192.168.1.100").To4(),
			ResponseAddress: net.ParseIP("8.8.8.8").To4(),
			QueryPort:       proto.Uint32(53333),
			ResponsePort:    proto.Uint32(53),
			QueryMessage:    []byte("\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07example\x03com\x00\x00\x01\x00\x01"),
		},
	}
	data, err := proto.Marshal(dt)
	if err != nil {
		t.Fatalf("failed to marshal dnstap message: %v", err)
	}

	// Framestream framing: length header (4 bytes big-endian)
	buf := make([]byte, 4+len(data))
	buf[0] = byte(len(data) >> 24)
	buf[1] = byte(len(data) >> 16)
	buf[2] = byte(len(data) >> 8)
	buf[3] = byte(len(data))
	copy(buf[4:], data)
	return buf
}

func runBenchmark(t *testing.T, binPath, configPath string, port int, frame []byte, numFrames int, tag string) ProcessStats {
	cmd := exec.Command(binPath, "-config", configPath)
	var outputBuf bytes.Buffer
	cmd.Stdout = &outputBuf
	cmd.Stderr = &outputBuf

	if err := cmd.Start(); err != nil {
		t.Fatalf("failed to start binary %s: %v", binPath, err)
	}

	// Wait for listener to open
	addr := fmt.Sprintf("127.0.0.1:%d", port)
	var conn net.Conn
	var err error
	for i := 0; i < 50; i++ {
		conn, err = net.DialTimeout("tcp", addr, 100*time.Millisecond)
		if err == nil {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if err != nil {
		cmd.Process.Kill()
		t.Fatalf("failed to connect to collector on %s: %v\nOutput: %s", addr, err, outputBuf.String())
	}

	// Handshake framestream content type
	ct := "protobuf:dnstap.Dnstap"
	ctrlPayload := append([]byte("\x00\x00\x00\x01"), []byte(fmt.Sprintf("%c%s", len(ct), ct))...)
	ctrlLen := uint32(len(ctrlPayload))
	ctrlFrame := make([]byte, 8+len(ctrlPayload))
	ctrlFrame[0] = 0 // escape
	ctrlFrame[1] = 0
	ctrlFrame[2] = 0
	ctrlFrame[3] = 0
	ctrlFrame[4] = byte(ctrlLen >> 24)
	ctrlFrame[5] = byte(ctrlLen >> 16)
	ctrlFrame[6] = byte(ctrlLen >> 8)
	ctrlFrame[7] = byte(ctrlLen)
	copy(ctrlFrame[8:], ctrlPayload)

	conn.Write(ctrlFrame)

	startTime := time.Now()
	w := bufio.NewWriterSize(conn, 64*1024)

	for i := 0; i < numFrames; i++ {
		w.Write(frame)
		if i%1000 == 0 {
			w.Flush()
		}
	}
	w.Flush()
	conn.Close()

	// Wait for processing to drain
	time.Sleep(500 * time.Millisecond)

	// Send SIGINT to gracefully terminate process and get resource usage
	cmd.Process.Signal(os.Interrupt)
	done := make(chan error, 1)
	go func() {
		done <- cmd.Wait()
	}()

	select {
	case <-done:
	case <-time.After(3 * time.Second):
		cmd.Process.Kill()
		<-done
	}

	duration := time.Since(startTime)

	// Collect Process Stats & Rusage
	var userCPU, sysCPU time.Duration
	var maxRSS int64

	if state := cmd.ProcessState; state != nil {
		userCPU = state.UserTime()
		sysCPU = state.SystemTime()
		if rusage, ok := state.SysUsage().(*syscall.Rusage); ok {
			maxRSS = rusage.Maxrss
			// On Linux, rusage.Maxrss is in Kilobytes
			if runtime.GOOS == "darwin" {
				maxRSS = maxRSS / 1024
			}
		}
	}

	// Fallback to /proc RSS if maxRSS is 0
	if maxRSS == 0 {
		maxRSS = getPeakRSSFromProc(cmd.Process.Pid)
	}

	throughput := float64(numFrames) / duration.Seconds()

	return ProcessStats{
		Tag:           tag,
		Duration:      duration,
		UserCPUTime:   userCPU,
		SystemCPUTime: sysCPU,
		MaxRSSKb:      maxRSS,
		MsgProcessed:  numFrames,
		Throughput:    throughput,
	}
}

func getPeakRSSFromProc(pid int) int64 {
	statusPath := fmt.Sprintf("/proc/%d/status", pid)
	data, err := os.ReadFile(statusPath)
	if err != nil {
		return 0
	}
	for _, line := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(line, "VmHWM:") || strings.HasPrefix(line, "VmRSS:") {
			parts := strings.Fields(line)
			if len(parts) >= 2 {
				val, _ := strconv.ParseInt(parts[1], 10, 64)
				return val
			}
		}
	}
	return 0
}

func formatComparisonReport(prev, curr ProcessStats) string {
	cpuPrev := prev.UserCPUTime + prev.SystemCPUTime
	cpuCurr := curr.UserCPUTime + curr.SystemCPUTime

	memDiff := float64(curr.MaxRSSKb-prev.MaxRSSKb) / float64(prev.MaxRSSKb) * 100.0
	cpuDiff := float64(cpuCurr-cpuPrev) / float64(cpuPrev) * 100.0
	tputDiff := (curr.Throughput - prev.Throughput) / prev.Throughput * 100.0

	return fmt.Sprintf(`
================================================================================
          PERFORMANCE COMPARISON: %s vs Current (Refactored)
================================================================================
Metric                      %-20s %-20s Delta
--------------------------------------------------------------------------------
Total Messages Processed    %-20d %-20d -
Execution Time              %-20s %-20s %+.2f%%
Total CPU Time (User+Sys)   %-20s %-20s %+.2f%%
Peak Memory (Max RSS)       %-20s %-20s %+.2f%%
Throughput                  %-20.2f %-20.2f %+.2f%%
================================================================================
`,
		prev.Tag,
		prev.Tag, "Current",
		prev.MsgProcessed, curr.MsgProcessed,
		prev.Duration.Round(time.Millisecond), curr.Duration.Round(time.Millisecond), (float64(curr.Duration-prev.Duration)/float64(prev.Duration))*100.0,
		cpuPrev.Round(time.Millisecond), cpuCurr.Round(time.Millisecond), cpuDiff,
		fmt.Sprintf("%d KB (%.2f MB)", prev.MaxRSSKb, float64(prev.MaxRSSKb)/1024.0),
		fmt.Sprintf("%d KB (%.2f MB)", curr.MaxRSSKb, float64(curr.MaxRSSKb)/1024.0),
		memDiff,
		prev.Throughput, curr.Throughput, tputDiff,
	)
}
