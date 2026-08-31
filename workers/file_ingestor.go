package workers

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/dmachard/go-dnscollector/v3/dnsutils"
	"github.com/dmachard/go-dnscollector/v3/pkg/config"
	"github.com/dmachard/go-framestream"
	"github.com/dmachard/go-logger"
	"github.com/dmachard/go-netutils"
	"github.com/fsnotify/fsnotify"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
)

var waitFor = 10 * time.Second

func IsValidMode(mode string) bool {
	switch mode {
	case
		config.ModePCAP,
		config.ModeDNSTap:
		return true
	}
	return false
}

func isTemporaryFile(filePath string) bool {
	ext := filepath.Ext(filePath)
	switch ext {
	case ".tmp", ".temp", ".part", ".crdownload", ".writing", ".swp":
		return true
	}
	base := filepath.Base(filePath)
	return strings.HasPrefix(base, ".") || strings.HasSuffix(base, "~")
}

type fileState struct {
	size        int64
	modTime     time.Time
	inProgress  bool
	processed   bool
	packetCount int
}

type FileIngestor struct {
	*GenericWorker
	watcherTimers   map[string]*time.Timer
	fileStates      map[string]*fileState
	dnsProcessor    DNSProcessor
	dnstapProcessor DNSTapProcessor
	mu              sync.Mutex
}

func NewFileIngestor(next []Worker, cfg *config.Config, logger *logger.Logger, name string) *FileIngestor {
	bufSize := cfg.Global.Worker.ChannelBufferSize
	w := &FileIngestor{
		GenericWorker: NewGenericWorker(cfg, logger, name, "fileingestor", bufSize, config.DefaultMonitor),
		watcherTimers: make(map[string]*time.Timer),
		fileStates:    make(map[string]*fileState),
	}
	w.SetDefaultRoutes(next)
	w.CheckConfig()
	return w
}

func (w *FileIngestor) CheckConfig() {
	if !IsValidMode(w.GetConfig().Collectors.FileIngestor.WatchMode) {
		w.LogFatal(config.PrefixLogWorker+"["+w.GetName()+"] - invalid mode: ", w.GetConfig().Collectors.FileIngestor.WatchMode)
	}

	w.LogInfo("watching directory [%s] to find [%s] files",
		w.GetConfig().Collectors.FileIngestor.WatchDir,
		w.GetConfig().Collectors.FileIngestor.WatchMode)
}

func (w *FileIngestor) ProcessFile(filePath string) {
	if isTemporaryFile(filePath) {
		return
	}

	info, err := os.Stat(filePath)
	if err != nil {
		return
	}

	w.mu.Lock()
	st, exists := w.fileStates[filePath]
	if exists {
		// If currently being processed or already processed without changes, skip
		if st.inProgress || (st.processed && st.size == info.Size() && st.modTime.Equal(info.ModTime())) {
			w.mu.Unlock()
			return
		}
	} else {
		st = &fileState{}
		w.fileStates[filePath] = st
	}
	st.inProgress = true
	st.size = info.Size()
	st.modTime = info.ModTime()
	w.mu.Unlock()

	switch w.GetConfig().Collectors.FileIngestor.WatchMode {
	case config.ModePCAP:
		// process file with pcap extension only
		if filepath.Ext(filePath) == ".pcap" || filepath.Ext(filePath) == ".pcap.gz" {
			w.LogInfo("file ready to process %s", filePath)
			go w.ProcessPcap(filePath)
		}
	case config.ModeDNSTap:
		// process dnstap
		if filepath.Ext(filePath) == ".fstrm" {
			w.LogInfo("file ready to process %s", filePath)
			go w.ProcessDnstap(filePath)
		}
	}
}

func (w *FileIngestor) ProcessPcap(filePath string) {
	defer func() {
		w.mu.Lock()
		if st, ok := w.fileStates[filePath]; ok {
			st.inProgress = false
		}
		w.mu.Unlock()
	}()

	w.mu.Lock()
	skipPackets := 0
	if st, ok := w.fileStates[filePath]; ok {
		skipPackets = st.packetCount
	}
	w.mu.Unlock()

	// open the file
	f, err := os.Open(filePath)
	if err != nil {
		w.LogError("unable to read file: %s", err)
		return
	}
	defer f.Close()

	// it is a pcap file ?
	pcapHandler, err := pcapgo.NewReader(f)
	if err != nil {
		w.LogError("unable to read pcap file: %s", err)
		return
	}

	fileName := filepath.Base(filePath)
	w.LogInfo("processing pcap file [%s]...", fileName)

	switch pcapHandler.LinkType() {
	case layers.LinkTypeEthernet,
		layers.LinkTypeLinuxSLL,
		layers.LinkTypeNull,
		layers.LinkTypeRaw,
		layers.LinkTypeIPv4,
		layers.LinkTypeIPv6,
		layers.LinkTypeLoop:
		// Supported link types
	default:
		w.LogError("pcap file [%s] ignored: unsupported link type %s", filePath, pcapHandler.LinkType())
		return
	}

	dnsChan := make(chan netutils.DNSPacket)
	udpChan := make(chan gopacket.Packet)
	tcpChan := make(chan gopacket.Packet)
	fragIP4Chan := make(chan gopacket.Packet)
	fragIP6Chan := make(chan gopacket.Packet)

	packetSource := gopacket.NewPacketSource(pcapHandler, pcapHandler.LinkType())
	packetSource.Lazy = true
	packetSource.NoCopy = true

	// defrag ipv4
	go netutils.IPDefragger(fragIP4Chan, udpChan, tcpChan, w.GetConfig().Collectors.FileIngestor.PcapDNSPort)
	// defrag ipv6
	go netutils.IPDefragger(fragIP6Chan, udpChan, tcpChan, w.GetConfig().Collectors.FileIngestor.PcapDNSPort)
	// tcp assembly
	go netutils.TCPAssembler(tcpChan, dnsChan, w.GetConfig().Collectors.FileIngestor.PcapDNSPort)
	// udp processor
	go netutils.UDPProcessor(udpChan, dnsChan, w.GetConfig().Collectors.FileIngestor.PcapDNSPort)

	go func() {
		nbPackets := 0
		lastReceivedTime := time.Now()
		for {
			select {
			case dnsPacket, noMore := <-dnsChan:
				if !noMore {
					goto end
				}

				lastReceivedTime = time.Now()
				// prepare dns message
				dm := dnsutils.AcquireDNSMessage()
				dm.Init()

				dm.NetworkInfo.Family = dnsPacket.IPLayer.EndpointType().String()
				dm.NetworkInfo.SetQueryIPBytes(dnsPacket.IPLayer.Src().Raw())
				dm.NetworkInfo.SetResponseIPBytes(dnsPacket.IPLayer.Dst().Raw())
				dm.NetworkInfo.QueryPort = dnsPacket.TransportLayer.Src().String()
				dm.NetworkInfo.ResponsePort = dnsPacket.TransportLayer.Dst().String()
				dm.NetworkInfo.Protocol = dnsPacket.TransportLayer.EndpointType().String()
				dm.NetworkInfo.IPDefragmented = dnsPacket.IPDefragmented
				dm.NetworkInfo.TCPReassembled = dnsPacket.TCPReassembled

				dm.DNS.Payload = dnsPacket.Payload
				dm.DNS.Length = len(dnsPacket.Payload)

				dm.DNSTap.Identity = w.GetConfig().GetServerIdentity()
				dm.DNSTap.TimeSec = dnsPacket.Timestamp.Second()
				dm.DNSTap.TimeNsec = int(dnsPacket.Timestamp.UnixNano())

				// count it
				nbPackets++

				// send DNS message to DNS processor
				b := dnsutils.AcquireDNSMessageBatch(1)
				b.Messages = append(b.Messages, dm)
				w.dnsProcessor.GetInputChannel() <- b
			case <-time.After(10 * time.Second):
				elapsed := time.Since(lastReceivedTime)
				if elapsed >= 10*time.Second {
					close(dnsChan)
				}
			}
		}
	end:
		w.LogInfo("pcap file [%s]: %d DNS packet(s) detected", fileName, nbPackets)
	}()

	nbPackets := 0
	packetIndex := 0
	for {
		packet, err := packetSource.NextPacket()

		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			w.LogError("unable to read packet: %s", err)
			break
		}

		packetIndex++
		if packetIndex <= skipPackets {
			continue
		}

		nbPackets++

		// some security checks
		if packet.NetworkLayer() == nil {
			continue
		}
		if packet.TransportLayer() == nil {
			continue
		}

		// ipv4 fragmented packet ?
		if packet.NetworkLayer().LayerType() == layers.LayerTypeIPv4 {
			ip4 := packet.NetworkLayer().(*layers.IPv4)
			if ip4.Flags&layers.IPv4MoreFragments == 1 || ip4.FragOffset > 0 {
				fragIP4Chan <- packet
				continue
			}
		}

		// ipv6 fragmented packet ?
		if packet.NetworkLayer().LayerType() == layers.LayerTypeIPv6 {
			v6frag := packet.Layer(layers.LayerTypeIPv6Fragment)
			if v6frag != nil {
				fragIP6Chan <- packet
				continue
			}
		}

		// tcp or udp packets ?
		if packet.TransportLayer().LayerType() == layers.LayerTypeUDP {
			udpChan <- packet
		}
		if packet.TransportLayer().LayerType() == layers.LayerTypeTCP {
			tcpChan <- packet
		}

	}

	w.LogInfo("pcap file [%s] processing terminated, %d packet(s) read", fileName, nbPackets)

	w.mu.Lock()
	if st, ok := w.fileStates[filePath]; ok {
		st.processed = true
		st.packetCount += nbPackets
	}
	w.mu.Unlock()

	// remove it ?
	if w.GetConfig().Collectors.FileIngestor.DeleteAfter {
		w.LogInfo("delete file [%s]", fileName)
		os.Remove(filePath)
		w.mu.Lock()
		delete(w.fileStates, filePath)
		w.mu.Unlock()
	}

	// close chan
	close(fragIP4Chan)
	close(fragIP6Chan)
	close(udpChan)
	close(tcpChan)

	// remove event timer for this file
	w.RemoveEvent(filePath)
}

func (w *FileIngestor) ProcessDnstap(filePath string) error {
	defer func() {
		w.mu.Lock()
		if st, ok := w.fileStates[filePath]; ok {
			st.inProgress = false
		}
		w.mu.Unlock()
	}()

	w.mu.Lock()
	skipFrames := 0
	if st, ok := w.fileStates[filePath]; ok {
		skipFrames = st.packetCount
	}
	w.mu.Unlock()

	f, err := os.Open(filePath)
	if err != nil {
		return fmt.Errorf("failed to open file: %w", err)
	}
	defer f.Close()

	fs := framestream.NewFstrm(bufio.NewReader(f), nil, nil, 0, []byte("protobuf:dnstap.Dnstap"), false)
	fs.SetZeroCopy(true)
	if err := fs.InitReceiver(); err != nil {
		return fmt.Errorf("failed to init framestream receiver: %w", err)
	}

	fileName := filepath.Base(filePath)
	w.LogInfo("processing dnstap file [%s]", fileName)

	nbFrames := 0
	frameIndex := 0
	for {
		frame, err := fs.RecvFrame(false)
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			w.LogError("unable to decode dnstap frame: %s", err)
			break
		}
		if frame.IsControl() {
			break
		}

		buf := frame.Data()

		frameIndex++
		if frameIndex <= skipFrames {
			continue
		}

		nbFrames++

		newbuf := make([]byte, len(buf))
		copy(newbuf, buf)

		w.dnstapProcessor.GetDataChannel() <- newbuf
	}

	w.mu.Lock()
	if st, ok := w.fileStates[filePath]; ok {
		st.processed = true
		st.packetCount += nbFrames
	}
	w.mu.Unlock()

	// remove it ?
	w.LogInfo("processing of [%s] terminated", fileName)
	if w.GetConfig().Collectors.FileIngestor.DeleteAfter {
		w.LogInfo("delete file [%s]", fileName)
		os.Remove(filePath)
		w.mu.Lock()
		delete(w.fileStates, filePath)
		w.mu.Unlock()
	}

	// remove event timer for this file
	w.RemoveEvent(filePath)

	return nil
}

func (w *FileIngestor) RegisterEvent(filePath string) {
	if isTemporaryFile(filePath) {
		return
	}

	// Get timer.
	w.mu.Lock()
	t, ok := w.watcherTimers[filePath]
	w.mu.Unlock()

	// No timer yet, so create one.
	if !ok {
		t = time.AfterFunc(math.MaxInt64, func() { w.ProcessFile(filePath) })
		t.Stop()

		w.mu.Lock()
		w.watcherTimers[filePath] = t
		w.mu.Unlock()
	}

	// Reset the timer for this path, so it will start from 100ms again.
	t.Reset(waitFor)
}

func (w *FileIngestor) RemoveEvent(filePath string) {
	w.mu.Lock()
	delete(w.watcherTimers, filePath)
	w.mu.Unlock()
}

func (w *FileIngestor) StartCollect() {
	w.LogInfo("starting data collection")
	defer w.CollectDone()

	bufSize := w.GetConfig().Global.Worker.ChannelBufferSize

	dnsProcessor := NewDNSProcessor(w.GetConfig(), w.GetLogger(), w.GetName(), bufSize)
	dnsProcessor.SetDefaultRoutes(w.GetDefaultRoutes())
	dnsProcessor.SetDefaultDropped(w.GetDroppedRoutes())
	go dnsProcessor.StartCollect()

	// start dnstap subprocessor
	dnstapProcessor := NewDNSTapProcessor(0, "", w.GetConfig(), w.GetLogger(), w.GetName(), bufSize)
	dnstapProcessor.SetDefaultRoutes(w.GetDefaultRoutes())
	dnstapProcessor.SetDefaultDropped(w.GetDroppedRoutes())
	go dnstapProcessor.StartCollect()

	w.dnstapProcessor = dnstapProcessor
	w.dnsProcessor = dnsProcessor

	// read current folder content
	entries, err := os.ReadDir(w.GetConfig().Collectors.FileIngestor.WatchDir)
	if err != nil {
		w.LogError("unable to read folder: %s", err)
	}

	for _, entry := range entries {
		// ignore folder
		if entry.IsDir() {
			continue
		}

		// prepare filepath
		fn := filepath.Join(w.GetConfig().Collectors.FileIngestor.WatchDir, entry.Name())

		switch w.GetConfig().Collectors.FileIngestor.WatchMode {
		case config.ModePCAP:
			// process file with pcap extension
			if filepath.Ext(fn) == ".pcap" || filepath.Ext(fn) == ".pcap.gz" {
				go w.ProcessFile(fn)
			}
		case config.ModeDNSTap:
			// process dnstap
			if filepath.Ext(fn) == ".fstrm" {
				go w.ProcessFile(fn)
			}
		}
	}

	// then watch for new one
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		w.LogFatal(config.PrefixLogWorker+"["+w.GetName()+"] new watcher: ", err)
	}
	// register the folder to watch
	err = watcher.Add(w.GetConfig().Collectors.FileIngestor.WatchDir)
	if err != nil {
		w.LogFatal(config.PrefixLogWorker+"["+w.GetName()+"] register folder: ", err)
	}

	for {
		select {
		case <-w.OnStop():
			w.LogInfo("stop to listen...")

			// stop watching
			watcher.Close()

			// stop processors
			dnsProcessor.Stop()
			dnstapProcessor.Stop()
			return

		// save the new config
		case cfg := <-w.NewConfig():
			w.SetConfig(cfg)
			w.CheckConfig()

			dnsProcessor.NewConfig() <- cfg
			dnstapProcessor.NewConfig() <- cfg

		case event, ok := <-watcher.Events:
			if !ok { // Channel was closed (i.e. Watcher.Close() was called).
				return
			}

			// detect activity on file
			if !event.Has(fsnotify.Create) && !event.Has(fsnotify.Write) {
				continue
			}

			// register the event by the name
			w.RegisterEvent(event.Name)

		case err, ok := <-watcher.Errors:
			if !ok {
				return
			}
			w.LogError("error:", err)
		}
	}
}

func init() {
	RegisterCollector("file-ingestor", func(c *config.Config) bool { return c.Collectors.FileIngestor.Enable }, func(c *config.Config, l *logger.Logger, s string) Worker {
		return NewFileIngestor(nil, c, l, s)
	})
}
