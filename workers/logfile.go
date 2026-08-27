package workers

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/klauspost/compress/gzip"

	"github.com/dmachard/go-dnscollector/v3/dnsutils"
	"github.com/dmachard/go-dnscollector/v3/pkg/config"
	"github.com/dmachard/go-dnscollector/v3/transformers"
	"github.com/dmachard/go-logger"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"

	framestream "github.com/farsightsec/golang-framestream"
)

const (
	compressSuffix = ".gz"
)

func IsValid(mode string) bool {
	switch mode {
	case
		config.ModeJinja,
		config.ModeText,
		config.ModeJSON,
		config.ModeFlatJSON,
		config.ModePCAP,
		config.ModeDNSTap:
		return true
	}
	return false
}

type LogFile struct {
	*GenericWorker
	writerPlain                            *bufio.Writer
	writerPcap                             *pcapgo.Writer
	writerDnstap                           *framestream.Encoder
	rotationTimer                          *time.Timer
	rotationInterval                       time.Duration
	fileFd                                 *os.File
	fileSize                               int64
	fileDir, fileName, fileExt, filePrefix string
	textFormat                             []string
	textFormatter                          *dnsutils.TextFormatter
	jinjaFormat                            string
	compressQueue                          chan string
	commandQueue                           chan string
	queueWg                                sync.WaitGroup
	pcapBuffer                             []byte
}

func NewLogFile(cfg *config.Config, logger *logger.Logger, name string) *LogFile {
	bufSize := cfg.Global.Worker.ChannelBufferSize
	w := &LogFile{
		GenericWorker: NewGenericWorker(cfg, logger, name, "file", bufSize, config.DefaultMonitor),
		compressQueue: make(chan string, 1),
		commandQueue:  make(chan string, 1),
	}
	w.ReadConfig()
	if err := w.OpenCurrentFile(); err != nil {
		w.LogFatal(config.PrefixLogWorker+"["+name+"] file - unable to open output file:", err)
	}

	// start compressor
	go w.startCompressor()
	w.initializeCompressionQueue()

	// start post command processor
	go w.startCommandProcessor()

	return w
}

func (w *LogFile) ReadConfig() {
	if !IsValid(w.GetConfig().Loggers.LogFile.Mode) {
		w.LogFatal("["+w.GetName()+"] logger=file - invalid mode: ", w.GetConfig().Loggers.LogFile.Mode)
	}
	w.fileDir = filepath.Dir(w.GetConfig().Loggers.LogFile.FilePath)
	w.fileName = filepath.Base(w.GetConfig().Loggers.LogFile.FilePath)
	w.fileExt = filepath.Ext(w.fileName)
	w.filePrefix = strings.TrimSuffix(w.fileName, w.fileExt)

	if len(w.GetConfig().Loggers.LogFile.TextFormat) > 0 {
		w.textFormat = strings.Fields(w.GetConfig().Loggers.LogFile.TextFormat)
	} else {
		w.textFormat = strings.Fields(w.GetConfig().Global.TextFormat)
	}

	var err error
	w.textFormatter, err = dnsutils.NewTextFormatter(w.textFormat, w.GetConfig().Global.TextFormatDelimiter, w.GetConfig().Global.TextFormatBoundary)
	if err != nil {
		w.LogFatal("["+w.GetName()+"] logger=file - invalid text format: ", err.Error())
	}

	if len(w.GetConfig().Loggers.Stdout.JinjaFormat) > 0 {
		w.jinjaFormat = w.GetConfig().Loggers.LogFile.JinjaFormat
	} else {
		w.jinjaFormat = w.GetConfig().Global.TextJinja
	}

	w.LogInfo("running in mode: %s", w.GetConfig().Loggers.LogFile.Mode)
}

func (w *LogFile) RemoveOldFiles() error {
	if w.GetConfig().Loggers.LogFile.MaxFiles == 0 {
		return nil
	}

	// remove old files ? keep only max files number
	entries, err := os.ReadDir(w.fileDir)
	if err != nil {
		return err
	}

	logFiles := []int{}
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}

		// extract timestamp from filename
		re := regexp.MustCompile(`^` + w.filePrefix + `-(?P<ts>\d+)` + w.fileExt)
		matches := re.FindStringSubmatch(entry.Name())

		if len(matches) == 0 {
			continue
		}

		// convert timestamp to int
		tsIndex := re.SubexpIndex("ts")
		i, err := strconv.Atoi(matches[tsIndex])
		if err != nil {
			continue
		}
		logFiles = append(logFiles, i)
	}
	sort.Ints(logFiles)

	// too much log files ?
	diffNB := len(logFiles) - (w.GetConfig().Loggers.LogFile.MaxFiles - 1)
	if diffNB > 0 {
		for i := 0; i < diffNB; i++ {
			filename := fmt.Sprintf("%s-%d%s", w.filePrefix, logFiles[i], w.fileExt)
			f := filepath.Join(w.fileDir, filename)
			if _, err := os.Stat(f); os.IsNotExist(err) {
				f = filepath.Join(w.fileDir, filename+compressSuffix)
			}

			// ignore errors on deletion
			os.Remove(f)
		}
	}

	return nil
}

func (w *LogFile) OpenCurrentFile() error {
	w.LogInfo("create new log file: %s", w.GetConfig().Loggers.LogFile.FilePath)

	fd, err := os.OpenFile(w.GetConfig().Loggers.LogFile.FilePath, os.O_RDWR|os.O_CREATE|os.O_APPEND, 0644)
	if err != nil {
		return err
	}
	w.fileFd = fd

	fileinfo, err := os.Stat(w.GetConfig().Loggers.LogFile.FilePath)
	if err != nil {
		return err
	}

	w.fileSize = fileinfo.Size()

	// create buffered writer
	writerBufSize := w.config.Loggers.LogFile.MaxBatchSize
	if writerBufSize <= 0 {
		writerBufSize = 64 * 1024
	}
	w.writerPlain = bufio.NewWriterSize(fd, writerBufSize)

	switch w.GetConfig().Loggers.LogFile.Mode {
	case config.ModePCAP:
		w.writerPcap = pcapgo.NewWriter(w.writerPlain)
		if w.fileSize == 0 {
			if err := w.writerPcap.WriteFileHeader(65536, layers.LinkTypeEthernet); err != nil {
				return err
			}
		}

	case config.ModeDNSTap:
		fsOptions := &framestream.EncoderOptions{ContentType: []byte("protobuf:dnstap.Dnstap"), Bidirectional: false}
		w.writerDnstap, err = framestream.NewEncoder(w.writerPlain, fsOptions)
		if err != nil {
			return err
		}

	}

	w.LogInfo("new log file created")
	return nil
}

func (w *LogFile) GetMaxSize() int64 {
	return int64(1024*1024) * int64(w.GetConfig().Loggers.LogFile.MaxSize)
}

func (w *LogFile) compressFile(filename string) {
	w.LogInfo("start to compress in background: %s", filename)

	// prepare dest filename
	baseName := filepath.Base(filename)
	baseName = strings.TrimPrefix(baseName, "tocompress-")
	if len(w.config.Loggers.LogFile.PostRotateCommand) > 0 {
		baseName = "toprocess-" + baseName
	}
	tmpFile := filename + compressSuffix
	dstFile := filepath.Join(filepath.Dir(filename), baseName+compressSuffix)

	// open the file
	fd, err := os.Open(filename)
	if err != nil {
		w.LogError("compress - failed to open file: %s", err)
		return
	}
	defer fd.Close()

	fi, err := os.Stat(filename)
	if err != nil {
		w.LogError("compress - failed to stat file: %s", err)
		return
	}

	gzf, err := os.OpenFile(tmpFile, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, fi.Mode())
	if err != nil {
		w.LogError("compress - failed to open compressed file: %s", err)
		return
	}
	defer gzf.Close()

	gz := gzip.NewWriter(gzf)

	if _, err := io.Copy(gz, fd); err != nil {
		w.LogError("compress - failed to compress file: %s", err)
		os.Remove(tmpFile)
		return
	}
	if err := gz.Close(); err != nil {
		w.LogError("compress - failed to close gz writer: %s", err)
		os.Remove(tmpFile)
		return
	}
	if err := gzf.Close(); err != nil {
		w.LogError("compress - failed to close gz file: %s", err)
		os.Remove(tmpFile)
		return
	}

	if err := fd.Close(); err != nil {
		w.LogError("compress - failed to close log file: %s", err)
		os.Remove(tmpFile)
		return
	}
	if err := os.Remove(filename); err != nil {
		w.LogError("compress - failed to remove log file: %s", err)
		os.Remove(tmpFile)
		return
	}

	// finally rename the gzip file
	if err := os.Rename(tmpFile, dstFile); err != nil {
		w.LogError("compress - unable to rename file: %s", err)
		os.Remove(tmpFile)
		return
	}

	// run post command on compressed file ?
	if len(w.config.Loggers.LogFile.PostRotateCommand) > 0 {
		w.queueWg.Add(1)
		go func() {
			w.commandQueue <- dstFile
		}()
	}

	w.LogInfo("compression terminated - %s", dstFile)
}

func (w *LogFile) postRotateCommand(fullPath string) {
	if len(w.GetConfig().Loggers.LogFile.PostRotateCommand) > 0 {
		w.LogInfo("execute postrotate command: %s", fullPath)
		dir := filepath.Dir(fullPath)
		filename := filepath.Base(fullPath)
		baseName := strings.TrimPrefix(filename, "toprocess-")
		_, err := exec.Command(w.GetConfig().Loggers.LogFile.PostRotateCommand, fullPath, dir, baseName).Output()
		if err != nil {
			w.LogError("postrotate command error - %s - %s", filename, err)
		} else {
			w.LogInfo("postrotate command terminated - %s", filename)
		}

		if w.GetConfig().Loggers.LogFile.PostRotateDelete {
			w.LogInfo("postrotate command delete original file - %s", filename)
			os.Remove(filename)
		}
	}
}

func (w *LogFile) FlushWriters() {
	switch w.GetConfig().Loggers.LogFile.Mode {
	case config.ModeText, config.ModeJSON, config.ModeFlatJSON, config.ModePCAP:
		w.writerPlain.Flush()
	case config.ModeDNSTap:
		w.writerDnstap.Flush()
		w.writerPlain.Flush()
	}
}

func (w *LogFile) RotateFile() error {
	// flush writers
	w.FlushWriters()

	// skip rotation if file size is zero
	if w.fileSize == 0 {
		if w.rotationInterval > 0 {
			w.rotationTimer.Reset(w.rotationInterval)
		}
		return nil
	}

	// reset rotation timer
	if w.rotationInterval > 0 {
		w.rotationTimer.Reset(w.rotationInterval)
	}

	// close current file
	if w.GetConfig().Loggers.LogFile.Mode == config.ModeDNSTap {
		w.writerDnstap.Close()
	}

	if err := w.fileFd.Close(); err != nil {
		return err
	}

	// Rename current log file
	newFilename := fmt.Sprintf("%s-%d%s", w.filePrefix, time.Now().UnixNano(), w.fileExt)
	if w.config.Loggers.LogFile.Compress {
		newFilename = fmt.Sprintf("tocompress-%s", newFilename)
	} else if len(w.config.Loggers.LogFile.PostRotateCommand) > 0 {
		newFilename = fmt.Sprintf("toprocess-%s", newFilename)
	}
	bfpath := filepath.Join(w.fileDir, newFilename)
	err := os.Rename(w.GetConfig().Loggers.LogFile.FilePath, bfpath)
	if err != nil {
		return err
	}

	// post rotate command?
	if w.config.Loggers.LogFile.Compress {
		w.queueWg.Add(1)
		go func() {
			w.compressQueue <- bfpath
		}()
	} else {
		w.queueWg.Add(1)
		go func() {
			w.commandQueue <- bfpath
		}()
	}

	// keep only max files
	err = w.RemoveOldFiles()
	if err != nil {
		w.LogError("unable to cleanup log files: %s", err)
		return err
	}

	// re-create new one
	if err := w.OpenCurrentFile(); err != nil {
		w.LogError("unable to re-create file: %s", err)
		return err
	}

	return nil
}

func (w *LogFile) WriteToPcapBytes(dm *dnsutils.DNSMessage, pktBytes []byte) error {
	packetSize := int64(16 + len(pktBytes))
	if (w.fileSize + packetSize) > w.GetMaxSize() {
		if err := w.RotateFile(); err != nil {
			return err
		}
	}

	ci := gopacket.CaptureInfo{
		Timestamp:     time.Unix(int64(dm.DNSTap.TimeSec), int64(dm.DNSTap.TimeNsec)),
		CaptureLength: len(pktBytes),
		Length:        len(pktBytes),
	}

	if err := w.writerPcap.WritePacket(ci, pktBytes); err != nil {
		return err
	}
	w.fileSize += packetSize
	return nil
}

func (w *LogFile) WriteToPcap(dm *dnsutils.DNSMessage, pkt []gopacket.SerializableLayer) {
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}
	for _, layer := range pkt {
		layer.SerializeTo(buf, opts)
	}
	_ = w.WriteToPcapBytes(dm, buf.Bytes())
}

func (w *LogFile) WriteToPlain(data []byte) {
	// rotate file ?
	if (w.fileSize + int64(len(data))) > w.GetMaxSize() {
		if err := w.RotateFile(); err != nil {
			w.LogError("failed to rotate text file: %s", err)
			return
		}
	}

	// write log to file and increase size
	n, _ := w.writerPlain.Write(data)
	w.fileSize += int64(n)
}

func (w *LogFile) WriteToDnstap(data []byte) {
	// rotate file ?
	if (w.fileSize + int64(len(data))) > w.GetMaxSize() {
		if err := w.RotateFile(); err != nil {
			w.LogError("failed to rotate dnstap file: %s", err)
			return
		}
	}

	// write log to file and increase size
	n, _ := w.writerDnstap.Write(data)
	w.fileSize += int64(n)
}

func (w *LogFile) initializeCompressionQueue() {
	// Get all files in the log directory
	files, err := os.ReadDir(w.fileDir)
	if err != nil {
		w.LogError("error reading log directory: %v", err)
		return
	}

	// Find files that start with "tocompress-"
	for _, file := range files {
		fileName := file.Name()

		// Check if the file is both marked for compression and has a `.gz` suffix
		if strings.HasPrefix(fileName, "tocompress-") && strings.HasSuffix(fileName, ".gz") {
			// Build the full path of the file
			fullPath := filepath.Join(w.fileDir, fileName)

			// Attempt to remove incomplete .gz file
			if err := os.Remove(fullPath); err != nil {
				w.LogError("error deleting incomplete compressed file %s: %v", fileName, err)
			}
			continue
		}

		// If it's a pending compression file, add it to the compression queue
		if strings.HasPrefix(fileName, "tocompress-") && !strings.HasSuffix(fileName, ".gz") {
			fullPath := filepath.Join(w.fileDir, fileName)
			w.compressQueue <- fullPath
		}
	}
}

func (w *LogFile) startCompressor() {
	for filename := range w.compressQueue {
		w.compressFile(filename)
		w.queueWg.Done()
	}
}

func (w *LogFile) startCommandProcessor() {
	for filename := range w.commandQueue {
		w.postRotateCommand(filename)
		w.queueWg.Done()
	}
}

func (w *LogFile) StartCollect() {
	w.LogInfo("starting data collection")
	defer w.CollectDone()

	// prepare next channels
	defaultRoutes, defaultNames := GetRoutes(w.GetDefaultRoutes())
	droppedRoutes, droppedNames := GetRoutes(w.GetDroppedRoutes())

	// prepare transforms
	subprocessors := transformers.NewTransforms(&w.GetConfig().OutgoingTransformers, w.GetLogger(), w.GetName(), w.GetOutputChannelAsList(), 0)

	// goroutine to process transformed dns messages
	go w.StartLogging()

	// loop to process incoming messages
	for {
		select {
		case <-w.OnStop():
			w.StopLogger()
			subprocessors.Reset()
			return

			// new config provided?
		case cfg := <-w.NewConfig():
			w.SetConfig(cfg)
			w.ReadConfig()
			subprocessors.ReloadConfig(&cfg.OutgoingTransformers)

		case batch, opened := <-w.GetInputChannel():
			if !opened {
				w.LogInfo("input channel closed!")
				return
			}

			outBatch := dnsutils.AcquireDNSMessageBatch(len(batch.Messages))
			for _, dm := range batch.Messages {
				// count global messages
				w.CountIngressTraffic()

				// apply transforms, init dns message with additional parts if necessary
				transformResult, err := subprocessors.ProcessMessage(dm)
				if err != nil {
					w.LogError(err.Error())
				}
				if transformResult == transformers.ReturnDrop {
					w.SendDroppedTo(droppedRoutes, droppedNames, dm)
					continue
				}

				dm.Retain(1)
				outBatch.Messages = append(outBatch.Messages, dm)
			}
			w.SendToOutputAndForwardBatch(defaultRoutes, defaultNames, outBatch)
			batch.Release()
		}
	}
}

func (w *LogFile) StartLogging() {
	w.LogInfo("logging has started")
	defer w.LoggingDone()

	// flush periodic timer
	flushInterval := time.Duration(w.GetConfig().Loggers.LogFile.FlushInterval) * time.Second
	if flushInterval <= 0 {
		flushInterval = 1 * time.Second
	}
	flushTicker := time.NewTicker(flushInterval)
	defer flushTicker.Stop()

	// rotation timer
	rotationInterval := w.GetConfig().Loggers.LogFile.RotationInterval
	w.rotationInterval = time.Duration(rotationInterval) * time.Second
	w.rotationTimer = time.NewTimer(w.rotationInterval)
	if rotationInterval == 0 {
		w.rotationTimer.Stop()
	}

	for {
		select {
		case <-w.OnLoggerStopped():
			// stop timers
			flushTicker.Stop()
			w.rotationTimer.Stop()

			// flush writer
			w.FlushWriters()

			// closing file
			w.LogInfo("closing log file")
			if w.GetConfig().Loggers.LogFile.Mode == config.ModeDNSTap {
				w.writerDnstap.Close()
			}
			w.fileFd.Close()

			// wait until queues are processed
			w.queueWg.Wait()
			close(w.compressQueue)
			close(w.commandQueue)

			return

		case batch, opened := <-w.GetOutputChannel():
			if !opened {
				w.LogInfo("output channel closed!")
				return
			}

			for _, dm := range batch.Messages {
				// Process the message based on the configured mode
				switch w.GetConfig().Loggers.LogFile.Mode {

				// with basic text mode
				case config.ModeText:
					// get a text buffer from pool
					buf := w.GetTextBuffer()
					buf.Reset()

					// encode to text line the dns message
					var err error
					if w.textFormatter != nil {
						err = w.textFormatter.Format(dm, buf)
					} else {
						err = dm.ToTextLine(
							w.textFormat,
							w.GetConfig().Global.TextFormatDelimiter,
							w.GetConfig().Global.TextFormatBoundary,
							buf,
						)
					}
					if err != nil {
						w.CountEgressDiscarded()
						w.LogError("logfile: could not encode to text format: %s", err)
						w.PutTextBuffer(buf)
						continue
					}

					// ensure it ends in a \n
					data := buf.Bytes()
					if len(data) == 0 || data[len(data)-1] != '\n' {
						buf.WriteByte('\n')
					}

					// write and return text buffer to pool
					w.WriteToPlain(buf.Bytes())
					w.PutTextBuffer(buf)

				// with custom text mode
				case config.ModeJinja:
					textLine, err := dm.ToTextTemplate(w.jinjaFormat)
					if err != nil {
						w.CountEgressDiscarded()
						w.LogError("jinja template: %s", err)
						continue
					}
					data := []byte(textLine)
					if len(data) > 0 && data[len(data)-1] != '\n' {
						data = append(data, '\n')
					}
					w.WriteToPlain(data)

				// with json mode
				case config.ModeJSON, config.ModeFlatJSON:
					buf := w.GetTextBuffer()
					buf.Reset()

					if w.GetConfig().Loggers.LogFile.Mode == config.ModeFlatJSON {
						if dm.Relabeling != nil {
							flat, err := dm.Flatten()
							if err != nil {
								w.CountEgressDiscarded()
								w.LogError("flattening DNS message failed: %e", err)
								w.PutTextBuffer(buf)
								continue
							}
							json.NewEncoder(buf).Encode(flat)
						} else {
							dm.GetTimestampRFC3339()
							dm.EncodeFlatJSON(buf)
							buf.WriteByte('\n')
						}
					} else {
						json.NewEncoder(buf).Encode(dm)
					}

					// send to file and return buffer to pool
					w.WriteToPlain(buf.Bytes())
					w.PutTextBuffer(buf)

				// with dnstap mode
				case config.ModeDNSTap:
					data, err := dm.ToDNSTap(w.GetConfig().Loggers.LogFile.ExtendedSupport)
					if err != nil {
						w.CountEgressDiscarded()
						w.LogError("failed to encode to DNStap protobuf: %s", err)
						continue
					}
					w.WriteToDnstap(data)

				// with pcap mode
				case config.ModePCAP:
					if len(dm.DNS.Payload) == 0 {
						w.CountEgressDiscarded()
						w.LogError("no dns payload to encode, drop it")
						continue
					}

					var err error
					w.pcapBuffer, err = dm.EncodeToPacketBytes(w.pcapBuffer[:0], w.GetConfig().Loggers.LogFile.OverwriteDNSPortPcap)
					if err != nil {
						w.CountEgressDiscarded()
						w.LogError("failed to encode to packet: %s", err)
						continue
					}

					// write the packet
					if err := w.WriteToPcapBytes(dm, w.pcapBuffer); err != nil {
						w.CountEgressDiscarded()
						w.LogError("failed to write packet to pcap: %s", err)
						continue
					}
				}
			}
			batch.Release()

		case <-flushTicker.C:
			w.FlushWriters()

		case <-w.rotationTimer.C:
			w.LogInfo("rotation interval reached")
			if err := w.RotateFile(); err != nil {
				w.LogError("failed to rotate file: %s", err)
			}
		}
	}
}

func init() {
	RegisterLogger("logfile", func(c *config.Config) bool { return c.Loggers.LogFile.Enable }, func(c *config.Config, l *logger.Logger, s string) Worker {
		return NewLogFile(c, l, s)
	})
}
