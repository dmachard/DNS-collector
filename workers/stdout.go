package workers

import (
	"bufio"
	"encoding/json"
	"io"
	"os"
	"strings"
	"time"

	"github.com/dmachard/go-dnscollector/v2/dnsutils"
	"github.com/dmachard/go-dnscollector/v2/pkg/config"
	"github.com/dmachard/go-dnscollector/v2/transformers"
	"github.com/dmachard/go-logger"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
)

func IsStdoutValidMode(mode string) bool {
	switch mode {
	case
		config.ModeJinja,
		config.ModeText,
		config.ModeJSON,
		config.ModeFlatJSON,
		config.ModePCAP:
		return true
	}
	return false
}

type StdOut struct {
	*GenericWorker
	textFormat    []string
	textFormatter *dnsutils.TextFormatter
	jinjaFormat   string
	writerRaw     *bufio.Writer
	writerPcap    *pcapgo.Writer
	pcapBuffer    []byte
}

func NewStdOut(cfg *config.Config, console *logger.Logger, name string) *StdOut {
	bufSize := cfg.Global.Worker.ChannelBufferSize
	w := &StdOut{GenericWorker: NewGenericWorker(cfg, console, name, "stdout", bufSize, config.DefaultMonitor)}

	// init writers with buffer to minimize syscalls
	writerBufSize := cfg.Loggers.Stdout.WriterBufferSize
	if writerBufSize <= 0 {
		writerBufSize = 64 * 1024 // 64KB default
	}
	w.writerRaw = bufio.NewWriterSize(os.Stdout, writerBufSize)
	w.ReadConfig()
	return w
}

func (w *StdOut) ReadConfig() {
	if !IsStdoutValidMode(w.GetConfig().Loggers.Stdout.Mode) {
		w.LogFatal("invalid mode: ", w.GetConfig().Loggers.Stdout.Mode)
	}

	if len(w.GetConfig().Loggers.Stdout.TextFormat) > 0 {
		w.textFormat = strings.Fields(w.GetConfig().Loggers.Stdout.TextFormat)
	} else {
		w.textFormat = strings.Fields(w.GetConfig().Global.TextFormat)
	}

	var err error
	w.textFormatter, err = dnsutils.NewTextFormatter(w.textFormat, w.GetConfig().Global.TextFormatDelimiter, w.GetConfig().Global.TextFormatBoundary)
	if err != nil {
		w.LogFatal("invalid text format: ", err.Error())
	}

	if len(w.GetConfig().Loggers.Stdout.JinjaFormat) > 0 {
		w.jinjaFormat = w.GetConfig().Loggers.Stdout.JinjaFormat
	} else {
		w.jinjaFormat = w.GetConfig().Global.TextJinja
	}
}

func (w *StdOut) SetTextWriter(out io.Writer) {
	writerBufSize := w.GetConfig().Loggers.Stdout.WriterBufferSize
	if writerBufSize <= 0 {
		writerBufSize = 64 * 1024 // 64KB default
	}
	w.writerRaw = bufio.NewWriterSize(out, writerBufSize)
}

func (w *StdOut) SetPcapWriter(pcapWriter io.Writer) {
	w.SetTextWriter(pcapWriter)
	w.writerPcap = pcapgo.NewWriter(w.writerRaw)
	if err := w.writerPcap.WriteFileHeader(65536, layers.LinkTypeEthernet); err != nil {
		w.LogFatal("pcap init error", err)
	}
}

func (w *StdOut) StartCollect() {
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
				w.LogInfo("run: input channel closed!")
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

func (w *StdOut) StartLogging() {
	w.LogInfo("logging has started")
	defer w.LoggingDone()

	// setup pcap writer if necessary
	if w.GetConfig().Loggers.Stdout.Mode == config.ModePCAP && w.writerPcap == nil {
		w.SetPcapWriter(os.Stdout)
	}

	// setup flush ticker
	flushInterval := time.Duration(w.GetConfig().Loggers.Stdout.FlushInterval * float64(time.Second))
	if flushInterval <= 0 {
		flushInterval = 1 * time.Second
	}
	flushTicker := time.NewTicker(flushInterval)
	defer flushTicker.Stop()

	// setup json encoder if necessary
	var jsonEncoder *json.Encoder
	if w.GetConfig().Loggers.Stdout.Mode == config.ModeJSON || w.GetConfig().Loggers.Stdout.Mode == config.ModeFlatJSON {
		jsonEncoder = json.NewEncoder(w.writerRaw)
	}

	for {
		select {
		case <-w.OnLoggerStopped():
			w.writerRaw.Flush()
			return

		case <-flushTicker.C:
			w.writerRaw.Flush()

		case batch, opened := <-w.GetOutputChannel():
			if !opened {
				w.LogInfo("process: output channel closed!")
				return
			}

			for _, dm := range batch.Messages {
				switch w.GetConfig().Loggers.Stdout.Mode {
				case config.ModePCAP:
					if len(dm.DNS.Payload) == 0 {
						w.CountEgressDiscarded()
						w.LogError("process: no dns payload to encode, drop it")
						continue
					}

					var err error
					w.pcapBuffer, err = dm.EncodeToPacketBytes(w.pcapBuffer[:0], w.GetConfig().Loggers.Stdout.OverwriteDNSPortPcap)
					if err != nil {
						w.CountEgressDiscarded()
						w.LogError("process: unable to encode packet: %s", err)
						continue
					}

					bufSize := len(w.pcapBuffer)
					ci := gopacket.CaptureInfo{
						Timestamp:     time.Unix(int64(dm.DNSTap.TimeSec), int64(dm.DNSTap.TimeNsec)),
						CaptureLength: bufSize,
						Length:        bufSize,
					}

					if err := w.writerPcap.WritePacket(ci, w.pcapBuffer); err != nil {
						w.CountEgressDiscarded()
						w.LogError("process: unable to write packet: %s", err)
						continue
					}

				case config.ModeText:
					// get buffer from pool
					buf := w.GetTextBuffer()
					buf.Reset()

					var err error
					if w.textFormatter != nil {
						err = w.textFormatter.Format(dm, buf)
					} else {
						err = dm.ToTextLine(w.textFormat, w.GetConfig().Global.TextFormatDelimiter, w.GetConfig().Global.TextFormatBoundary, buf)
					}
					if err == nil {
						w.writerRaw.Write(buf.Bytes())
						w.writerRaw.WriteByte('\n')
					}

					// return buffer to pool
					w.PutTextBuffer(buf)

				case config.ModeJinja:
					textLine, err := dm.ToTextTemplate(w.jinjaFormat)
					if err != nil {
						w.CountEgressDiscarded()
						w.LogError("process: unable to update template: %s", err)
						continue
					}
					w.writerRaw.WriteString(textLine)
					w.writerRaw.WriteByte('\n')

				case config.ModeJSON:
					err := jsonEncoder.Encode(dm)
					if err != nil {
						w.CountEgressDiscarded()
						w.LogError("process: unable to encode json: %s", err)
						continue
					}

				case config.ModeFlatJSON:
					if dm.Relabeling != nil {
						flat, err := dm.Flatten()
						if err != nil {
							w.CountEgressDiscarded()
							w.LogError("process: flattening DNS message failed: %e", err)
							continue
						}
						err = jsonEncoder.Encode(flat)
						if err != nil {
							w.CountEgressDiscarded()
							w.LogError("process: unable to encode flat json: %s", err)
							continue
						}
					} else {
						buf := w.GetTextBuffer()
						buf.Reset()
						dm.GetTimestampRFC3339()
						dm.EncodeFlatJSON(buf)
						buf.WriteByte('\n')
						w.writerRaw.Write(buf.Bytes())
						w.PutTextBuffer(buf)
					}
				}
			}
			batch.Release()
		}
	}
}

func init() {
	RegisterLogger("stdout", func(c *config.Config) bool { return c.Loggers.Stdout.Enable }, func(c *config.Config, l *logger.Logger, s string) Worker {
		return NewStdOut(c, l, s)
	})
}
