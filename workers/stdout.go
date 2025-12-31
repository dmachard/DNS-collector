package workers

import (
	"bufio"
	"encoding/json"
	"io"
	"os"
	"strings"
	"time"

	"github.com/dmachard/go-dnscollector/pkgconfig"
	"github.com/dmachard/go-dnscollector/transformers"
	"github.com/dmachard/go-logger"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
)

func IsStdoutValidMode(mode string) bool {
	switch mode {
	case
		pkgconfig.ModeJinja,
		pkgconfig.ModeText,
		pkgconfig.ModeJSON,
		pkgconfig.ModeFlatJSON,
		pkgconfig.ModePCAP:
		return true
	}
	return false
}

type StdOut struct {
	*GenericWorker
	textFormat  []string
	jinjaFormat string
	writerRaw   *bufio.Writer
	writerPcap  *pcapgo.Writer
}

func NewStdOut(config *pkgconfig.Config, console *logger.Logger, name string) *StdOut {
	bufSize := config.Global.Worker.ChannelBufferSize
	if config.Loggers.Stdout.ChannelBufferSize > 0 {
		bufSize = config.Loggers.Stdout.ChannelBufferSize
	}
	w := &StdOut{GenericWorker: NewGenericWorker(config, console, name, "stdout", bufSize, pkgconfig.DefaultMonitor)}

	// init writers with buffer to minimize syscalls
	writerBufSize := config.Loggers.Stdout.WriterBufferSize
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

		case dm, opened := <-w.GetInputChannel():
			if !opened {
				w.LogInfo("run: input channel closed!")
				return
			}

			// count global messages
			w.CountIngressTraffic()

			// apply transforms, init dns message with additional parts if necessary
			transformResult, err := subprocessors.ProcessMessage(&dm)
			if err != nil {
				w.LogError(err.Error())
			}
			if transformResult == transformers.ReturnDrop {
				w.SendDroppedTo(droppedRoutes, droppedNames, dm)
				continue
			}

			// send to output channel
			w.CountEgressTraffic()
			w.GetOutputChannel() <- dm

			// send to next ?
			w.SendForwardedTo(defaultRoutes, defaultNames, dm)
		}
	}
}

func (w *StdOut) StartLogging() {
	w.LogInfo("logging has started")
	defer w.LoggingDone()

	// setup pcap writer if necessary
	if w.GetConfig().Loggers.Stdout.Mode == pkgconfig.ModePCAP && w.writerPcap == nil {
		w.SetPcapWriter(os.Stdout)
	}

	// setup flush ticker
	flushInterval := time.Duration(w.GetConfig().Loggers.Stdout.FlushInterval * float64(time.Second))
	if flushInterval <= 0 {
		flushInterval = 1 * time.Second
	}
	flushTicker := time.NewTicker(flushInterval)
	defer flushTicker.Stop()

	for {
		select {
		case <-w.OnLoggerStopped():
			w.writerRaw.Flush()
			return

		case <-flushTicker.C:
			w.writerRaw.Flush()

		case dm, opened := <-w.GetOutputChannel():
			if !opened {
				w.LogInfo("process: output channel closed!")
				return
			}

			switch w.GetConfig().Loggers.Stdout.Mode {
			case pkgconfig.ModePCAP:
				if len(dm.DNS.Payload) == 0 {
					w.CountEgressDiscarded()
					w.LogError("process: no dns payload to encode, drop it")
					continue
				}

				pkt, err := dm.ToPacketLayer(w.GetConfig().Loggers.Stdout.OverwriteDNSPortPcap)
				if err != nil {
					w.CountEgressDiscarded()
					w.LogError("process: unable to pack layer: %s", err)
					continue
				}

				buf := gopacket.NewSerializeBuffer()
				opts := gopacket.SerializeOptions{
					FixLengths:       true,
					ComputeChecksums: true,
				}
				for _, l := range pkt {
					l.SerializeTo(buf, opts)
				}

				bufSize := len(buf.Bytes())
				ci := gopacket.CaptureInfo{
					Timestamp:     time.Unix(int64(dm.DNSTap.TimeSec), int64(dm.DNSTap.TimeNsec)),
					CaptureLength: bufSize,
					Length:        bufSize,
				}

				w.writerPcap.WritePacket(ci, buf.Bytes())

			case pkgconfig.ModeText:
				// get buffer from pool
				buf := w.GetTextBuffer()
				buf.Reset()

				err := dm.ToTextLine(w.textFormat, w.GetConfig().Global.TextFormatDelimiter, w.GetConfig().Global.TextFormatBoundary, buf)
				if err == nil {
					w.writerRaw.Write(buf.Bytes())
					w.writerRaw.WriteByte('\n')
				}

				// return buffer to pool
				w.PutTextBuffer(buf)

			case pkgconfig.ModeJinja:
				textLine, err := dm.ToTextTemplate(w.jinjaFormat)
				if err != nil {
					w.CountEgressDiscarded()
					w.LogError("process: unable to update template: %s", err)
					continue
				}
				w.writerRaw.WriteString(textLine)
				w.writerRaw.WriteByte('\n')

			case pkgconfig.ModeJSON:
				err := json.NewEncoder(w.writerRaw).Encode(dm)
				if err != nil {
					w.CountEgressDiscarded()
					w.LogError("process: unable to encode json: %s", err)
					continue
				}

			case pkgconfig.ModeFlatJSON:
				flat, err := dm.Flatten()
				if err != nil {
					w.CountEgressDiscarded()
					w.LogError("process: flattening DNS message failed: %e", err)
					continue
				}
				err = json.NewEncoder(w.writerRaw).Encode(flat)
				if err != nil {
					w.CountEgressDiscarded()
					w.LogError("process: unable to encode flat json: %s", err)
					continue
				}
			}
		}
	}
}
