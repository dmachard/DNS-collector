package loggers

import (
	"bytes"
	"encoding/json"
	"io"
	"log"
	"os"
	"strings"
	"time"

	"github.com/dmachard/go-dnscollector/dnsutils"
	"github.com/dmachard/go-dnscollector/transformers"
	"github.com/dmachard/go-logger"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
)

func IsStdoutValidMode(mode string) bool {
	switch mode {
	case
		dnsutils.ModeText,
		dnsutils.ModeJSON,
		dnsutils.ModeFlatJSON,
		dnsutils.ModePCAP:
		return true
	}
	return false
}

type StdOut struct {
	stopProcess chan bool
	doneProcess chan bool
	stopRun     chan bool
	doneRun     chan bool
	inputChan   chan dnsutils.DNSMessage
	outputChan  chan dnsutils.DNSMessage
	textFormat  []string
	config      *dnsutils.Config
	configChan  chan *dnsutils.Config
	logger      *logger.Logger
	writerText  *log.Logger
	writerPcap  *pcapgo.Writer
	name        string
}

func NewStdOut(config *dnsutils.Config, console *logger.Logger, name string) *StdOut {
	console.Info("[%s] logger=stdout - enabled", name)
	o := &StdOut{
		stopProcess: make(chan bool),
		doneProcess: make(chan bool),
		stopRun:     make(chan bool),
		doneRun:     make(chan bool),
		inputChan:   make(chan dnsutils.DNSMessage, config.Loggers.Stdout.ChannelBufferSize),
		outputChan:  make(chan dnsutils.DNSMessage, config.Loggers.Stdout.ChannelBufferSize),
		logger:      console,
		config:      config,
		configChan:  make(chan *dnsutils.Config),
		writerText:  log.New(os.Stdout, "", 0),
		name:        name,
	}
	o.ReadConfig()
	return o
}

func (c *StdOut) GetName() string { return c.name }

func (c *StdOut) SetLoggers(loggers []dnsutils.Worker) {}

func (c *StdOut) ReadConfig() {
	if !IsStdoutValidMode(c.config.Loggers.Stdout.Mode) {
		c.logger.Fatal("["+c.name+"] logger=stdout - invalid mode: ", c.config.Loggers.Stdout.Mode)
	}

	if len(c.config.Loggers.Stdout.TextFormat) > 0 {
		c.textFormat = strings.Fields(c.config.Loggers.Stdout.TextFormat)
	} else {
		c.textFormat = strings.Fields(c.config.Global.TextFormat)
	}
}

func (c *StdOut) ReloadConfig(config *dnsutils.Config) {
	c.LogInfo("reload configuration!")
	c.configChan <- config
}

func (c *StdOut) LogInfo(msg string, v ...interface{}) {
	c.logger.Info("["+c.name+"] logger=stdout - "+msg, v...)
}

func (c *StdOut) LogError(msg string, v ...interface{}) {
	c.logger.Error("["+c.name+"] logger=stdout - "+msg, v...)
}

func (c *StdOut) SetTextWriter(b *bytes.Buffer) {
	c.writerText = log.New(os.Stdout, "", 0)
	c.writerText.SetOutput(b)
}

func (c *StdOut) SetPcapWriter(w io.Writer) {
	c.LogInfo("init pcap writer")

	c.writerPcap = pcapgo.NewWriter(w)
	if err := c.writerPcap.WriteFileHeader(65536, layers.LinkTypeEthernet); err != nil {
		c.logger.Fatal("["+c.name+"] logger=stdout - pcap init error: %e", err)
	}
}

func (c *StdOut) Channel() chan dnsutils.DNSMessage {
	return c.inputChan
}

func (c *StdOut) Stop() {
	c.LogInfo("stopping to run...")
	c.stopRun <- true
	<-c.doneRun

	c.LogInfo("stopping to process...")
	c.stopProcess <- true
	<-c.doneProcess
}

func (c *StdOut) Run() {
	c.LogInfo("running in background...")

	// prepare transforms
	listChannel := []chan dnsutils.DNSMessage{}
	listChannel = append(listChannel, c.outputChan)
	subprocessors := transformers.NewTransforms(&c.config.OutgoingTransformers, c.logger, c.name, listChannel, 0)

	// goroutine to process transformed dns messages
	go c.Process()

	// loop to process incoming messages
RUN_LOOP:
	for {
		select {
		case <-c.stopRun:
			// cleanup transformers
			subprocessors.Reset()
			c.doneRun <- true
			break RUN_LOOP

		// new config provided?
		case cfg, opened := <-c.configChan:
			if !opened {
				return
			}
			c.config = cfg
			c.ReadConfig()
			subprocessors.ReloadConfig(&cfg.OutgoingTransformers)

		case dm, opened := <-c.inputChan:
			if !opened {
				c.LogInfo("run: input channel closed!")
				return
			}

			// apply tranforms, init dns message with additionnals parts if necessary
			subprocessors.InitDNSMessageFormat(&dm)
			if subprocessors.ProcessMessage(&dm) == transformers.ReturnDrop {
				continue
			}

			// send to output channel
			c.outputChan <- dm
		}
	}
	c.LogInfo("run terminated")
}

func (c *StdOut) Process() {

	// standard output buffer
	buffer := new(bytes.Buffer)

	if c.config.Loggers.Stdout.Mode == dnsutils.ModePCAP && c.writerPcap == nil {
		c.SetPcapWriter(os.Stdout)
	}

	c.LogInfo("ready to process")
PROCESS_LOOP:
	for {
		select {
		case <-c.stopProcess:
			c.doneProcess <- true
			break PROCESS_LOOP

		case dm, opened := <-c.outputChan:
			if !opened {
				c.LogInfo("process: output channel closed!")
				return
			}

			switch c.config.Loggers.Stdout.Mode {
			case dnsutils.ModePCAP:
				if len(dm.DNS.Payload) == 0 {
					c.LogError("process: no dns payload to encode, drop it")
					continue
				}

				pkt, err := dm.ToPacketLayer()
				if err != nil {
					c.LogError("unable to pack layer: %s", err)
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

				c.writerPcap.WritePacket(ci, buf.Bytes())

			case dnsutils.ModeText:
				c.writerText.Print(dm.String(c.textFormat,
					c.config.Global.TextFormatDelimiter,
					c.config.Global.TextFormatBoundary))

			case dnsutils.ModeJSON:
				json.NewEncoder(buffer).Encode(dm)
				c.writerText.Print(buffer.String())
				buffer.Reset()

			case dnsutils.ModeFlatJSON:
				flat, err := dm.Flatten()
				if err != nil {
					c.LogError("process: flattening DNS message failed: %e", err)
				}
				json.NewEncoder(buffer).Encode(flat)
				c.writerText.Print(buffer.String())
				buffer.Reset()
			}
		}
	}
	c.LogInfo("processing terminated")
}
