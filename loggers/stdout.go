package loggers

import (
	"bytes"
	"encoding/json"
	"log"
	"os"
	"strings"

	"github.com/dmachard/go-dnscollector/dnsutils"
	"github.com/dmachard/go-dnscollector/transformers"
	"github.com/dmachard/go-logger"
)

type StdOut struct {
	done       chan bool
	cleanup    chan bool
	channel    chan dnsutils.DnsMessage
	textFormat []string
	config     *dnsutils.Config
	logger     *logger.Logger
	stdout     *log.Logger
	name       string
}

func NewStdOut(config *dnsutils.Config, console *logger.Logger, name string) *StdOut {
	console.Info("[%s] logger=stdout - enabled", name)
	o := &StdOut{
		done:    make(chan bool),
		cleanup: make(chan bool),
		channel: make(chan dnsutils.DnsMessage, config.Loggers.Stdout.ChannelBufferSize),
		logger:  console,
		config:  config,
		stdout:  log.New(os.Stdout, "", 0),
		name:    name,
	}
	o.ReadConfig()
	return o
}

func (c *StdOut) GetName() string { return c.name }

func (c *StdOut) SetLoggers(loggers []dnsutils.Worker) {}

func (c *StdOut) ReadConfig() {
	if len(c.config.Loggers.Stdout.TextFormat) > 0 {
		c.textFormat = strings.Fields(c.config.Loggers.Stdout.TextFormat)
	} else {
		c.textFormat = strings.Fields(c.config.Global.TextFormat)
	}
}

func (c *StdOut) LogInfo(msg string, v ...interface{}) {
	c.logger.Info("["+c.name+"] logger=stdout - "+msg, v...)
}

func (c *StdOut) LogError(msg string, v ...interface{}) {
	c.logger.Error("["+c.name+"] logger=stdout - "+msg, v...)
}

func (o *StdOut) SetBuffer(b *bytes.Buffer) {
	o.stdout.SetOutput(b)
}

func (o *StdOut) Channel() chan dnsutils.DnsMessage {
	return o.channel
}

func (o *StdOut) Stop() {
	o.LogInfo("stopping...")
	o.cleanup <- true

	// read done channel and block until run is terminated
	<-o.done
	o.LogInfo("run terminated")
	close(o.done)
}

func (o *StdOut) Run() {
	o.LogInfo("running in background...")

	// prepare transforms
	listChannel := []chan dnsutils.DnsMessage{}
	listChannel = append(listChannel, o.channel)
	subprocessors := transformers.NewTransforms(&o.config.OutgoingTransformers, o.logger, o.name, listChannel, 0)

	// standard output buffer
	buffer := new(bytes.Buffer)

	for {
		select {
		case <-o.cleanup:
			o.LogInfo("cleanup called")
			//close(o.channel)

			subprocessors.Reset()

			o.done <- true
			return

		case dm, opened := <-o.channel:
			// channel is closed ?
			if !opened {
				o.LogInfo("channel closed, cleanup...")
				o.cleanup <- true
				continue
			}

			// apply tranforms, init dns message with additionnals parts if necessary
			subprocessors.InitDnsMessageFormat(&dm)
			if subprocessors.ProcessMessage(&dm) == transformers.RETURN_DROP {
				continue
			}

			switch o.config.Loggers.Stdout.Mode {
			case dnsutils.MODE_TEXT:
				o.stdout.Print(dm.String(o.textFormat,
					o.config.Global.TextFormatDelimiter,
					o.config.Global.TextFormatBoundary))

			case dnsutils.MODE_JSON:
				json.NewEncoder(buffer).Encode(dm)
				o.stdout.Print(buffer.String())
				buffer.Reset()

			case dnsutils.MODE_FLATJSON:
				flat, err := dm.Flatten()
				if err != nil {
					o.LogError("flattening DNS message failed: %e", err)
				}
				json.NewEncoder(buffer).Encode(flat)
				o.stdout.Print(buffer.String())
				buffer.Reset()
			}
		}
	}
}
