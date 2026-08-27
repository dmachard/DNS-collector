package workers

import (
	"time"

	"github.com/dmachard/go-dnscollector/v3/dnsutils"
	"github.com/dmachard/go-dnscollector/v3/pkg/config"
	"github.com/dmachard/go-dnscollector/v3/transformers"
	"github.com/dmachard/go-logger"
)

type DNSProcessor struct {
	*GenericWorker
}

func NewDNSProcessor(cfg *config.Config, logger *logger.Logger, name string, size int) DNSProcessor {
	w := DNSProcessor{GenericWorker: NewGenericWorker(cfg, logger, name, "dns processor", size, config.DefaultMonitor)}
	return w
}

func (w *DNSProcessor) StartCollect() {
	w.LogInfo("starting data collection")
	defer w.CollectDone()

	// prepare next channels
	defaultRoutes, defaultNames := GetRoutes(w.GetDefaultRoutes())
	droppedRoutes, droppedNames := GetRoutes(w.GetDroppedRoutes())

	// prepare enabled transformers
	transforms := transformers.NewTransforms(&w.GetConfig().IngoingTransformers, w.GetLogger(), w.GetName(), defaultRoutes, 0)

	// read incoming dns message
	for {
		select {
		case cfg := <-w.NewConfig():
			w.SetConfig(cfg)
			transforms.ReloadConfig(&cfg.IngoingTransformers)

		case <-w.OnStop():
			transforms.Reset()
			return

		case batch, opened := <-w.GetInputChannel():
			if !opened {
				w.LogInfo("channel closed, exit")
				return
			}
			outBatch := dnsutils.AcquireDNSMessageBatch(len(batch.Messages))
			for _, dm := range batch.Messages {
				// count global messages
				w.CountIngressTraffic()

				// compute timestamp
				ts := time.Unix(int64(dm.DNSTap.TimeSec), int64(dm.DNSTap.TimeNsec))
				dm.DNSTap.Timestamp = ts.UnixNano()
				dm.DNSTap.TimestampRFC3339 = "-"

				// decode the dns payload
				dnsHeader, err := dnsutils.DecodeDNS(dm.DNS.Payload)
				if err != nil {
					dm.DNS.MalformedPacket = true
					w.LogError("dns parser malformed packet: %s - %v+", err, dm)
				}

				// get number of questions and answers
				dm.DNS.QdCount = dnsHeader.Qdcount
				dm.DNS.AnCount = dnsHeader.Ancount
				dm.DNS.ArCount = dnsHeader.Arcount
				dm.DNS.NsCount = dnsHeader.Nscount

				// dns reply ?
				if dnsHeader.Qr == 1 {
					dm.DNSTap.Operation = "CLIENT_RESPONSE"
					dm.DNS.Type = dnsutils.DNSReply
					qip := dm.NetworkInfo.QueryIP
					qport := dm.NetworkInfo.QueryPort
					qbuf := dm.NetworkInfo.QueryIPBuf
					qlen := dm.NetworkInfo.QueryIPLen
					dm.NetworkInfo.QueryIP = dm.NetworkInfo.ResponseIP
					dm.NetworkInfo.QueryPort = dm.NetworkInfo.ResponsePort
					dm.NetworkInfo.QueryIPBuf = dm.NetworkInfo.ResponseIPBuf
					dm.NetworkInfo.QueryIPLen = dm.NetworkInfo.ResponseIPLen
					dm.NetworkInfo.ResponseIP = qip
					dm.NetworkInfo.ResponsePort = qport
					dm.NetworkInfo.ResponseIPBuf = qbuf
					dm.NetworkInfo.ResponseIPLen = qlen
				} else {
					dm.DNS.Type = dnsutils.DNSQuery
					dm.DNSTap.Operation = dnsutils.DNSTapClientQuery
				}

				if err = dnsutils.DecodePayload(dm, &dnsHeader, w.GetConfig()); err != nil {
					w.LogError("%v - %v", err, dm)
				}

				if dm.DNS.MalformedPacket {
					if w.GetConfig().Global.Trace.LogMalformed {
						w.LogInfo("payload: %v", dm.DNS.Payload)
					}
				}

				// count output packets
				w.CountEgressTraffic()

				// apply all enabled transformers
				transformResult, err := transforms.ProcessMessage(dm)
				if err != nil {
					w.LogError(err.Error())
				}
				if transformResult == transformers.ReturnDrop {
					w.SendDroppedTo(droppedRoutes, droppedNames, dm)
					continue
				}

				// append to output batch
				// Retain so the incoming batch's Release() does not zero dm
				// while outBatch is still in flight to downstream routes.
				dm.Retain(1)
				outBatch.Messages = append(outBatch.Messages, dm)
			}
			if len(outBatch.Messages) > 0 {
				w.SendForwardedBatchTo(defaultRoutes, defaultNames, outBatch)
			} else {
				outBatch.Release()
			}
			batch.Release()
		}
	}
}
