package workers

import (
	"bufio"
	"encoding/hex"
	"errors"
	"io"
	"net"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/dmachard/go-dnscollector/v3/dnsutils"
	"github.com/dmachard/go-dnscollector/v3/pkg/config"
	"github.com/dmachard/go-dnscollector/v3/transformers"
	"github.com/dmachard/go-logger"
	"github.com/dmachard/go-netutils"
	powerdns_protobuf "github.com/dmachard/go-powerdns-protobuf"
	"github.com/miekg/dns"
	"google.golang.org/protobuf/proto"
)

type PdnsServer struct {
	*GenericWorker
	connCounter uint64
}

func NewPdnsServer(next []Worker, cfg *config.Config, logger *logger.Logger, name string) *PdnsServer {
	bufSize := cfg.Global.Worker.ChannelBufferSize
	w := &PdnsServer{GenericWorker: NewGenericWorker(cfg, logger, name, "powerdns", bufSize, config.DefaultMonitor)}
	w.SetDefaultRoutes(next)
	w.CheckConfig()
	return w
}

func (w *PdnsServer) CheckConfig() {
	if !netutils.IsValidTLS(w.GetConfig().Collectors.PowerDNS.TLSMinVersion) {
		w.LogFatal(config.PrefixLogWorker + "[" + w.GetName() + "] invalid tls min version")
	}
}

func (w *PdnsServer) HandleConn(conn net.Conn, connID uint64, forceClose chan bool, wg *sync.WaitGroup) {
	// close connection on function exit
	defer func() {
		w.LogInfo("conn #%d - connection handler terminated", connID)
		netutils.Close(conn, w.GetConfig().Collectors.Dnstap.ResetConn)
		wg.Done()
	}()

	// get peer address
	peer := conn.RemoteAddr().String()
	peerName := netutils.GetPeerName(peer)
	w.LogInfo("new connection #%d from %s (%s)", connID, peer, peerName)

	// start protobuf subprocessor
	bufSize := w.GetConfig().Global.Worker.ChannelBufferSize
	pdnsProcessor := NewPdnsProcessor(int(connID), peerName, w.GetConfig(), w.GetLogger(), w.GetName(), bufSize)
	pdnsProcessor.SetMetrics(w.GetMetrics())
	pdnsProcessor.SetDefaultRoutes(w.GetDefaultRoutes())
	pdnsProcessor.SetDefaultDropped(w.GetDroppedRoutes())
	go pdnsProcessor.StartCollect()

	r := bufio.NewReader(conn)
	pbs := powerdns_protobuf.NewProtobufStream(r, conn, 5*time.Second)

	var err error
	var payload *powerdns_protobuf.ProtoPayload
	cleanup := make(chan struct{})

	// goroutine to close the connection properly
	go func() {
		defer func() {
			pdnsProcessor.Stop()
			w.LogInfo("conn #%d - cleanup connection handler terminated", connID)
		}()

		for {
			select {
			case <-forceClose:
				w.LogInfo("conn #%d - force to cleanup the connection handler", connID)
				netutils.Close(conn, w.GetConfig().Collectors.Dnstap.ResetConn)
				return
			case <-cleanup:
				w.LogInfo("conn #%d - cleanup the connection handler", connID)
				return
			}
		}
	}()

	for {
		payload, err = pbs.RecvPayload(false)
		if err != nil {
			connClosed := false

			var opErr *net.OpError
			if errors.As(err, &opErr) {
				if errors.Is(opErr, net.ErrClosed) {
					connClosed = true
				}
			}
			if errors.Is(err, io.EOF) {
				connClosed = true
			}

			if connClosed {
				w.LogInfo("conn #%d - connection closed with peer %s", connID, peer)
			} else {
				w.LogError("conn #%d - powerdns reader error: %s", connID, err)
			}

			// exit goroutine
			close(cleanup)
			break
		}

		// send payload to the channel
		select {
		case pdnsProcessor.GetDataChannel() <- payload.Data(): // Successful send
		default:
			w.WorkerIsBusy("dnstap-processor", 1)
		}
	}
}

func (w *PdnsServer) StartCollect() {
	w.LogInfo("starting data collection")
	defer w.CollectDone()

	var connWG sync.WaitGroup
	connCleanup := make(chan bool)
	cfg := w.GetConfig().Collectors.PowerDNS

	// start to listen
	listener, err := netutils.StartToListen(
		cfg.ListenIP, cfg.ListenPort, "",
		cfg.TLSSupport, netutils.TLSVersion[cfg.TLSMinVersion],
		cfg.CertFile, cfg.KeyFile)
	if err != nil {
		w.LogFatal(config.PrefixLogWorker+"["+w.GetName()+"] listening failed: ", err)
	}
	w.LogInfo("listening on %s", listener.Addr())

	// goroutine to Accept() blocks waiting for new connection.
	acceptChan := make(chan net.Conn)
	netutils.AcceptConnections(listener, acceptChan)

	// main loop
	for {
		select {
		case <-w.OnStop():
			w.LogInfo("stop to listen...")
			listener.Close()

			w.LogInfo("closing connected peers...")
			close(connCleanup)
			connWG.Wait()
			return

			// save the new config
		case cfg := <-w.NewConfig():
			w.SetConfig(cfg)
			w.CheckConfig()

		case conn, opened := <-acceptChan:
			if !opened {
				return
			}

			if w.GetConfig().Collectors.Dnstap.RcvBufSize > 0 {
				before, actual, err := netutils.SetSockRCVBUF(conn, cfg.RcvBufSize, cfg.TLSSupport)
				if err != nil {
					w.LogFatal(config.PrefixLogWorker+"["+w.GetName()+"] unable to set SO_RCVBUF: ", err)
				}
				w.LogInfo("set SO_RCVBUF option, value before: %d, desired: %d, actual: %d", before, cfg.RcvBufSize, actual)
			}

			// handle the connection
			connWG.Add(1)
			connID := atomic.AddUint64(&w.connCounter, 1)
			go w.HandleConn(conn, connID, connCleanup, &connWG)

		}
	}
}

var (
	ProtobufPowerDNSToDNSTap = map[string]string{
		"DNSQueryType":            "CLIENT_QUERY",
		"DNSResponseType":         "CLIENT_RESPONSE",
		"DNSOutgoingQueryType":    "RESOLVER_QUERY",
		"DNSIncomingResponseType": "RESOLVER_RESPONSE",
		"AuthRequest":             "AUTH_QUERY",
		"AuthResponse":            "AUTH_RESPONSE",
		"120":                     "AUTH_QUERY",
	}
)

type PdnsProcessor struct {
	*GenericWorker
	ConnID      int
	PeerName    string
	dataChannel chan []byte
}

func NewPdnsProcessor(connID int, peerName string, cfg *config.Config, logger *logger.Logger, name string, size int) PdnsProcessor {
	w := PdnsProcessor{GenericWorker: NewGenericWorker(cfg, logger, name, "powerdns processor #"+strconv.Itoa(connID), size, config.DefaultMonitor)}
	w.ConnID = connID
	w.PeerName = peerName
	w.dataChannel = make(chan []byte, size)
	return w
}

func (w *PdnsProcessor) GetDataChannel() chan []byte {
	return w.dataChannel
}

func (w *PdnsProcessor) StartCollect() {
	w.LogInfo("starting data collection")
	defer w.CollectDone()

	pbdm := &powerdns_protobuf.PBDNSMessage{}

	// prepare next channels
	defaultRoutes, defaultNames := GetRoutes(w.GetDefaultRoutes())
	droppedRoutes, droppedNames := GetRoutes(w.GetDroppedRoutes())

	// prepare enabled transformers
	transforms := transformers.NewTransforms(&w.GetConfig().IngoingTransformers, w.GetLogger(), w.GetName(), defaultRoutes, w.ConnID)
	batchSize := w.GetBatchSize()
	curBatch := dnsutils.AcquireDNSMessageBatch(batchSize)

	// read incoming dns message
	for {
		select {
		case cfg := <-w.NewConfig():
			w.SetConfig(cfg)
			transforms.ReloadConfig(&cfg.IngoingTransformers)

		case <-w.OnStop():
			if len(curBatch.Messages) > 0 {
				w.SendForwardedBatchTo(defaultRoutes, defaultNames, curBatch)
			} else {
				curBatch.Release()
			}
			transforms.Reset()
			close(w.GetDataChannel())
			return

		case data, opened := <-w.GetDataChannel():
			if !opened {
				if len(curBatch.Messages) > 0 {
					w.SendForwardedBatchTo(defaultRoutes, defaultNames, curBatch)
				} else {
					curBatch.Release()
				}
				w.LogInfo("channel closed, exit")
				return
			}
			// count global messages
			w.CountIngressTraffic()

			err := proto.Unmarshal(data, pbdm)
			if err != nil {
				w.LogError("pbdm decoding, %s", err)
				continue
			}

			// init dns message
			dm := dnsutils.AcquireDNSMessage()
			dm.Init()

			// init powerdns with default values
			dm.PowerDNS = &dnsutils.CollectorPowerDNS{
				Tags:                  []string{},
				OriginalRequestSubnet: "",
				AppliedPolicy:         "",
				Metadata:              map[string]string{},
			}

			dm.DNSTap.Identity = string(pbdm.GetServerIdentity())
			if op, ok := ProtobufPowerDNSToDNSTap[pbdm.GetType().String()]; ok {
				dm.DNSTap.Operation = op
			} else {
				dm.DNSTap.Operation = pbdm.GetType().String()
			}
			for _, event := range pbdm.GetTrace() {
				if op, ok := ProtobufPowerDNSToDNSTap[event.GetEvent().String()]; ok {
					dm.DNSTap.Operation = op
					break
				}
			}

			if ipVersion, valid := netutils.IPVersion[pbdm.GetSocketFamily().String()]; valid {
				dm.NetworkInfo.Family = ipVersion
			} else {
				dm.NetworkInfo.Family = config.StrUnknown
			}
			dm.NetworkInfo.Protocol = pbdm.GetSocketProtocol().String()

			if pbdm.From != nil {
				dm.NetworkInfo.SetQueryIPBytes(pbdm.From)
			}
			dm.NetworkInfo.QueryPort = dnsutils.FastPortToString(pbdm.GetFromPort())
			if pbdm.To != nil {
				dm.NetworkInfo.SetResponseIPBytes(pbdm.To)
			}
			dm.NetworkInfo.ResponsePort = dnsutils.FastPortToString(pbdm.GetToPort())

			dm.DNS.ID = int(pbdm.GetId())
			dm.DNS.Length = int(pbdm.GetInBytes())
			dm.DNSTap.TimeSec = int(pbdm.GetTimeSec())
			dm.DNSTap.TimeNsec = int(pbdm.GetTimeUsec()) * 1e3

			if int(pbdm.Type.Number())%2 == 1 {
				dm.DNS.Type = dnsutils.DNSQuery
			} else {
				dm.DNS.Type = dnsutils.DNSReply

				tsQuery := float64(pbdm.Response.GetQueryTimeSec()) + float64(pbdm.Response.GetQueryTimeUsec())/1e6
				tsReply := float64(pbdm.GetTimeSec()) + float64(pbdm.GetTimeUsec())/1e6

				// convert latency to human
				dm.DNSTap.Latency = tsReply - tsQuery
				dm.DNSTap.LatencyMs = int((tsReply - tsQuery) * 1000)

				dm.DNS.Rcode = dnsutils.RcodeToString(int(pbdm.Response.GetRcode()))
			}

			// compute timestamp
			ts := time.Unix(int64(dm.DNSTap.TimeSec), int64(dm.DNSTap.TimeNsec))
			dm.DNSTap.Timestamp = ts.UnixNano()
			dm.DNSTap.TimestampRFC3339 = "-"

			dm.DNS.Qname = pbdm.Question.GetQName()
			// remove ending dot ?
			dm.DNS.Qname = strings.TrimSuffix(dm.DNS.Qname, ".")

			// get query type
			dm.DNS.Qtype = dnsutils.RdatatypeToString(int(pbdm.Question.GetQType()))

			// get specific powerdns params
			pdns := dnsutils.CollectorPowerDNS{}

			// get PowerDNS OriginalRequestSubnet
			ip := pbdm.GetOriginalRequestorSubnet()
			if len(ip) == 4 {
				pdns.OriginalRequestSubnet = dnsutils.FastIPv4ToString(ip)
			} else if len(ip) == 16 {
				pdns.OriginalRequestSubnet = net.IP(ip).String()
			}

			// get PowerDNS tags
			if tags := pbdm.GetResponse().GetTags(); len(tags) > 0 {
				pdns.Tags = tags
			}

			// get powerdns open telemetry data
			if opendata := pbdm.GetOpenTelemetryData(); len(opendata) > 0 {
				pdns.OpenTelemetryData = hex.EncodeToString(opendata)
			}

			// get powerdns edns version
			if ednsVersion := pbdm.GetEdnsVersion(); ednsVersion > 0 {
				pdns.EdnsVersion = strconv.Itoa(int(ednsVersion))
			}

			// get powerdns ede
			if pbdm.Ede != nil {
				ede := int(pbdm.GetEde())
				pdns.Ede = &ede
			}
			if len(pbdm.GetEdeText()) > 0 {
				pdns.EdeText = pbdm.GetEdeText()
			}

			// get powerdns opentelemetry trace id
			if traceID := pbdm.GetOpenTelemetryTraceID(); len(traceID) > 0 {
				pdns.OpenTelemetryTraceID = hex.EncodeToString(traceID)
			}

			// get PowerDNS policy applied
			if resp := pbdm.GetResponse(); resp != nil {
				pdns.AppliedPolicy = resp.GetAppliedPolicy()
				pdns.AppliedPolicyHit = resp.GetAppliedPolicyHit()
				pdns.AppliedPolicyKind = resp.GetAppliedPolicyKind().String()
				pdns.AppliedPolicyTrigger = resp.GetAppliedPolicyTrigger()
				pdns.AppliedPolicyType = resp.GetAppliedPolicyType().String()
			}

			// get PowerDNS metadata
			if meta := pbdm.GetMeta(); len(meta) > 0 {
				metas := make(map[string]string, len(meta))
				for _, e := range meta {
					metas[e.GetKey()] = strings.Join(e.Value.StringVal, " ")
				}
				pdns.Metadata = metas
			}

			// get http protocol version
			if pbdm.GetSocketProtocol().String() == "DOH" {
				pdns.HTTPVersion = pbdm.GetHttpVersion().String()
			}

			// get some string
			if len(pbdm.MessageId) > 0 {
				pdns.MessageID = hex.EncodeToString(pbdm.MessageId)
			}
			if len(pbdm.InitialRequestId) > 0 {
				pdns.InitialRequestorID = hex.EncodeToString(pbdm.InitialRequestId)
			}
			pdns.RequestorID = pbdm.GetRequestorId()
			pdns.DeviceName = pbdm.GetDeviceName()
			if len(pbdm.DeviceId) > 0 {
				pdns.DeviceID = hex.EncodeToString(pbdm.DeviceId)
			}

			// finally set pdns to dns message
			dm.PowerDNS = &pdns

			// decode answers
			RRs := pbdm.GetResponse().GetRrs()
			if len(RRs) > 0 {
				answers := make([]dnsutils.DNSAnswer, 0, len(RRs))
				for j := range RRs {
					var rdata string
					switch RRs[j].GetType() {
					case 1:
						rdata = dnsutils.FastIPv4ToString(RRs[j].GetRdata())
					case 28:
						rdata = net.IP(RRs[j].GetRdata()).String()
					default:
						rdata = string(RRs[j].GetRdata())
					}

					rr := dnsutils.DNSAnswer{
						Name:      RRs[j].GetName(),
						Rdatatype: dnsutils.RdatatypeToString(int(RRs[j].GetType())),
						Class:     dnsutils.ClassToString(int(RRs[j].GetClass())),
						TTL:       int(RRs[j].GetTtl()),
						Rdata:     rdata,
					}
					answers = append(answers, rr)
				}
				dm.DNS.DNSRRs.Answers = answers
			}

			if w.GetConfig().Collectors.PowerDNS.AddDNSPayload {

				qname := dns.Fqdn(pbdm.Question.GetQName())
				newDNS := new(dns.Msg)
				newDNS.Id = uint16(pbdm.GetId())
				newDNS.Response = false

				question := dns.Question{
					Name:   qname,
					Qtype:  uint16(pbdm.Question.GetQType()),
					Qclass: uint16(pbdm.Question.GetQClass()),
				}
				newDNS.Question = append(newDNS.Question, question)

				if int(pbdm.Type.Number())%2 != 1 {
					newDNS.Response = true
					newDNS.Rcode = int(pbdm.Response.GetRcode())

					newDNS.Answer = []dns.RR{}
					rrs := pbdm.GetResponse().GetRrs()
					for j := range rrs {
						rrname := dns.Fqdn(rrs[j].GetName())
						switch rrs[j].GetType() {
						// A
						case 1:
							rdata := &dns.A{
								Hdr: dns.RR_Header{Name: rrname, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: rrs[j].GetTtl()},
								A:   net.IP(rrs[j].GetRdata()),
							}
							newDNS.Answer = append(newDNS.Answer, rdata)
						// AAAA
						case 28:
							rdata := &dns.AAAA{
								Hdr:  dns.RR_Header{Name: rrname, Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: rrs[j].GetTtl()},
								AAAA: net.IP(rrs[j].GetRdata()),
							}
							newDNS.Answer = append(newDNS.Answer, rdata)
						// CNAME
						case 5:
							rdata := &dns.CNAME{
								Hdr:    dns.RR_Header{Name: rrname, Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: rrs[j].GetTtl()},
								Target: dns.Fqdn(string(rrs[j].GetRdata())),
							}
							newDNS.Answer = append(newDNS.Answer, rdata)
						}

					}

				}

				pktWire, err := newDNS.Pack()
				if err == nil {
					dm.DNS.Payload = pktWire
					if dm.DNS.Length == 0 {
						dm.DNS.Length = len(pktWire)
					}
				} else {
					dm.DNS.MalformedPacket = true
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

			// append to batch and dispatch
			curBatch.Messages = append(curBatch.Messages, dm)
			if len(curBatch.Messages) >= batchSize || len(w.GetDataChannel()) == 0 {
				w.SendForwardedBatchTo(defaultRoutes, defaultNames, curBatch)
				curBatch = dnsutils.AcquireDNSMessageBatch(batchSize)
			}
		}
	}
}

func init() {
	RegisterCollector("powerdns", func(c *config.Config) bool { return c.Collectors.PowerDNS.Enable }, func(c *config.Config, l *logger.Logger, s string) Worker {
		return NewPdnsServer(nil, c, l, s)
	})
}
