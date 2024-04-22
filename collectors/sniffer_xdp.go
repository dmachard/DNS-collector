//go:build linux || darwin || freebsd
// +build linux darwin freebsd

package collectors

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"time"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/perf"
	"github.com/dmachard/go-dnscollector/dnsutils"
	"github.com/dmachard/go-dnscollector/netutils"
	"github.com/dmachard/go-dnscollector/pkgconfig"
	"github.com/dmachard/go-dnscollector/pkgutils"
	"github.com/dmachard/go-dnscollector/processors"
	"github.com/dmachard/go-dnscollector/xdp"
	"github.com/dmachard/go-logger"
	"golang.org/x/sys/unix"
)

type XDPSniffer struct {
	*pkgutils.Collector
}

func NewXDPSniffer(next []pkgutils.Worker, config *pkgconfig.Config, logger *logger.Logger, name string) *XDPSniffer {
	s := &XDPSniffer{Collector: pkgutils.NewCollector(config, logger, name, "xdp sniffer")}
	s.SetDefaultRoutes(next)
	return s
}

func (c *XDPSniffer) Run() {
	c.LogInfo("running collector...")
	defer func() {
		c.LogInfo("run terminated")
		c.StopIsDone()
	}()

	// init dns processor
	dnsProcessor := processors.NewDNSProcessor(c.GetConfig(), c.GetLogger(), c.GetName(), c.GetConfig().Collectors.XdpLiveCapture.ChannelBufferSize)
	go dnsProcessor.Run(c.GetDefaultRoutes(), c.GetDroppedRoutes())

	// get network interface by name
	iface, err := net.InterfaceByName(c.GetConfig().Collectors.XdpLiveCapture.Device)
	if err != nil {
		c.LogFatal(pkgutils.PrefixLogCollector+"["+c.GetName()+"] lookup network iface: ", err)
	}

	// Load pre-compiled programs into the kernel.
	objs := xdp.BpfObjects{}
	if err := xdp.LoadBpfObjects(&objs, nil); err != nil {
		c.LogFatal(pkgutils.PrefixLogCollector+"["+c.GetName()+"] loading BPF objects: ", err)
	}
	defer objs.Close()

	// Attach the program.
	l, err := link.AttachXDP(link.XDPOptions{
		Program:   objs.XdpSniffer,
		Interface: iface.Index,
	})
	if err != nil {
		c.LogFatal(pkgutils.PrefixLogCollector+"["+c.GetName()+"] could not attach XDP program: ", err)
	}
	defer l.Close()

	c.LogInfo("XDP program attached to iface %q (index %d)", iface.Name, iface.Index)

	perfEvent, err := perf.NewReader(objs.Pkts, 1<<24)
	if err != nil {
		c.LogFatal(pkgutils.PrefixLogCollector+"["+c.GetName()+"] read event: ", err)
	}

	dnsChan := make(chan dnsutils.DNSMessage)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})

	go func(ctx context.Context) {
		defer func() {
			dnsProcessor.Stop()
			c.LogInfo("read data terminated")
			defer close(done)
		}()

		var pkt xdp.BpfPktEvent
		var netErr net.Error
		for {
			select {
			case <-ctx.Done():
				c.LogInfo("stopping sniffer...")
				perfEvent.Close()
				return
			default:
				// The data submitted via bpf_perf_event_output.
				perfEvent.SetDeadline(time.Now().Add(1 * time.Second))
				record, err := perfEvent.Read()
				if err != nil {
					if errors.As(err, &netErr) && netErr.Timeout() {
						continue
					}
					c.LogError("BPF reading map: %s", err)
					break
				}
				if record.LostSamples != 0 {
					c.LogError("BPF dump: Dropped %d samples from kernel perf buffer", record.LostSamples)
					continue
				}

				reader := bytes.NewReader(record.RawSample)
				if err := binary.Read(reader, binary.LittleEndian, &pkt); err != nil {
					c.LogError("BPF reading sample: %s", err)
					break
				}

				// adjust arrival time
				timenow := time.Now().UTC()
				var ts unix.Timespec
				unix.ClockGettime(unix.CLOCK_MONOTONIC, &ts)
				elapsed := time.Since(timenow) * time.Nanosecond
				delta3 := time.Duration(uint64(unix.TimespecToNsec(ts))-pkt.Timestamp) * time.Nanosecond
				tsAdjusted := timenow.Add(-(delta3 + elapsed))

				// convert ip
				var saddr, daddr net.IP
				if pkt.IpVersion == 0x0800 {
					saddr = netutils.GetIPAddress(pkt.SrcAddr, netutils.ConvertIP4)
					daddr = netutils.GetIPAddress(pkt.DstAddr, netutils.ConvertIP4)
				} else {
					saddr = netutils.GetIPAddress(pkt.SrcAddr6, netutils.ConvertIP6)
					daddr = netutils.GetIPAddress(pkt.DstAddr6, netutils.ConvertIP6)
				}

				// prepare DnsMessage
				dm := dnsutils.DNSMessage{}
				dm.Init()

				dm.DNSTap.TimeSec = int(tsAdjusted.Unix())
				dm.DNSTap.TimeNsec = int(tsAdjusted.UnixNano() - tsAdjusted.Unix()*1e9)

				if pkt.SrcPort == 53 {
					dm.DNSTap.Operation = dnsutils.DNSTapClientResponse
				} else {
					dm.DNSTap.Operation = dnsutils.DNSTapClientQuery
				}

				dm.NetworkInfo.QueryIP = saddr.String()
				dm.NetworkInfo.QueryPort = fmt.Sprint(pkt.SrcPort)
				dm.NetworkInfo.ResponseIP = daddr.String()
				dm.NetworkInfo.ResponsePort = fmt.Sprint(pkt.DstPort)

				if pkt.IpVersion == 0x0800 {
					dm.NetworkInfo.Family = netutils.ProtoIPv4
				} else {
					dm.NetworkInfo.Family = netutils.ProtoIPv6
				}

				if pkt.IpProto == 0x11 {
					dm.NetworkInfo.Protocol = netutils.ProtoUDP
					dm.DNS.Payload = record.RawSample[int(pkt.PktOffset)+int(pkt.PayloadOffset):]
					dm.DNS.Length = len(dm.DNS.Payload)
				} else {
					dm.NetworkInfo.Protocol = netutils.ProtoTCP
					dm.DNS.Payload = record.RawSample[int(pkt.PktOffset)+int(pkt.PayloadOffset)+2:]
					dm.DNS.Length = len(dm.DNS.Payload)
				}

				dnsChan <- dm
			}
		}
	}(ctx)

	for {
		select {
		case <-c.OnStop():
			c.LogInfo("stop to listen...")
			cancel()
			<-done
			return

		// new config provided?
		case cfg := <-c.NewConfig():
			c.SetConfig(cfg)

			// send the config to the dns processor
			dnsProcessor.ConfigChan <- cfg

		// dns message to read ?
		case dm := <-dnsChan:

			// update identity with config ?
			dm.DNSTap.Identity = c.GetConfig().GetServerIdentity()

			dnsProcessor.GetChannel() <- dm

		}
	}
}
