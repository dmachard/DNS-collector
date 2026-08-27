package transformers

import (
	"context"
	"fmt"
	"net"
	"os"
	"sync/atomic"
	"time"

	"github.com/dmachard/go-dnscollector/v2/dnsutils"
	"github.com/dmachard/go-dnscollector/v2/pkg/bgpmrt"
	"github.com/dmachard/go-dnscollector/v2/pkgconfig"
	"github.com/dmachard/go-logger"
)

type BGPTransform struct {
	GenericTransformer
	tree         atomic.Pointer[bgpmrt.BGPRadixTree]
	cancelReload context.CancelFunc
	lastModTime  time.Time
	lastFileSize int64
}

func NewDNSBGPTransform(config *pkgconfig.ConfigTransformers, logger *logger.Logger, name string, instance int, nextWorkers []chan *dnsutils.DNSMessageBatch) *BGPTransform {
	t := &BGPTransform{GenericTransformer: NewTransformer(config, logger, "bgp", name, instance, nextWorkers)}
	return t
}

func (t *BGPTransform) GetTransforms() ([]Subtransform, error) {
	subtransforms := []Subtransform{}
	if t.config.BGP.Enable {
		if err := t.Open(); err != nil {
			return nil, fmt.Errorf("open error %w", err)
		}
		subtransforms = append(subtransforms, Subtransform{name: "bgp:lookup", processFunc: t.bgpTransform})
	}
	return subtransforms, nil
}

func (t *BGPTransform) Reset() {
	if t.config.BGP.Enable {
		t.Close()
	}
}

func (t *BGPTransform) Open() error {
	t.Close()

	if len(t.config.BGP.MrtFile) == 0 {
		return fmt.Errorf("bgp mrt-file path is required")
	}

	if err := t.loadMRTFile(); err != nil {
		return err
	}

	// Start background housekeeping loop for auto-reloading if configured
	if t.config.BGP.MrtCheckUpdateInterval > 0 {
		ctx, cancel := context.WithCancel(context.Background())
		t.cancelReload = cancel
		go t.watchMRTFile(ctx)
	}

	return nil
}

func (t *BGPTransform) Close() {
	if t.cancelReload != nil {
		t.cancelReload()
		t.cancelReload = nil
	}
}

func (t *BGPTransform) loadMRTFile() error {
	fileInfo, err := os.Stat(t.config.BGP.MrtFile)
	if err != nil {
		return fmt.Errorf("failed to stat MRT file: %w", err)
	}

	parser := bgpmrt.NewMRTParser()
	tree, err := parser.ParseFile(t.config.BGP.MrtFile)
	if err != nil {
		return fmt.Errorf("failed to parse MRT file: %w", err)
	}

	t.tree.Store(tree)
	t.lastModTime = fileInfo.ModTime()
	t.lastFileSize = fileInfo.Size()

	t.LogInfo("MRT file loaded (%d prefixes from %s)", tree.TotalPrefixes(), t.config.BGP.MrtFile)
	return nil
}

func (t *BGPTransform) watchMRTFile(ctx context.Context) {
	interval := time.Duration(t.config.BGP.MrtCheckUpdateInterval) * time.Second
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			fileInfo, err := os.Stat(t.config.BGP.MrtFile)
			if err != nil {
				t.LogError("failed to check MRT file update: %v", err)
				continue
			}

			if fileInfo.ModTime().After(t.lastModTime) || fileInfo.Size() != t.lastFileSize {
				t.LogInfo("MRT file change detected, reloading...")
				if err := t.loadMRTFile(); err != nil {
					t.LogError("failed to reload MRT file: %v", err)
				}
			}
		}
	}
}

func (t *BGPTransform) Lookup(ip net.IP) *bgpmrt.BGPRecord {
	tree := t.tree.Load()
	if tree == nil {
		return nil
	}
	return tree.Lookup(ip)
}

func (t *BGPTransform) bgpTransform(dm *dnsutils.DNSMessage) (int, error) {
	if dm.BGP == nil {
		dm.BGP = &dnsutils.TransformBGP{
			OriginASN: "-",
			ASPath:    "-",
			Prefix:    "-",
		}
	}

	var parsedIP net.IP

	// Lookup ECS IP if enabled and present
	if t.config.BGP.LookupECS && len(dm.EDNS.Options) > 0 {
		parsedIP = lookupECSIP(dm)
	}

	if parsedIP == nil {
		parsedIP = net.ParseIP(dm.NetworkInfo.GetQueryIP())
	}

	rec := t.Lookup(parsedIP)
	if rec != nil {
		if t.config.BGP.OriginASN {
			dm.BGP.OriginASN = rec.OriginASN
		}
		if t.config.BGP.ASPath {
			dm.BGP.ASPath = rec.ASPath
		}
		if t.config.BGP.Prefix {
			dm.BGP.Prefix = rec.Prefix
		}
	} else {
		if t.config.BGP.OriginASN {
			dm.BGP.OriginASN = "-"
		}
		if t.config.BGP.ASPath {
			dm.BGP.ASPath = "-"
		}
		if t.config.BGP.Prefix {
			dm.BGP.Prefix = "-"
		}
	}

	return ReturnKeep, nil
}
