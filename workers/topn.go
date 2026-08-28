package workers

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/dmachard/go-dnscollector/v3/dnsutils"
	"github.com/dmachard/go-dnscollector/v3/pkg/config"
	"github.com/dmachard/go-logger"
	"github.com/dmachard/go-topmap"
)

type TopItem struct {
	Rank  int    `json:"rank"`
	Name  string `json:"name"`
	Count int    `json:"count"`
}

type TopNReport struct {
	Timestamp    string    `json:"timestamp"`
	Interval     int       `json:"interval"`
	TotalQueries uint64    `json:"total_queries"`
	TopQnames    []TopItem `json:"top_qnames,omitempty"`
	TopClients   []TopItem `json:"top_clients,omitempty"`
	TopRcodes    []TopItem `json:"top_rcodes,omitempty"`
	TopTlds      []TopItem `json:"top_tlds,omitempty"`
}

type TopN struct {
	*GenericWorker
	mu           sync.Mutex
	topSize      int
	topQnames    *topmap.TopMap
	mapQnames    map[string]int
	topClients   *topmap.TopMap
	mapClients   map[string]int
	topRcodes    *topmap.TopMap
	mapRcodes    map[string]int
	topTlds      *topmap.TopMap
	mapTlds      map[string]int
	totalQueries atomic.Uint64
	writer       io.Writer
	fileWriter   *os.File
	stopReport   chan struct{}
}

func NewTopN(cfg *config.Config, console *logger.Logger, name string) *TopN {
	bufSize := cfg.Global.Worker.ChannelBufferSize
	w := &TopN{
		GenericWorker: NewGenericWorker(cfg, console, name, "topn", bufSize, config.DefaultMonitor),
		writer:        os.Stdout,
		stopReport:    make(chan struct{}),
	}
	w.ReadConfig()
	return w
}

func (w *TopN) ReadConfig() {
	cfg := w.GetConfig().Loggers.TopN

	topSize := cfg.TopN
	if topSize <= 0 {
		topSize = 10
	}
	w.topSize = topSize

	w.mu.Lock()
	if cfg.TrackQnames {
		w.topQnames = topmap.NewTopMap(topSize)
		w.mapQnames = make(map[string]int)
	}
	if cfg.TrackClients {
		w.topClients = topmap.NewTopMap(topSize)
		w.mapClients = make(map[string]int)
	}
	if cfg.TrackRcodes {
		w.topRcodes = topmap.NewTopMap(topSize)
		w.mapRcodes = make(map[string]int)
	}
	if cfg.TrackTlds {
		w.topTlds = topmap.NewTopMap(topSize)
		w.mapTlds = make(map[string]int)
	}
	w.mu.Unlock()

	if cfg.Output == "file" && len(cfg.FilePath) > 0 {
		f, err := os.OpenFile(cfg.FilePath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
		if err != nil {
			w.LogError("failed to open topn output file: %v", err)
			w.writer = os.Stdout
		} else {
			w.fileWriter = f
			w.writer = bufio.NewWriter(f)
		}
	} else {
		w.writer = os.Stdout
	}
}

func (w *TopN) SetWriter(wr io.Writer) {
	w.writer = wr
}

func (w *TopN) Stop() {
	select {
	case <-w.stopReport:
	default:
		close(w.stopReport)
	}
	if w.fileWriter != nil {
		_ = w.fileWriter.Close()
	}
	w.GenericWorker.Stop()
}

func (w *TopN) RecordQname(qname string) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.topQnames != nil {
		w.mapQnames[qname]++
		w.topQnames.Record(qname, w.mapQnames[qname])
	}
}

func (w *TopN) RecordClient(ip string) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.topClients != nil {
		w.mapClients[ip]++
		w.topClients.Record(ip, w.mapClients[ip])
	}
}

func (w *TopN) RecordRcode(rcode string) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.topRcodes != nil {
		w.mapRcodes[rcode]++
		w.topRcodes.Record(rcode, w.mapRcodes[rcode])
	}
}

func (w *TopN) RecordTld(tld string) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.topTlds != nil {
		w.mapTlds[tld]++
		w.topTlds.Record(tld, w.mapTlds[tld])
	}
}

func (w *TopN) StartCollect() {
	w.LogInfo("starting data collection")
	defer w.CollectDone()

	cfg := w.GetConfig().Loggers.TopN
	interval := cfg.Interval
	if interval <= 0 {
		interval = 60
	}

	var reportWg sync.WaitGroup
	reportWg.Add(1)
	go func() {
		defer reportWg.Done()
		w.reportLoop(time.Duration(interval) * time.Second)
	}()

	w.RunBatchLoop(func(batch *dnsutils.DNSMessageBatch) {
		for _, dm := range batch.Messages {
			w.CountIngressTraffic()
			w.totalQueries.Add(1)

			if w.topQnames != nil && len(dm.DNS.Qname) > 0 && dm.DNS.Qname != "-" {
				w.RecordQname(dm.DNS.Qname)
			}
			if w.topClients != nil && len(dm.NetworkInfo.QueryIP) > 0 && dm.NetworkInfo.QueryIP != "-" {
				w.RecordClient(dm.NetworkInfo.QueryIP)
			}
			if w.topRcodes != nil && len(dm.DNS.Rcode) > 0 && dm.DNS.Rcode != "-" {
				w.RecordRcode(dm.DNS.Rcode)
			}
			if w.topTlds != nil && dm.PublicSuffix != nil && len(dm.PublicSuffix.QnamePublicSuffix) > 0 {
				w.RecordTld(dm.PublicSuffix.QnamePublicSuffix)
			}
		}
		batch.Release()
	})

	select {
	case <-w.stopReport:
	default:
		close(w.stopReport)
	}
	reportWg.Wait()
}

func (w *TopN) reportLoop(interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			w.GenerateReport(int(interval.Seconds()))
		case <-w.stopReport:
			return
		}
	}
}

func (w *TopN) snapshotAndReset(tm *topmap.TopMap, m map[string]int) ([]TopItem, *topmap.TopMap, map[string]int) {
	if tm == nil {
		return nil, nil, nil
	}
	records := tm.Get()
	result := make([]TopItem, len(records))
	for i, r := range records {
		result[i] = TopItem{
			Rank:  i + 1,
			Name:  r.Name,
			Count: r.Hit,
		}
	}
	newTM := topmap.NewTopMap(w.topSize)
	newMap := make(map[string]int)
	return result, newTM, newMap
}

func (w *TopN) GenerateReport(intervalSec int) {
	total := w.totalQueries.Swap(0)

	w.mu.Lock()
	topQ, newQ, newMapQ := w.snapshotAndReset(w.topQnames, w.mapQnames)
	if w.topQnames != nil {
		w.topQnames, w.mapQnames = newQ, newMapQ
	}

	topC, newC, newMapC := w.snapshotAndReset(w.topClients, w.mapClients)
	if w.topClients != nil {
		w.topClients, w.mapClients = newC, newMapC
	}

	topR, newR, newMapR := w.snapshotAndReset(w.topRcodes, w.mapRcodes)
	if w.topRcodes != nil {
		w.topRcodes, w.mapRcodes = newR, newMapR
	}

	topT, newT, newMapT := w.snapshotAndReset(w.topTlds, w.mapTlds)
	if w.topTlds != nil {
		w.topTlds, w.mapTlds = newT, newMapT
	}
	w.mu.Unlock()

	now := time.Now().UTC().Format(time.RFC3339)
	mode := w.GetConfig().Loggers.TopN.Mode

	switch mode {
	case "json":
		report := TopNReport{
			Timestamp:    now,
			Interval:     intervalSec,
			TotalQueries: total,
			TopQnames:    topQ,
			TopClients:   topC,
			TopRcodes:    topR,
			TopTlds:      topT,
		}
		data, err := json.Marshal(report)
		if err == nil {
			_, _ = fmt.Fprintln(w.writer, string(data))
		}
	case "flat-json":
		emitFlat := func(category string, items []TopItem) {
			for _, item := range items {
				line := map[string]interface{}{
					"timestamp": now,
					"interval":  intervalSec,
					"category":  category,
					"rank":      item.Rank,
					"name":      item.Name,
					"count":     item.Count,
				}
				data, err := json.Marshal(line)
				if err == nil {
					_, _ = fmt.Fprintln(w.writer, string(data))
				}
			}
		}
		emitFlat("qname", topQ)
		emitFlat("client", topC)
		emitFlat("rcode", topR)
		emitFlat("tld", topT)
	case "text":
		fallthrough
	default:
		_, _ = fmt.Fprintf(w.writer, "\n=== [Top-N Summary Report (%s - %ds window - %d queries)] ===\n", now, intervalSec, total)
		printTable := func(title string, items []TopItem) {
			if len(items) == 0 {
				return
			}
			_, _ = fmt.Fprintf(w.writer, "-- %s --\n", title)
			for _, item := range items {
				_, _ = fmt.Fprintf(w.writer, "  #%-2d %-40s %d\n", item.Rank, item.Name, item.Count)
			}
		}
		printTable("Top Domains", topQ)
		printTable("Top Clients", topC)
		printTable("Top Rcodes", topR)
		printTable("Top TLDs", topT)
		_, _ = fmt.Fprintln(w.writer, "==========================================================")
	}

	if bw, ok := w.writer.(*bufio.Writer); ok {
		_ = bw.Flush()
	}
}

func init() {
	RegisterLogger("topn", func(c *config.Config) bool { return c.Loggers.TopN.Enable }, func(c *config.Config, l *logger.Logger, s string) Worker {
		return NewTopN(c, l, s)
	})
}
