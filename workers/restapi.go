package workers

import (
	"crypto/tls"
	"encoding/json"
	"net"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/dmachard/go-dnscollector/v2/dnsutils"
	"github.com/dmachard/go-dnscollector/v2/pkg/config"
	"github.com/dmachard/go-dnscollector/v2/transformers"
	"github.com/dmachard/go-logger"
	"github.com/dmachard/go-netutils"
	"github.com/dmachard/go-topmap"
	"github.com/hashicorp/golang-lru/v2/expirable"
)

type HitsRecord struct {
	TotalHits int            `json:"total-hits"`
	Hits      map[string]int `json:"hits"`
}

type SearchBy struct {
	Clients *expirable.LRU[string, *HitsRecord]
	Domains *expirable.LRU[string, *HitsRecord]
}

type HitsStream struct {
	Streams map[string]SearchBy
}

type HitsUniq struct {
	Clients        *expirable.LRU[string, int]
	Domains        *expirable.LRU[string, int]
	NxDomains      *expirable.LRU[string, int]
	SfDomains      *expirable.LRU[string, int]
	PublicSuffixes *expirable.LRU[string, int]
	Suspicious     *expirable.LRU[string, *dnsutils.TransformSuspicious]
}

type KeyHit struct {
	Key string `json:"key"`
	Hit int    `json:"hit"`
}

type RestAPI struct {
	*GenericWorker
	doneAPI    chan bool
	httpserver net.Listener
	httpmux    *http.ServeMux

	HitsStream HitsStream
	HitsUniq   HitsUniq

	Streams map[string]int `json:"streams"`

	TopQnames      *topmap.TopMap
	TopClients     *topmap.TopMap
	TopTLDs        *topmap.TopMap
	TopNonExistent *topmap.TopMap
	TopServFail    *topmap.TopMap

	sync.RWMutex
}

func (w *RestAPI) initHitsUniq() {
	cfg := w.GetConfig().Loggers.RestAPI
	w.HitsUniq = HitsUniq{
		Clients:        expirable.NewLRU[string, int](cfg.RequestersCacheSize, nil, time.Duration(cfg.RequestersCacheTTL)*time.Second),
		Domains:        expirable.NewLRU[string, int](cfg.DomainsCacheSize, nil, time.Duration(cfg.DomainsCacheTTL)*time.Second),
		NxDomains:      expirable.NewLRU[string, int](cfg.NXDomainsCacheSize, nil, time.Duration(cfg.NXDomainsCacheTTL)*time.Second),
		SfDomains:      expirable.NewLRU[string, int](cfg.ServfailDomainsCacheSize, nil, time.Duration(cfg.ServfailDomainsCacheTTL)*time.Second),
		PublicSuffixes: expirable.NewLRU[string, int](cfg.TLDsCacheSize, nil, time.Duration(cfg.TLDsCacheTTL)*time.Second),
		Suspicious:     expirable.NewLRU[string, *dnsutils.TransformSuspicious](cfg.SuspiciousCacheSize, nil, time.Duration(cfg.SuspiciousCacheTTL)*time.Second),
	}
}

func (w *RestAPI) newSearchBy() SearchBy {
	cfg := w.GetConfig().Loggers.RestAPI
	return SearchBy{
		Clients: expirable.NewLRU[string, *HitsRecord](cfg.RequestersCacheSize, nil, time.Duration(cfg.RequestersCacheTTL)*time.Second),
		Domains: expirable.NewLRU[string, *HitsRecord](cfg.DomainsCacheSize, nil, time.Duration(cfg.DomainsCacheTTL)*time.Second),
	}
}

func NewRestAPI(cfg *config.Config, logger *logger.Logger, name string) *RestAPI {
	bufSize := cfg.Global.Worker.ChannelBufferSize
	w := &RestAPI{GenericWorker: NewGenericWorker(cfg, logger, name, "restapi", bufSize, config.DefaultMonitor)}
	w.HitsStream = HitsStream{
		Streams: make(map[string]SearchBy),
	}
	w.initHitsUniq()
	w.Streams = make(map[string]int)
	w.TopQnames = topmap.NewTopMap(cfg.Loggers.RestAPI.TopN)
	w.TopClients = topmap.NewTopMap(cfg.Loggers.RestAPI.TopN)
	w.TopTLDs = topmap.NewTopMap(cfg.Loggers.RestAPI.TopN)
	w.TopNonExistent = topmap.NewTopMap(cfg.Loggers.RestAPI.TopN)
	w.TopServFail = topmap.NewTopMap(cfg.Loggers.RestAPI.TopN)
	return w
}

func (w *RestAPI) ReadConfig() {
	if !netutils.IsValidTLS(w.GetConfig().Loggers.RestAPI.TLSMinVersion) {
		w.LogFatal(config.PrefixLogWorker + "[" + w.GetName() + "]restapi - invalid tls min version")
	}
}

func (w *RestAPI) BasicAuth(httpWriter http.ResponseWriter, r *http.Request) bool {
	login, password, authOK := r.BasicAuth()
	if !authOK {
		return false
	}

	return (login == w.GetConfig().Loggers.RestAPI.BasicAuthLogin) &&
		(password == w.GetConfig().Loggers.RestAPI.BasicAuthPwd)
}

func (w *RestAPI) DeleteResetHandler(httpWriter http.ResponseWriter, r *http.Request) {
	w.RLock()
	defer w.RUnlock()

	if !w.BasicAuth(httpWriter, r) {
		http.Error(httpWriter, "Not authorized", http.StatusUnauthorized)
		return
	}

	switch r.Method {
	case http.MethodDelete:
		w.HitsUniq.Clients.Purge()
		w.HitsUniq.Domains.Purge()
		w.HitsUniq.NxDomains.Purge()
		w.HitsUniq.SfDomains.Purge()
		w.HitsUniq.PublicSuffixes.Purge()
		w.HitsUniq.Suspicious.Purge()

		w.Streams = make(map[string]int)

		w.TopQnames = topmap.NewTopMap(w.GetConfig().Loggers.RestAPI.TopN)
		w.TopClients = topmap.NewTopMap(w.GetConfig().Loggers.RestAPI.TopN)
		w.TopTLDs = topmap.NewTopMap(w.GetConfig().Loggers.RestAPI.TopN)
		w.TopNonExistent = topmap.NewTopMap(w.GetConfig().Loggers.RestAPI.TopN)
		w.TopServFail = topmap.NewTopMap(w.GetConfig().Loggers.RestAPI.TopN)

		w.HitsStream.Streams = make(map[string]SearchBy)

		httpWriter.Header().Set("Content-Type", "application/text")
		httpWriter.Write([]byte("OK"))
	default:
		http.Error(httpWriter, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func (w *RestAPI) GetTopTLDsHandler(httpWriter http.ResponseWriter, r *http.Request) {
	w.RLock()
	defer w.RUnlock()

	if !w.BasicAuth(httpWriter, r) {
		http.Error(httpWriter, "Not authorized", http.StatusUnauthorized)
		return
	}

	httpWriter.Header().Set("Content-Type", "application/json")

	switch r.Method {
	case http.MethodGet:
		json.NewEncoder(httpWriter).Encode(w.TopTLDs.Get())
	default:
		http.Error(httpWriter, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func (w *RestAPI) GetTopClientsHandler(httpWriter http.ResponseWriter, r *http.Request) {
	w.RLock()
	defer w.RUnlock()

	if !w.BasicAuth(httpWriter, r) {
		http.Error(httpWriter, "Not authorized", http.StatusUnauthorized)
		return
	}

	httpWriter.Header().Set("Content-Type", "application/json")

	switch r.Method {
	case http.MethodGet:
		json.NewEncoder(httpWriter).Encode(w.TopClients.Get())
	default:
		http.Error(httpWriter, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func (w *RestAPI) GetTopDomainsHandler(httpWriter http.ResponseWriter, r *http.Request) {
	w.RLock()
	defer w.RUnlock()

	if !w.BasicAuth(httpWriter, r) {
		http.Error(httpWriter, "Not authorized", http.StatusUnauthorized)
		return
	}

	httpWriter.Header().Set("Content-Type", "application/json")

	switch r.Method {
	case http.MethodGet:
		json.NewEncoder(httpWriter).Encode(w.TopQnames.Get())
	default:
		http.Error(httpWriter, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func (w *RestAPI) GetTopNxDomainsHandler(httpWriter http.ResponseWriter, r *http.Request) {
	w.RLock()
	defer w.RUnlock()

	if !w.BasicAuth(httpWriter, r) {
		http.Error(httpWriter, "Not authorized", http.StatusUnauthorized)
		return
	}

	httpWriter.Header().Set("Content-Type", "application/json")

	switch r.Method {
	case http.MethodGet:
		json.NewEncoder(httpWriter).Encode(w.TopNonExistent.Get())
	default:
		http.Error(httpWriter, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func (w *RestAPI) GetTopSfDomainsHandler(httpWriter http.ResponseWriter, r *http.Request) {
	w.RLock()
	defer w.RUnlock()

	if !w.BasicAuth(httpWriter, r) {
		http.Error(httpWriter, "Not authorized", http.StatusUnauthorized)
		return
	}

	httpWriter.Header().Set("Content-Type", "application/json")

	switch r.Method {
	case http.MethodGet:
		json.NewEncoder(httpWriter).Encode(w.TopServFail.Get())
	default:
		http.Error(httpWriter, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func (w *RestAPI) GetTLDsHandler(httpWriter http.ResponseWriter, r *http.Request) {
	w.RLock()
	defer w.RUnlock()

	if !w.BasicAuth(httpWriter, r) {
		http.Error(httpWriter, "Not authorized", http.StatusUnauthorized)
		return
	}

	httpWriter.Header().Set("Content-Type", "application/json")

	switch r.Method {
	case http.MethodGet:
		dataArray := []KeyHit{}
		for _, tld := range w.HitsUniq.PublicSuffixes.Keys() {
			if hit, ok := w.HitsUniq.PublicSuffixes.Get(tld); ok {
				dataArray = append(dataArray, KeyHit{Key: tld, Hit: hit})
			}
		}

		json.NewEncoder(httpWriter).Encode(dataArray)
	default:
		http.Error(httpWriter, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func (w *RestAPI) GetClientsHandler(httpWriter http.ResponseWriter, r *http.Request) {
	w.RLock()
	defer w.RUnlock()

	if !w.BasicAuth(httpWriter, r) {
		http.Error(httpWriter, "Not authorized", http.StatusUnauthorized)
		return
	}

	httpWriter.Header().Set("Content-Type", "application/json")

	switch r.Method {
	case http.MethodGet:
		dataArray := []KeyHit{}
		for _, address := range w.HitsUniq.Clients.Keys() {
			if hit, ok := w.HitsUniq.Clients.Get(address); ok {
				dataArray = append(dataArray, KeyHit{Key: address, Hit: hit})
			}
		}
		json.NewEncoder(httpWriter).Encode(dataArray)
	default:
		http.Error(httpWriter, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func (w *RestAPI) GetDomainsHandler(httpWriter http.ResponseWriter, r *http.Request) {
	w.RLock()
	defer w.RUnlock()

	if !w.BasicAuth(httpWriter, r) {
		http.Error(httpWriter, "Not authorized", http.StatusUnauthorized)
		return
	}

	httpWriter.Header().Set("Content-Type", "application/json")

	switch r.Method {
	case http.MethodGet:
		dataArray := []KeyHit{}
		for _, domain := range w.HitsUniq.Domains.Keys() {
			if hit, ok := w.HitsUniq.Domains.Get(domain); ok {
				dataArray = append(dataArray, KeyHit{Key: domain, Hit: hit})
			}
		}

		json.NewEncoder(httpWriter).Encode(dataArray)
	default:
		http.Error(httpWriter, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func (w *RestAPI) GetNxDomainsHandler(httpWriter http.ResponseWriter, r *http.Request) {
	w.RLock()
	defer w.RUnlock()

	if !w.BasicAuth(httpWriter, r) {
		http.Error(httpWriter, "Not authorized", http.StatusUnauthorized)
		return
	}

	httpWriter.Header().Set("Content-Type", "application/json")

	switch r.Method {
	case http.MethodGet:
		dataArray := []KeyHit{}
		for _, domain := range w.HitsUniq.NxDomains.Keys() {
			if hit, ok := w.HitsUniq.NxDomains.Get(domain); ok {
				dataArray = append(dataArray, KeyHit{Key: domain, Hit: hit})
			}
		}

		json.NewEncoder(httpWriter).Encode(dataArray)

	default:
		http.Error(httpWriter, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func (w *RestAPI) GetSfDomainsHandler(httpWriter http.ResponseWriter, r *http.Request) {
	w.RLock()
	defer w.RUnlock()

	if !w.BasicAuth(httpWriter, r) {
		http.Error(httpWriter, "Not authorized", http.StatusUnauthorized)
		return
	}

	httpWriter.Header().Set("Content-Type", "application/json")

	switch r.Method {
	case http.MethodGet:
		dataArray := []KeyHit{}
		for _, domain := range w.HitsUniq.SfDomains.Keys() {
			if hit, ok := w.HitsUniq.SfDomains.Get(domain); ok {
				dataArray = append(dataArray, KeyHit{Key: domain, Hit: hit})
			}
		}

		json.NewEncoder(httpWriter).Encode(dataArray)
	default:
		http.Error(httpWriter, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func (w *RestAPI) GetSuspiciousHandler(httpWriter http.ResponseWriter, r *http.Request) {
	w.RLock()
	defer w.RUnlock()

	if !w.BasicAuth(httpWriter, r) {
		http.Error(httpWriter, "Not authorized", http.StatusUnauthorized)
		return
	}

	httpWriter.Header().Set("Content-Type", "application/json")

	switch r.Method {
	case http.MethodGet:
		dataArray := []*dnsutils.TransformSuspicious{}
		for _, domain := range w.HitsUniq.Suspicious.Keys() {
			if suspicious, ok := w.HitsUniq.Suspicious.Get(domain); ok {
				suspicious.Domain = domain
				dataArray = append(dataArray, suspicious)
			}
		}

		json.NewEncoder(httpWriter).Encode(dataArray)
	default:
		http.Error(httpWriter, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func (w *RestAPI) GetSearchHandler(httpWriter http.ResponseWriter, r *http.Request) {
	w.RLock()
	defer w.RUnlock()

	if !w.BasicAuth(httpWriter, r) {
		http.Error(httpWriter, "Not authorized", http.StatusUnauthorized)
		return
	}

	switch r.Method {
	case http.MethodGet:

		filter := r.URL.Query()["filter"]
		if len(filter) == 0 {
			http.Error(httpWriter, "Arguments are missing", http.StatusBadRequest)
			return
		}

		dataArray := []KeyHit{}

		// search by IP
		for _, search := range w.HitsStream.Streams {
			userHits, clientExists := search.Clients.Get(filter[0])
			if clientExists {
				for domain, hit := range userHits.Hits {
					dataArray = append(dataArray, KeyHit{Key: domain, Hit: hit})
				}
			}
		}

		// search by domain
		if len(dataArray) == 0 {
			for _, search := range w.HitsStream.Streams {
				domainHits, domainExists := search.Domains.Get(filter[0])
				if domainExists {
					for addr, hit := range domainHits.Hits {
						dataArray = append(dataArray, KeyHit{Key: addr, Hit: hit})
					}
				}
			}
		}

		httpWriter.Header().Set("Content-Type", "application/json")
		json.NewEncoder(httpWriter).Encode(dataArray)

	default:
		http.Error(httpWriter, "{\"error\": \"Method not allowed\"}", http.StatusMethodNotAllowed)
	}
}

func (w *RestAPI) GetStreamsHandler(httpWriter http.ResponseWriter, r *http.Request) {
	w.RLock()
	defer w.RUnlock()

	if !w.BasicAuth(httpWriter, r) {
		http.Error(httpWriter, "Not authorized", http.StatusUnauthorized)
		return
	}

	httpWriter.Header().Set("Content-Type", "application/json")

	switch r.Method {
	case http.MethodGet:
		dataArray := []KeyHit{}
		for stream, hit := range w.Streams {
			dataArray = append(dataArray, KeyHit{Key: stream, Hit: hit})
		}

		json.NewEncoder(httpWriter).Encode(dataArray)
	default:
		http.Error(httpWriter, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func (w *RestAPI) RecordDNSMessage(dm *dnsutils.DNSMessage) {
	w.Lock()
	defer w.Unlock()

	if _, exists := w.Streams[dm.DNSTap.Identity]; !exists {
		w.Streams[dm.DNSTap.Identity] = 1
	} else {
		w.Streams[dm.DNSTap.Identity] += 1
	}

	// record suspicious domains only if enabled
	if dm.Suspicious != nil {
		if dm.Suspicious.Score > 0.0 {
			w.HitsUniq.Suspicious.Add(dm.DNS.Qname, dm.Suspicious)
		}
	}

	// uniq record for tld
	// record public suffix only if enabled
	if dm.PublicSuffix != nil {
		if dm.PublicSuffix.QnamePublicSuffix != "-" {
			count, _ := w.HitsUniq.PublicSuffixes.Get(dm.PublicSuffix.QnamePublicSuffix)
			count++
			w.HitsUniq.PublicSuffixes.Add(dm.PublicSuffix.QnamePublicSuffix, count)
			w.TopTLDs.Record(dm.PublicSuffix.QnamePublicSuffix, count)
		}
	}

	// uniq record for domains
	domainCount, _ := w.HitsUniq.Domains.Get(dm.DNS.Qname)
	domainCount++
	w.HitsUniq.Domains.Add(dm.DNS.Qname, domainCount)
	w.TopQnames.Record(dm.DNS.Qname, domainCount)

	if dm.DNS.Rcode == dnsutils.DNSRcodeNXDomain {
		nxCount, _ := w.HitsUniq.NxDomains.Get(dm.DNS.Qname)
		nxCount++
		w.HitsUniq.NxDomains.Add(dm.DNS.Qname, nxCount)
		w.TopNonExistent.Record(dm.DNS.Qname, nxCount)
	}

	if dm.DNS.Rcode == dnsutils.DNSRcodeServFail {
		sfCount, _ := w.HitsUniq.SfDomains.Get(dm.DNS.Qname)
		sfCount++
		w.HitsUniq.SfDomains.Add(dm.DNS.Qname, sfCount)
		w.TopServFail.Record(dm.DNS.Qname, sfCount)
	}

	// uniq record for queries
	queryIP := dm.NetworkInfo.GetQueryIP()
	clientCount, _ := w.HitsUniq.Clients.Get(queryIP)
	clientCount++
	w.HitsUniq.Clients.Add(queryIP, clientCount)
	w.TopClients.Record(queryIP, clientCount)

	// record dns message per client source ip and domain
	if _, exists := w.HitsStream.Streams[dm.DNSTap.Identity]; !exists {
		w.HitsStream.Streams[dm.DNSTap.Identity] = w.newSearchBy()
	}

	// continue with the query IP
	clientRecord, ok := w.HitsStream.Streams[dm.DNSTap.Identity].Clients.Get(queryIP)
	if !ok {
		clientRecord = &HitsRecord{Hits: make(map[string]int), TotalHits: 1}
		w.HitsStream.Streams[dm.DNSTap.Identity].Clients.Add(queryIP, clientRecord)
	} else {
		clientRecord.TotalHits++
	}
	clientRecord.Hits[dm.DNS.Qname]++

	// continue with Qname
	domainRecord, ok := w.HitsStream.Streams[dm.DNSTap.Identity].Domains.Get(dm.DNS.Qname)
	if !ok {
		domainRecord = &HitsRecord{Hits: make(map[string]int), TotalHits: 1}
		w.HitsStream.Streams[dm.DNSTap.Identity].Domains.Add(dm.DNS.Qname, domainRecord)
	} else {
		domainRecord.TotalHits++
	}
	domainRecord.Hits[queryIP]++
}

func (w *RestAPI) ListenAndServe() {
	w.LogInfo("starting server...")

	mux := http.NewServeMux()
	mux.HandleFunc("/tlds", w.GetTLDsHandler)
	mux.HandleFunc("/tlds/top", w.GetTopTLDsHandler)
	mux.HandleFunc("/streams", w.GetStreamsHandler)
	mux.HandleFunc("/clients", w.GetClientsHandler)
	mux.HandleFunc("/clients/top", w.GetTopClientsHandler)
	mux.HandleFunc("/domains", w.GetDomainsHandler)
	mux.HandleFunc("/domains/servfail", w.GetSfDomainsHandler)
	mux.HandleFunc("/domains/top", w.GetTopDomainsHandler)
	mux.HandleFunc("/domains/nonexistent", w.GetNxDomainsHandler)
	mux.HandleFunc("/domains/nonexistent/top", w.GetTopNxDomainsHandler)
	mux.HandleFunc("/domains/servfail/top", w.GetTopSfDomainsHandler)
	mux.HandleFunc("/domains/suspicious", w.GetSuspiciousHandler)
	mux.HandleFunc("/search", w.GetSearchHandler)
	mux.HandleFunc("/reset", w.DeleteResetHandler)

	var err error
	var listener net.Listener
	addrlisten := w.GetConfig().Loggers.RestAPI.ListenIP + ":" + strconv.Itoa(w.GetConfig().Loggers.RestAPI.ListenPort)

	// listening with tls enabled ?
	if w.GetConfig().Loggers.RestAPI.TLSSupport {
		w.LogInfo("tls support enabled")
		var cer tls.Certificate
		cer, err = tls.LoadX509KeyPair(w.GetConfig().Loggers.RestAPI.CertFile, w.GetConfig().Loggers.RestAPI.KeyFile)
		if err != nil {
			w.LogFatal("loading certificate failed:", err)
		}

		// prepare tls configuration
		tlsConfig := &tls.Config{
			Certificates: []tls.Certificate{cer},
			MinVersion:   tls.VersionTLS12,
		}

		// update tls min version according to the user config
		tlsConfig.MinVersion = netutils.TLSVersion[w.GetConfig().Loggers.RestAPI.TLSMinVersion]

		listener, err = tls.Listen(netutils.SocketTCP, addrlisten, tlsConfig)

	} else {
		// basic listening
		listener, err = net.Listen(netutils.SocketTCP, addrlisten)
	}

	// something wrong ?
	if err != nil {
		w.LogFatal("listening failed:", err)
	}

	w.httpserver = listener
	w.httpmux = mux
	w.LogInfo("is listening on %s", listener.Addr())

	http.Serve(w.httpserver, w.httpmux)

	w.LogInfo("http server terminated")
	w.doneAPI <- true
}

func (w *RestAPI) StartCollect() {
	w.LogInfo("starting data collection")
	defer w.CollectDone()

	// prepare next channels
	defaultRoutes, defaultNames := GetRoutes(w.GetDefaultRoutes())
	droppedRoutes, droppedNames := GetRoutes(w.GetDroppedRoutes())

	// prepare transforms
	subprocessors := transformers.NewTransforms(&w.GetConfig().OutgoingTransformers, w.GetLogger(), w.GetName(), w.GetOutputChannelAsList(), 0)

	// start http server
	go w.ListenAndServe()

	// goroutine to process transformed dns messages
	go w.StartLogging()

	// loop to process incoming messages
	for {
		select {
		case <-w.OnStop():
			w.StopLogger()
			subprocessors.Reset()

			w.httpserver.Close()
			<-w.doneAPI

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

func (w *RestAPI) StartLogging() {
	w.LogInfo("logging has started")
	defer w.LoggingDone()

	for {
		select {
		case <-w.OnLoggerStopped():
			return

		case batch, opened := <-w.GetOutputChannel():
			if !opened {
				w.LogInfo("output channel closed!")
				return
			}
			for _, dm := range batch.Messages {
				// record the dnstap message
				w.RecordDNSMessage(dm)
			}
			batch.Release()
		}
	}
}

func init() {
	RegisterLogger("restapi", func(c *config.Config) bool { return c.Loggers.RestAPI.Enable }, func(c *config.Config, l *logger.Logger, s string) Worker {
		return NewRestAPI(c, l, s)
	})
}
