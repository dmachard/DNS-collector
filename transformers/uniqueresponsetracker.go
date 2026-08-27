package transformers

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/dmachard/go-dnscollector/v3/dnsutils"
	"github.com/dmachard/go-dnscollector/v3/pkg/config"
	"github.com/dmachard/go-dnscollector/v3/pkg/cuckoo"
	"github.com/dmachard/go-logger"
	"github.com/hashicorp/golang-lru/v2/expirable"
)

type UniqueResponseTracker struct {
	ttl             time.Duration
	storageEngine   string
	lruCache        *expirable.LRU[string, struct{}]
	cuckooFilter    *cuckoo.SlidingCuckooFilter
	whitelist       map[string]*regexp.Regexp
	persistencePath string
	logInfo         func(msg string, v ...interface{})
	logError        func(msg string, v ...interface{})
}

func NewUniqueResponseTracker(ttl time.Duration, maxSize int, engine string, cuckooFPBits int, whitelist map[string]*regexp.Regexp, persistencePath string, logInfo, logError func(msg string, v ...interface{})) (*UniqueResponseTracker, error) {
	if ttl <= 0 {
		return nil, fmt.Errorf("invalid TTL value: %v", ttl)
	}

	if engine == "" {
		engine = "lru"
	}

	tracker := &UniqueResponseTracker{
		ttl:             ttl,
		storageEngine:   engine,
		whitelist:       whitelist,
		persistencePath: persistencePath,
		logInfo:         logInfo,
		logError:        logError,
	}

	if engine == "lru" {
		tracker.lruCache = expirable.NewLRU[string, struct{}](maxSize, nil, ttl)
	} else {
		tracker.cuckooFilter = cuckoo.NewSlidingCuckooFilter(maxSize, ttl, cuckooFPBits)
	}

	if persistencePath != "" && engine == "lru" {
		if err := tracker.loadCacheFromDisk(); err != nil {
			return nil, fmt.Errorf("failed to load cache state: %w", err)
		}
	}

	return tracker, nil
}

func (urt *UniqueResponseTracker) isWhitelisted(domain string) bool {
	for _, d := range urt.whitelist {
		if d.MatchString(domain) {
			return true
		}
	}
	return false
}

// IsNewResponse checks if the tuple (Qname, Rtype, Rdata) is observed for the first time.
func (urt *UniqueResponseTracker) IsNewResponse(qname string, rtype string, rdata string) bool {
	lowerDomain := strings.ToLower(qname)
	if urt.isWhitelisted(lowerDomain) {
		return false
	}

	if urt.storageEngine == "cuckoo" && urt.cuckooFilter != nil {
		h := cuckoo.HashTuple(lowerDomain, rtype, rdata)
		return urt.cuckooFilter.TestAndAdd(h)
	}

	key := lowerDomain + "/" + rtype + "/" + rdata
	if _, exists := urt.lruCache.Get(key); exists {
		return false
	}

	urt.lruCache.Add(key, struct{}{})
	return true
}

func (urt *UniqueResponseTracker) SaveCacheToDisk() error {
	if urt.lruCache == nil {
		return nil
	}
	keys := urt.lruCache.Keys()
	data, err := json.Marshal(keys)
	if err != nil {
		return err
	}

	return os.WriteFile(urt.persistencePath, data, 0644)
}

func (urt *UniqueResponseTracker) loadCacheFromDisk() error {
	if urt.persistencePath == "" {
		return errors.New("persistence filepath not set")
	}

	data, err := os.ReadFile(urt.persistencePath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}

	var keys []string
	if err := json.Unmarshal(data, &keys); err != nil {
		return err
	}

	if urt.lruCache != nil {
		for _, key := range keys {
			urt.lruCache.Add(key, struct{}{})
		}
	}

	return nil
}

// Close cleans up tracker resources (e.g. background ticker).
func (urt *UniqueResponseTracker) Close() {
	if urt.cuckooFilter != nil {
		urt.cuckooFilter.Close()
	}
}

type UniqueResponseTrackerTransform struct {
	GenericTransformer
	config           *config.TransformUniqueResponseTracker
	responseTracker  *UniqueResponseTracker
	listDomainsRegex map[string]*regexp.Regexp
}

func NewUniqueResponseTrackerTransform(cfg *config.TransformUniqueResponseTracker, logger *logger.Logger, name string, instance int, nextWorkers []chan *dnsutils.DNSMessageBatch) *UniqueResponseTrackerTransform {
	t := &UniqueResponseTrackerTransform{config: cfg, GenericTransformer: NewTransformer(logger, "unique-response-tracker", name, instance, nextWorkers)}
	t.listDomainsRegex = make(map[string]*regexp.Regexp)
	return t
}

func (t *UniqueResponseTrackerTransform) ReloadConfig(cfg *config.TransformUniqueResponseTracker) {
	t.config = cfg
	ttl := time.Duration(cfg.TTL) * time.Second
	t.responseTracker.ttl = ttl
	t.LogInfo("unique-response-tracker configuration reloaded")
}

func (t *UniqueResponseTrackerTransform) GetTransforms() ([]Subtransform, error) {
	subtransforms := []Subtransform{}
	if t.config.Enable {
		if err := t.LoadWhiteDomainsList(); err != nil {
			return nil, err
		}

		ttl := time.Duration(t.config.TTL) * time.Second
		maxSize := t.config.CacheSize
		engine := t.config.StorageEngine
		fpBits := t.config.CuckooFingerprintBits
		tracker, err := NewUniqueResponseTracker(ttl, maxSize, engine, fpBits, t.listDomainsRegex, t.config.PersistenceFile, t.LogInfo, t.LogError)
		if err != nil {
			return nil, err
		}
		t.responseTracker = tracker

		subtransforms = append(subtransforms, Subtransform{name: "unique-response-tracker:detect", processFunc: t.trackUniqueResponse})
	}
	return subtransforms, nil
}

func (t *UniqueResponseTrackerTransform) LoadWhiteDomainsList() error {
	for key := range t.listDomainsRegex {
		delete(t.listDomainsRegex, key)
	}

	if len(t.config.WhiteDomainsFile) > 0 {
		file, err := os.Open(t.config.WhiteDomainsFile)
		if err != nil {
			return fmt.Errorf("unable to open regex list file: %w", err)
		}
		defer file.Close()

		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			domain := strings.ToLower(scanner.Text())
			if len(domain) > 0 {
				t.listDomainsRegex[domain] = regexp.MustCompile(domain)
			}
		}
		t.LogInfo("loaded with %d domains in the whitelist", len(t.listDomainsRegex))
	}
	return nil
}

func (t *UniqueResponseTrackerTransform) trackUniqueResponse(dm *dnsutils.DNSMessage) (int, error) {
	if len(dm.DNS.DNSRRs.Answers) == 0 {
		return ReturnDrop, nil
	}

	if t.responseTracker.storageEngine == "lru" && t.responseTracker.lruCache != nil {
		if t.responseTracker.lruCache.Len() == t.config.CacheSize {
			return ReturnError, fmt.Errorf("LRU cache is full. Consider increasing cache-size to avoid frequent evictions")
		}
	}

	hasNewResponse := false
	for _, ans := range dm.DNS.DNSRRs.Answers {
		if t.responseTracker.IsNewResponse(dm.DNS.Qname, ans.Rdatatype, ans.Rdata) {
			hasNewResponse = true
		}
	}

	if hasNewResponse {
		return ReturnKeep, nil
	}
	return ReturnDrop, nil
}

func (t *UniqueResponseTrackerTransform) Reset() {
	if t.responseTracker != nil {
		t.responseTracker.Close()
		if len(t.responseTracker.persistencePath) != 0 {
			if err := t.responseTracker.SaveCacheToDisk(); err != nil {
				t.LogError("failed to save cache state: %v", err)
			}
			t.LogInfo("cache content saved on disk with success")
		}
	}
}
