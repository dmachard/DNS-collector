package config

import (
	"reflect"

	"github.com/creasty/defaults"
)

var (
	DefaultTransformersOrder = []string{
		"extract",
		"normalize",
		"filtering",
		"geoip",
		"bgp",
		"atags",
		"suspicious",
		"user-privacy",
		"machine-learning",
		"rest",
		"relabeling",
		"latency",
		"rewrite",
		"new-domain-tracker",
		"unique-response-tracker",
		"reducer",
		"reordering",
	}
)

type RelabelingConfig struct {
	Regex       string `yaml:"regex"`
	Replacement string `yaml:"replacement"`
}

type TransformUserPrivacy struct {
	Enable            bool   `yaml:"enable" default:"false"`
	AnonymizeIP       bool   `yaml:"anonymize-ip" default:"false"`
	AnonymizeIPV4Bits string `yaml:"anonymize-v4bits" default:"0.0.0.0/16"`
	AnonymizeIPV6Bits string `yaml:"anonymize-v6bits" default:"::/64"`
	MinimizeQname     bool   `yaml:"minimize-qname" default:"false"`
	HashQueryIP       bool   `yaml:"hash-query-ip" default:"false"`
	HashReplyIP       bool   `yaml:"hash-reply-ip" default:"false"`
	HashIPAlgo        string `yaml:"hash-ip-algo" default:"sha1"`
}

type TransformNormalize struct {
	Enable              bool `yaml:"enable" default:"false"`
	QnameLowerCase      bool `yaml:"qname-lowercase" default:"false"`
	RRLowerCase         bool `yaml:"rr-lowercase" default:"false"`
	QuietText           bool `yaml:"quiet-text" default:"false"`
	AddTld              bool `yaml:"add-tld" default:"false"`
	AddTldPlusOne       bool `yaml:"add-tld-plus-one" default:"false"`
	ReplaceNonPrintable bool `yaml:"qname-replace-nonprintable" default:"false"`
}

type TransformLatency struct {
	Enable            bool `yaml:"enable" default:"false"`
	MeasureLatency    bool `yaml:"measure-latency" default:"false"`
	UnansweredQueries bool `yaml:"unanswered-queries" default:"false"`
	QueriesTimeout    int  `yaml:"queries-timeout" default:"2"`
}

type TransformReducer struct {
	Enable                    bool     `yaml:"enable" default:"false"`
	RepetitiveTrafficDetector bool     `yaml:"repetitive-traffic-detector" default:"false"`
	QnamePlusOne              bool     `yaml:"qname-plus-one" default:"false"`
	WatchInterval             int      `yaml:"watch-interval" default:"2"`
	UniqueFields              []string `yaml:"unique-fields" default:"[\"dnstap.identity\", \"dnstap.operation\", \"network.query-ip\", \"network.response-ip\",  \"dns.qname\", \"dns.qtype\"]"`
}

type TransformFiltering struct {
	Enable          bool     `yaml:"enable" default:"false"`
	DropFqdnFile    string   `yaml:"drop-fqdn-file" default:""`
	DropDomainFile  string   `yaml:"drop-domain-file" default:""`
	KeepFqdnFile    string   `yaml:"keep-fqdn-file" default:""`
	KeepDomainFile  string   `yaml:"keep-domain-file" default:""`
	DropQueryIPFile string   `yaml:"drop-queryip-file" default:""`
	KeepQueryIPFile string   `yaml:"keep-queryip-file" default:""`
	KeepRdataFile   string   `yaml:"keep-rdata-file" default:""`
	DropRcodes      []string `yaml:"drop-rcodes,flow" default:"[]"`
	LogQueries      bool     `yaml:"log-queries" default:"true"`
	LogReplies      bool     `yaml:"log-replies" default:"true"`
	Downsample      int      `yaml:"downsample" default:"0"`
}

type TransformGeoIP struct {
	Enable           bool   `yaml:"enable" default:"false"`
	LookupECS        bool   `yaml:"lookup-ecs" default:"false"`
	DBCountryFile    string `yaml:"mmdb-country-file" default:""`
	DBCityFile       string `yaml:"mmdb-city-file" default:""`
	DBASNFile        string `yaml:"mmdb-asn-file" default:""`
	DBCoordinateFile string `yaml:"mmdb-coordinate-file" default:""`
}

type TransformBGP struct {
	Enable                 bool   `yaml:"enable" default:"false"`
	LookupECS              bool   `yaml:"lookup-ecs" default:"false"`
	MrtFile                string `yaml:"mrt-file" default:""`
	MrtCheckUpdateInterval int    `yaml:"mrt-checkupdate-interval" default:"300"`
	OriginASN              bool   `yaml:"origin-asn" default:"true"`
	ASPath                 bool   `yaml:"as-path" default:"true"`
	Prefix                 bool   `yaml:"prefix" default:"true"`
}

type TransformSuspicious struct {
	Enable             bool     `yaml:"enable" default:"false"`
	ThresholdQnameLen  int      `yaml:"threshold-qname-len" default:"100"`
	ThresholdPacketLen int      `yaml:"threshold-packet-len" default:"1000"`
	ThresholdSlow      float64  `yaml:"threshold-slow" default:"1.0"`
	CommonQtypes       []string `yaml:"common-qtypes,flow" default:"[\"A\", \"AAAA\", \"TXT\", \"CNAME\", \"PTR\", \"NAPTR\", \"DNSKEY\", \"SRV\", \"SOA\", \"NS\", \"MX\", \"DS\", \"HTTPS\"]"`
	UnallowedChars     []string `yaml:"unallowed-chars,flow" default:"[\"\\\"\", \"==\", \"/\", \":\"]"`
	ThresholdMaxLabels int      `yaml:"threshold-max-labels" default:"10"`
	WhitelistDomains   []string `yaml:"whitelist-domains,flow" default:"[\"\\\\.ip6\\\\.arpa\"]"`
}

type TransformExtract struct {
	Enable       bool     `yaml:"enable" default:"false"`
	AddPayload   bool     `yaml:"add-payload" default:"false"`
	Base64Fields []string `yaml:"base64-fields,flow" default:"[]"`
	HexFields    []string `yaml:"hex-fields,flow" default:"[]"`
}

type TransformMachineLearning struct {
	Enable      bool `yaml:"enable" default:"false"`
	AddFeatures bool `yaml:"add-features" default:"false"`
}

type TransformATags struct {
	Enable  bool     `yaml:"enable" default:"false"`
	AddTags []string `yaml:"add-tags,flow" default:"[]"`
}

type TransformRest struct {
	Enable           bool   `yaml:"enable" default:"false"`
	URL              string `yaml:"url" default:"http://127.0.0.1:8088"`
	Timeout          int    `yaml:"timeout" default:"1"`
	BasicAuthEnabled bool   `yaml:"basic-auth-enable" default:"false"`
	BasicAuthLogin   string `yaml:"basic-auth-login" default:""`
	BasicAuthPwd     string `yaml:"basic-auth-pwd" default:""`
}

type TransformRelabeling struct {
	Enable bool               `yaml:"enable" default:"false"`
	Rename []RelabelingConfig `yaml:"rename,flow"`
	Remove []RelabelingConfig `yaml:"remove,flow"`
}

type TransformRewrite struct {
	Enable      bool                   `yaml:"enable" default:"false"`
	Identifiers map[string]interface{} `yaml:"identifiers,flow"`
}

type TransformNewDomainTracker struct {
	Enable           bool   `yaml:"enable" default:"false"`
	TTL              int    `yaml:"ttl" default:"3600"`
	CacheSize        int    `yaml:"cache-size" default:"100000"`
	WhiteDomainsFile string `yaml:"white-domains-file" default:""`
	PersistenceFile  string `yaml:"persistence-file" default:""`
}

type TransformUniqueResponseTracker struct {
	Enable                bool   `yaml:"enable" default:"false"`
	TTL                   int    `yaml:"ttl" default:"86400"`
	CacheSize             int    `yaml:"cache-size" default:"100000"`
	StorageEngine         string `yaml:"storage-engine" default:"lru"`
	CuckooFingerprintBits int    `yaml:"cuckoo-fingerprint-bits" default:"16"`
	WhiteDomainsFile      string `yaml:"white-domains-file" default:""`
	PersistenceFile       string `yaml:"persistence-file" default:""`
}

type TransformReordering struct {
	Enable        bool `yaml:"enable" default:"false"`
	FlushInterval int  `yaml:"flush-interval" default:"30"`
	MaxBufferSize int  `yaml:"max-buffer-size" default:"100"`
}

type TransformFrequencyFiltering struct {
	Enable        bool   `yaml:"enable" default:"false"`
	TrackBy       string `yaml:"track-by" default:"qname"`
	Threshold     int    `yaml:"threshold" default:"1000"`
	WindowSeconds int    `yaml:"window-seconds" default:"60"`
	SampleRate    int    `yaml:"sample-rate" default:"100"`
	TagOnly       bool   `yaml:"tag-only" default:"false"`
	Capacity      int    `yaml:"capacity" default:"100000"`
}

type ConfigTransformers struct {
	Order                 []string                       `yaml:"order" default:"[]"`
	UserPrivacy           TransformUserPrivacy           `yaml:"user-privacy"`
	Normalize             TransformNormalize             `yaml:"normalize"`
	Latency               TransformLatency               `yaml:"latency"`
	Reducer               TransformReducer               `yaml:"reducer"`
	Filtering             TransformFiltering             `yaml:"filtering"`
	GeoIP                 TransformGeoIP                 `yaml:"geoip"`
	BGP                   TransformBGP                   `yaml:"bgp"`
	Suspicious            TransformSuspicious            `yaml:"suspicious"`
	Extract               TransformExtract               `yaml:"extract"`
	MachineLearning       TransformMachineLearning       `yaml:"machine-learning"`
	ATags                 TransformATags                 `yaml:"atags"`
	Rest                  TransformRest                  `yaml:"rest"`
	Relabeling            TransformRelabeling            `yaml:"relabeling"`
	Rewrite               TransformRewrite               `yaml:"rewrite"`
	NewDomainTracker      TransformNewDomainTracker      `yaml:"new-domain-tracker"`
	UniqueResponseTracker TransformUniqueResponseTracker `yaml:"unique-response-tracker"`
	Reordering            TransformReordering            `yaml:"reordering"`
	FrequencyFiltering    TransformFrequencyFiltering    `yaml:"frequency-filtering"`
}

func (c *ConfigTransformers) SetDefault() {
	defaults.Set(c)
}

func (c *ConfigTransformers) IsValid(userCfg map[string]interface{}) error {
	return CheckConfigWithTags(reflect.ValueOf(*c), userCfg)
}

func GetFakeConfigTransformers() *ConfigTransformers {
	config := &ConfigTransformers{}
	config.SetDefault()
	return config
}
