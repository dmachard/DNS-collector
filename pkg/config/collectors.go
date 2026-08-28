package config

import (
	"reflect"

	"github.com/creasty/defaults"
)

type CollectorDNSMessageMatching struct {
	Include map[string]interface{} `yaml:"include"`
	Exclude map[string]interface{} `yaml:"exclude"`
}

type CollectorDNSMessage struct {
	Enable   bool                        `yaml:"enable" default:"false"`
	Matching CollectorDNSMessageMatching `yaml:"matching"`
}

type CollectorTail struct {
	Enable       bool   `yaml:"enable" default:"false"`
	TimeLayout   string `yaml:"time-layout" default:""`
	PatternQuery string `yaml:"pattern-query" default:""`
	PatternReply string `yaml:"pattern-reply" default:""`
	FilePath     string `yaml:"file-path" default:""`
}

type CollectorDnstap struct {
	Enable           bool   `yaml:"enable" default:"false"`
	ListenIP         string `yaml:"listen-ip" default:"0.0.0.0"`
	ListenPort       int    `yaml:"listen-port" default:"6000"`
	SockPath         string `yaml:"sock-path" default:""`
	TLSSupport       bool   `yaml:"tls-support" default:"false"`
	TLSMinVersion    string `yaml:"tls-min-version" default:"1.2"`
	CertFile         string `yaml:"cert-file" default:""`
	KeyFile          string `yaml:"key-file" default:""`
	RcvBufSize       int    `yaml:"sock-rcvbuf" default:"0"`
	ReadBufferSize   int    `yaml:"sock-read-buffer-size" default:"65536"`
	ResetConn        bool   `yaml:"reset-conn" default:"true"`
	NumWorkers       int    `yaml:"num-workers" default:"0"`
	DisableDNSParser bool   `yaml:"disable-dnsparser" default:"false"`
	ExtendedSupport  bool   `yaml:"extended-support" default:"false"`
	FastDecoder      bool   `yaml:"fast-decoder" default:"true"`
	Compression      string `yaml:"compression" default:"none"`
}

type CollectorDnstapProxifier struct {
	Enable        bool   `yaml:"enable" default:"false"`
	ListenIP      string `yaml:"listen-ip" default:"0.0.0.0"`
	ListenPort    int    `yaml:"listen-port" default:"6000"`
	SockPath      string `yaml:"sock-path" default:""`
	TLSSupport    bool   `yaml:"tls-support" default:"false"`
	TLSMinVersion string `yaml:"tls-min-version" default:"1.2"`
	CertFile      string `yaml:"cert-file" default:""`
	KeyFile       string `yaml:"key-file" default:""`
}

type CollectorAfpacketLiveCapture struct {
	Enable          bool   `yaml:"enable" default:"false"`
	Port            int    `yaml:"port" default:"53"`
	Device          string `yaml:"device" default:""`
	FragmentSupport bool   `yaml:"enable-defrag-ip" default:"true"`
	GreSupport      bool   `yaml:"enable-gre" default:"false"`
	RawIPSupport    bool   `yaml:"enable-rawip" default:"false"`
}

type CollectorXdpLiveCapture struct {
	Enable bool   `yaml:"enable" default:"false"`
	Port   int    `yaml:"port" default:"53"`
	Device string `yaml:"device" default:""`
}

type CollectorPowerDNS struct {
	Enable        bool   `yaml:"enable" default:"false"`
	ListenIP      string `yaml:"listen-ip" default:"0.0.0.0"`
	ListenPort    int    `yaml:"listen-port" default:"6001"`
	TLSSupport    bool   `yaml:"tls-support" default:"false"`
	TLSMinVersion string `yaml:"tls-min-version" default:"1.2"`
	CertFile      string `yaml:"cert-file" default:""`
	KeyFile       string `yaml:"key-file" default:""`
	AddDNSPayload bool   `yaml:"add-dns-payload" default:"false"`
	RcvBufSize    int    `yaml:"sock-rcvbuf" default:"0"`
	ResetConn     bool   `yaml:"reset-conn" default:"true"`
}

type CollectorFileIngestor struct {
	Enable      bool   `yaml:"enable" default:"false"`
	WatchDir    string `yaml:"watch-dir" default:""`
	WatchMode   string `yaml:"watch-mode" default:"pcap"`
	PcapDNSPort int    `yaml:"pcap-dns-port" default:"53"`
	DeleteAfter bool   `yaml:"delete-after" default:"false"`
}

type CollectorTzsp struct {
	Enable     bool   `yaml:"enable" default:"false"`
	ListenIP   string `yaml:"listen-ip" default:"0.0.0.0"`
	ListenPort int    `yaml:"listen-port" default:"10000"`
}

type ConfigCollectors struct {
	DNSMessage          CollectorDNSMessage          `yaml:"dnsmessage"`
	Tail                CollectorTail                `yaml:"tail"`
	Dnstap              CollectorDnstap              `yaml:"dnstap"`
	DnstapProxifier     CollectorDnstapProxifier     `yaml:"dnstap-relay"`
	AfpacketLiveCapture CollectorAfpacketLiveCapture `yaml:"afpacket-sniffer"`
	XdpLiveCapture      CollectorXdpLiveCapture      `yaml:"xdp-sniffer"`
	PowerDNS            CollectorPowerDNS            `yaml:"powerdns"`
	FileIngestor        CollectorFileIngestor        `yaml:"file-ingestor"`
	Tzsp                CollectorTzsp                `yaml:"tzsp"`
}

func (c *ConfigCollectors) SetDefault() {
	defaults.Set(c)
}

func (c *ConfigCollectors) IsValid(userCfg map[string]interface{}) error {
	return CheckConfigWithTags(reflect.ValueOf(*c), userCfg)
}

func (c *ConfigCollectors) GetNames() (ret []string) {
	cl := reflect.TypeOf(*c)

	for i := 0; i < cl.NumField(); i++ {
		field := cl.Field(i)
		tag := field.Tag.Get("yaml")
		ret = append(ret, tag)
	}
	return ret
}

func (c *ConfigCollectors) IsExists(name string) bool {
	tags := c.GetNames()
	for i := range tags {
		if name == tags[i] {
			return true
		}
	}
	return false
}
