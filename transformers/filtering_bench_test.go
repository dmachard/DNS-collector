package transformers

import (
	"fmt"
	"os"
	"testing"

	"github.com/dmachard/go-dnscollector/v2/dnsutils"
	"github.com/dmachard/go-dnscollector/v2/pkgconfig"
	"github.com/dmachard/go-logger"
)

func BenchmarkFiltering_DropDomainRegex(b *testing.B) {
	// Create a temporary file with 100 regex patterns
	tmpFile, err := os.CreateTemp("", "filtering_regex_*.txt")
	if err != nil {
		b.Fatalf("failed to create temp file: %v", err)
	}
	defer os.Remove(tmpFile.Name())

	for i := 0; i < 100; i++ {
		_, _ = fmt.Fprintf(tmpFile, "domain%d\\.com$\n", i)
	}
	tmpFile.Close()

	config := pkgconfig.GetFakeConfigTransformers()
	config.Filtering.Enable = true
	config.Filtering.DropDomainFile = tmpFile.Name()

	outChans := []chan *dnsutils.DNSMessage{}
	filtering := NewFilteringTransform(config, logger.New(false), "test", 0, outChans)
	_, _ = filtering.GetTransforms()

	dm := dnsutils.GetFakeDNSMessage()
	dm.DNS.Qname = "notmatchingdomain.com"

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = filtering.dropDomainRegexFilter(&dm)
	}
}
