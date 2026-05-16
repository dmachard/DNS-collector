package workers

import (
	"testing"

	"github.com/dmachard/go-dnscollector/v2/pkgconfig"
	"github.com/dmachard/go-logger"
)

func TestGenericWorker(t *testing.T) {
	NewGenericWorker(pkgconfig.GetDefaultConfig(), logger.New(false), "testonly", "", pkgconfig.DefaultBufferSize, pkgconfig.WorkerMonitorDisabled)
}
