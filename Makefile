BINARY_NAME := dnscollector

GO_VERSION := $(shell go env GOVERSION | sed -n 's/go\([0-9]\+\.[0-9]\+\).*/\1/p')

GO_LOGGER := 1.2.0
GO_POWERDNS_PROTOBUF := 1.6.0
GO_DNSTAP_PROTOBUF := 1.4.0
GO_FRAMESTREAM := 1.3.2
GO_CLIENTSYSLOG := 1.0.2
GO_TOPMAP := 1.0.3
GO_NETUTILS := 1.8.0

BUILD_TIME := $(shell LANG=en_US date +"%F_%T_%z")
COMMIT := $(shell git rev-parse --short HEAD)
BRANCH := $(shell git rev-parse --abbrev-ref HEAD)
VERSION ?= $(shell git describe --tags --abbrev=0 ${COMMIT} 2>/dev/null | cut -c2-)
VERSION := $(or $(VERSION),$(COMMIT))

LD_FLAGS ?=
LD_FLAGS += -s -w # disable debug informations
LD_FLAGS += -X github.com/prometheus/common/version.Version=$(VERSION)
LD_FLAGS += -X github.com/prometheus/common/version.Revision=$(COMMIT)
LD_FLAGS += -X github.com/prometheus/common/version.Branch=$(BRANCH)
LD_FLAGS += -X github.com/prometheus/common/version.BuildDate=$(BUILD_TIME)

ifndef $(GOPATH)
	GOPATH=$(shell go env GOPATH)
	export GOPATH
endif

.PHONY: all check-go dep lint build clean goversion stats

# This target depends on dep and build.
all: check-go dep build

check-go:
	@command -v go > /dev/null 2>&1 || { echo >&2 "Go is not installed. Please install it before proceeding."; exit 1; }

# Displays the Go version.
goversion: check-go
	@echo "Go version: $(GO_VERSION)"

# Installs project dependencies.
dep: goversion
	@go get github.com/dmachard/go-logger@v$(GO_LOGGER)
	@go get github.com/dmachard/go-powerdns-protobuf@v$(GO_POWERDNS_PROTOBUF)
	@go get github.com/dmachard/go-dnstap-protobuf@v$(GO_DNSTAP_PROTOBUF)
	@go get github.com/dmachard/go-framestream@v$(GO_FRAMESTREAM)
	@go get github.com/dmachard/go-clientsyslog@v$(GO_CLIENTSYSLOG)
	@go get github.com/dmachard/go-topmap@v$(GO_TOPMAP)
	@go get github.com/dmachard/go-netutils@v$(GO_NETUTILS)
	@go mod edit -go=$(GO_VERSION)
	@go mod tidy

# Builds the project using go build.
build: check-go
	CGO_ENABLED=0 go build -v -ldflags="$(LD_FLAGS)" -o ${BINARY_NAME} dnscollector.go

# Builds and runs the project.
run: build
	./${BINARY_NAME}

# Builds and runs the project with the -v flag.
version: build
	./${BINARY_NAME} -v

# Runs linters.
lint:
	$(GOPATH)/bin/golangci-lint run --config=.golangci.yml ./...

# Runs various tests for different packages.
tests: check-go
	@echo "Running tests..."
	@go test -v -race -coverprofile=coverage.out -json ./... | tee test_output.json | \
	jq -r 'select(.Output != null) | .Output' | sed '/^\s*$$/d' | sed 's/^[ \t]*//'
	go tool cover -func=coverage.out

	@TEST_COUNT=$$(jq -r 'select(.Action == "pass" or .Action == "fail") | .Test' test_output.json | sort -u | wc -l); \
	COVERAGE=$$(go tool cover -func=coverage.out | grep total: | awk '{print $$3}'); \
	echo "Total executed tests: $$TEST_COUNT"; \
	echo "Code coverage: $$COVERAGE"

	@rm -f test_output.json coverage.out

stats:
	@echo "Calculating Go code statistics (excluding tests)..."
	@TOTAL_LINES=$$(find . -name '*.go' ! -name '*_test.go' -print0 | xargs -0 cat | wc -l); \
	COMMENT_LINES=$$(find . -name '*.go' ! -name '*_test.go' -print0 | xargs -0 grep -E '^\s*//' | wc -l); \
	EMPTY_LINES=$$(find . -name '*.go' ! -name '*_test.go' -print0 | xargs -0 grep -E '^\s*$$' | wc -l); \
	CODE_LINES=$$((TOTAL_LINES - COMMENT_LINES - EMPTY_LINES)); \
	echo "Total lines        : $$TOTAL_LINES"; \
	echo "Comment lines      : $$COMMENT_LINES"; \
	echo "Empty lines        : $$EMPTY_LINES"; \
	echo "Effective code lines: $$CODE_LINES"

# Cleans the project using go clean.
clean: check-go
	@go clean
	@rm -f $(BINARY_NAME)
