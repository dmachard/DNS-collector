# Development

To compile DNS-collector, we assume you have a working Go setup.
First, make sure your golang version is `1.21` or higher


## Build and run from source

Building from source

- The very fast way, go to the top of the project and run go command

```bash
go run .
```

- Uses the `MakeFile` (prefered way)

```bash
make
```

Execute the binary

```bash
make run
```

- From the `DockerFile`

## Run linters

Install linter

```bash
sudo apt install build-essential
go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@latest
```

Execute linter before to commit

```bash
make lint
```

## Run test units

Execute testunits before to commit

```bash
sudo make tests
```

Execute a test for one specific testcase in a package

```bash
go test -timeout 10s -cover -v ./workers -run Test_SyslogRun
```

Run bench

```bash
cd dnsutils/
go test -run=^$ -bench=.
```

## Update Golang version and package dependencies

Update go version

```bash
go mod edit -go=1.24
```

Update package dependencies

```bash
make dep
```

### Running basic Python tests

```bash
# set python env
python3 -m venv venv
source venv/bin/activate
python3 -m pip install dnstap_pb fstrm dnspython protobuf

# build dnscollector
make build

# run tests
python3 -m unittest tests.config -v
```

### Running Local DNS Integration Tests

You can also run full integration tests locally with actual DNS servers deployed via Docker. A helper script `tests/run_local_dns_tests.sh` (and associated Makefile targets) automates the process of generating certificates, spinning up docker containers, executing query tests, and cleaning up.

Prerequisites: `docker`, `openssl`, `python3`, `go`, `dig` (dnsutils).

#### Quick start:

Run the default test case (`unbound` over `tcp`):
```bash
make test-dns
```

Run all matrix configurations (`unbound`, `coredns`, `dnsdist2`, `knotresolver` in all modes):
```bash
make test-dns-all
```

Clean up temporary files, certificates, virtualenv, and containers:
```bash
make test-dns-clean
```

#### Advanced usage:

You can invoke the script directly to target a specific service, mode, or docker image version:
```bash
# Run coredns over TLS
./tests/run_local_dns_tests.sh -s coredns -m tls

# Run dnsdist2 over DoQ with a specific version
./tests/run_local_dns_tests.sh -s dnsdist2 -m doq -v 21

# Skip rebuilding the binary (if already compiled)
./tests/run_local_dns_tests.sh -s unbound -m tcp --no-build

# Show help options
./tests/run_local_dns_tests.sh --help
```
