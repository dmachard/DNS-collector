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

### Running python tests

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
