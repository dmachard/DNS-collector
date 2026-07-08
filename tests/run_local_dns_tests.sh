#!/usr/bin/env bash

# Exit immediately if a command exits with a non-zero status
set -e

# Base directory
BASE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$BASE_DIR"

# Add common paths for Go, just in case
export PATH="$PATH:/usr/local/go/bin:$HOME/go/bin"

# Defaults
SERVICE=""
MODE=""
VERSION=""
RUN_ALL=false
NO_BUILD=false

# Support colored output
RED='\e[31m'
GREEN='\e[32m'
YELLOW='\e[33m'
BLUE='\e[34m'
NC='\e[0m' # No Color

# Default matrix configurations
# format: "service:mode:version"
MATRIX=(
    "unbound:tcp:1.24.2"
    "unbound:tcp:1.25.0"
    "coredns:tcp:1.14.4"
    "coredns:tls:1.14.4"
    "dnsdist2:tcp:20"
    "dnsdist2:doq:20"
    "dnsdist2:tcp:21"
    "dnsdist2:doq:21"
    "knotresolver:unix:6.0.16"
    "knotresolver:unix:6.4.0"
)

show_help() {
    echo "Usage: ./tests/run_local_dns_tests.sh [options]"
    echo
    echo "Options:"
    echo "  -s, --service <name>      Service to test (unbound, coredns, dnsdist2, knotresolver)"
    echo "  -m, --mode <mode>         Mode to test (tcp, tls, doq, unix)"
    echo "  -v, --version <version>   Version of the service image to test"
    echo "  -a, --all                 Run all matrix configurations"
    echo "  -c, --clean               Clean up local test resources (docker containers, venv, certs, q) and exit"
    echo "      --no-build            Do not build/rebuild the dnscollector binary"
    echo "  -h, --help                Show this help message"
    echo
    echo "Matrix configurations available:"
    for item in "${MATRIX[@]}"; do
        IFS=":" read -r s m v <<< "$item"
        echo "  - Service: $s | Mode: $m | Version: $v"
    done
    echo
    echo "Examples:"
    echo "  ./tests/run_local_dns_tests.sh -s unbound -m tcp"
    echo "  ./tests/run_local_dns_tests.sh -s dnsdist2 -m doq -v 21"
    echo "  ./tests/run_local_dns_tests.sh --all"
}

cleanup_all() {
    echo -e "${YELLOW}Cleaning up test resources...${NC}"
    
    # Detect Docker command
    local docker_cmd="docker"
    if ! docker info &>/dev/null && sudo docker info &>/dev/null; then
        docker_cmd="sudo docker"
    fi
    
    # Stop docker container
    if $docker_cmd ps -a --format '{{.Names}}' | grep -Eq "^dnsserver$"; then
        echo "Stopping and removing dnsserver container..."
        $docker_cmd stop dnsserver &>/dev/null || true
        $docker_cmd rm dnsserver &>/dev/null || true
    fi
    
    # Remove files
    echo "Removing temporary certificate files..."
    rm -f ./tests/testsdata/dnscollector.key ./tests/testsdata/dnscollector.crt
    rm -f ca.key ca.crt server.conf dnscollector.csr
    
    echo "Removing unix socket directory..."
    if [ -d /tmp/dnstap-socket ]; then
        rm -rf /tmp/dnstap-socket || {
            if [ -t 0 ] || sudo -n true 2>/dev/null; then
                sudo rm -rf /tmp/dnstap-socket
            else
                echo -e "${YELLOW}Warning: Could not remove /tmp/dnstap-socket and no interactive terminal for sudo.${NC}"
            fi
        }
    fi
    
    echo "Removing python virtual environment..."
    rm -rf venv
    
    echo "Removing downloaded q utility..."
    rm -f q
    
    echo -e "${GREEN}Cleanup complete.${NC}"
}

cleanup_on_exit() {
    # If the container dnsserver is running, stop/remove it
    if [ -n "$DOCKER_CMD" ]; then
        if $DOCKER_CMD ps -a --format '{{.Names}}' | grep -Eq "^dnsserver$"; then
            echo -e "\n${YELLOW}Script interrupted or exited. Stopping and removing dnsserver container...${NC}"
            $DOCKER_CMD stop dnsserver &>/dev/null || true
            $DOCKER_CMD rm dnsserver &>/dev/null || true
        fi
    fi
}

check_prereqs() {
    echo -e "\n=== Checking prerequisites ==="
    for cmd in docker openssl python3 go dig; do
        if ! command -v "$cmd" &> /dev/null; then
            echo -e "${RED}Error: $cmd is not installed.${NC}" >&2
            exit 1
        fi
    done
    
    # Detect Docker command and access
    DOCKER_CMD="docker"
    if ! docker info &>/dev/null; then
        if sudo docker info &>/dev/null; then
            DOCKER_CMD="sudo docker"
        else
            echo -e "${RED}Error: Docker is not running or current user does not have permission to run docker.${NC}" >&2
            exit 1
        fi
    fi
    echo "Prerequisites OK (using '$DOCKER_CMD' for container actions)."
}

build_binary() {
    echo -e "\n=== Building dnscollector binary ==="
    if [ "$NO_BUILD" = true ] && [ -f "./dnscollector" ]; then
        echo "Binary already exists and --no-build was specified. Skipping build."
        return
    fi
    CGO_ENABLED=0 go build -ldflags="-s -w" -o dnscollector dnscollector.go
    if [ $? -ne 0 ]; then
        echo -e "${RED}Error: Failed to build dnscollector.${NC}" >&2
        exit 1
    fi
    chmod +x dnscollector
    echo "dnscollector built successfully."
}

setup_unix_socket() {
    echo -e "\n=== Setting up unix socket directory ==="
    if [ ! -d /tmp/dnstap-socket ]; then
        mkdir -p /tmp/dnstap-socket || {
            if [ -t 0 ] || sudo -n true 2>/dev/null; then
                sudo mkdir -p /tmp/dnstap-socket
            else
                echo -e "${YELLOW}Warning: Could not create /tmp/dnstap-socket and no interactive terminal for sudo.${NC}"
            fi
        }
    fi
    
    if [ -d /tmp/dnstap-socket ]; then
        chmod 777 /tmp/dnstap-socket || {
            if [ -t 0 ] || sudo -n true 2>/dev/null; then
                sudo chmod 777 /tmp/dnstap-socket
            else
                echo -e "${YELLOW}Warning: Could not chmod /tmp/dnstap-socket and no interactive terminal for sudo.${NC}"
            fi
        }
    fi
    
    # Check if pdns group and user exists, if not attempt to create them (ignore errors if they fail or already exist)
    if ! getent group pdns &>/dev/null; then
        echo "Creating pdns group..."
        if [ -t 0 ] || sudo -n true 2>/dev/null; then
            sudo addgroup --system --gid 953 pdns || true
        else
            echo -e "${YELLOW}Warning: pdns group does not exist and no interactive terminal for sudo.${NC}"
        fi
    fi
    if ! getent passwd pdns &>/dev/null; then
        echo "Creating pdns user..."
        if [ -t 0 ] || sudo -n true 2>/dev/null; then
            sudo adduser --system --disabled-password --no-create-home --uid 953 --gid 953 pdns || true
        else
            echo -e "${YELLOW}Warning: pdns user does not exist and no interactive terminal for sudo.${NC}"
        fi
    fi
}

generate_certificates() {
    echo -e "\n=== Generating Certificates ==="
    if [ -f "./tests/testsdata/dnscollector.key" ] && [ -f "./tests/testsdata/dnscollector.crt" ]; then
        echo "Certificates already exist in ./tests/testsdata/. Skipping generation."
        return
    fi
    
    openssl genrsa 2048 > ca.key
    openssl req -days 365 -new -x509 -nodes -key ca.key -out ca.crt -subj "/C=LU/ST=Space/L=Moon/O=GitHub/OU=Lab/CN=dnscollector.dev/emailAddress=admin@dnscollector.dev"
    
    echo -e "[ req ]\nprompt = no\ndistinguished_name = req_distinguished_name\nreq_extensions = req_ext\n[ req_distinguished_name ]\ncountryName = LU\nstateOrProvinceName = Space\nlocalityName = Moon\norganizationName = GitHub\norganizationalUnitName = DNScollector\ncommonName = dnscollector.dev\nemailAddress = admin@dnscollector.dev\n[ req_ext ]\nsubjectAltName = DNS: dnscollector.dev, IP: 127.0.0.1" > server.conf
    
    openssl req -newkey rsa:2048 -nodes -keyout dnscollector.key -out dnscollector.csr --config server.conf
    openssl x509 -req -days 365 -in dnscollector.csr -out dnscollector.crt -CA ca.crt -CAkey ca.key -extensions req_ext -extfile server.conf
    
    chmod 644 dnscollector.key || {
        if [ -t 0 ] || sudo -n true 2>/dev/null; then
            sudo chmod 644 dnscollector.key
        else
            echo -e "${YELLOW}Warning: Could not chmod dnscollector.key and no interactive terminal for sudo.${NC}"
        fi
    }
    mkdir -p ./tests/testsdata/
    mv dnscollector.key ./tests/testsdata/
    mv dnscollector.crt ./tests/testsdata/
    rm -f ca.key ca.crt server.conf dnscollector.csr
    echo "Certificates generated and moved to ./tests/testsdata/"
}

setup_python_env() {
    echo -e "\n=== Setting up Python Virtual Environment ==="
    if [ ! -d "venv" ]; then
        python3 -m venv venv
    fi
    source venv/bin/activate
    python3 -m pip install --upgrade pip
    python3 -m pip install dnstap_pb fstrm dnspython protobuf
}

download_q() {
    if [ ! -f "./q" ]; then
        echo -e "\n=== Downloading q binary for DoQ testing ==="
        Q_VERSION="0.19.12"
        wget -q "https://github.com/natesales/q/releases/download/v${Q_VERSION}/q_${Q_VERSION}_linux_amd64.tar.gz" -O q.tar.gz
        tar xzf q.tar.gz q
        rm -f q.tar.gz
        chmod +x q
        echo "q downloaded successfully."
    fi
}

deploy_container() {
    local service="$1"
    local version="$2"
    local mode="$3"
    
    echo -e "\n=== Deploying Docker image for $service ($mode, version $version) ==="
    
    local pwd_dir
    pwd_dir=$(pwd)
    case "$service" in
        "unbound")
            $DOCKER_CMD run -d --network="host" --name=dnsserver \
                --volume="$pwd_dir/tests/testsdata/unbound/unbound_${mode}.conf:/opt/unbound/etc/unbound/unbound.conf:z" \
                -v /tmp/dnstap-socket/:/opt/unbound/etc/unbound/tmp/:z \
                "ghcr.io/majorp93/unbound:${version}"
            ;;
        "coredns")
            $DOCKER_CMD run -d --network="host" --name=dnsserver \
                -v "$pwd_dir/tests/testsdata/:$pwd_dir/tests/testsdata/" \
                -v /tmp/dnstap-socket/:/tmp/ \
                "coredns/coredns:${version}" -conf "$pwd_dir/tests/testsdata/coredns/coredns_${mode}.conf"
            ;;
        "dnsdist")
            $DOCKER_CMD run -d --network="host" --name=dnsserver \
                --volume="$pwd_dir/tests/testsdata/powerdns/dnsdist_${mode}.conf:/etc/dnsdist/conf.d/dnsdist.conf:z" \
                --volume="$pwd_dir/tests/testsdata/dnscollector.key:/etc/dnsdist/conf.d/server.key:z" \
                --volume="$pwd_dir/tests/testsdata/dnscollector.crt:/etc/dnsdist/conf.d/server.crt:z" \
                -v /tmp/dnstap-socket/:/tmp/ \
                "powerdns/dnsdist-${version}"
            ;;
        "dnsdist2")
            $DOCKER_CMD run -d --network="host" --name=dnsserver \
                --volume="$pwd_dir/tests/testsdata/powerdns/dnsdist2_${mode}.yml:/etc/dnsdist/dnsdist.yml:z" \
                --volume="$pwd_dir/tests/testsdata/dnscollector.key:/etc/dnsdist/server.key:z" \
                --volume="$pwd_dir/tests/testsdata/dnscollector.crt:/etc/dnsdist/server.crt:z" \
                -v /tmp/dnstap-socket/:/tmp/ \
                "powerdns/dnsdist-${version}" -C /etc/dnsdist/dnsdist.yml
            ;;
        "knotresolver")
            $DOCKER_CMD run -d --network="host" --name=dnsserver \
                --volume="$pwd_dir/tests/testsdata/knot/knotresolver_${mode}.yml:/etc/knot-resolver/config.yaml:z" \
                -v /tmp/dnstap-socket/:/tmp/ \
                "cznic/knot-resolver:v${version}"
            ;;
        *)
            echo -e "${RED}Error: Unknown service $service${NC}" >&2
            exit 1
            ;;
    esac
    
    echo "Waiting for DNS server to be ready on port 5553..."
    local attempts=0
    local max_attempts=30
    until dig -p 5553 www.github.com @127.0.0.1 | grep -q "NOERROR"; do
        attempts=$((attempts + 1))
        if [ "$attempts" -ge "$max_attempts" ]; then
            echo -e "${RED}Error: DNS server failed to start or respond.${NC}" >&2
            $DOCKER_CMD logs dnsserver
            exit 1
        fi
        sleep 2.0
    done
    echo "DNS server is ready."
}

run_test_case() {
    local service="$1"
    local mode="$2"
    local version="$3"
    
    echo -e "\n${BLUE}======================================================================${NC}"
    echo -e "${BLUE}Running Test: Service=$service | Mode=$mode | Version=$version${NC}"
    echo -e "${BLUE}======================================================================${NC}"
    
    # 1. Clean up any existing container
    if $DOCKER_CMD ps -a --format '{{.Names}}' | grep -Eq "^dnsserver$"; then
        $DOCKER_CMD stop dnsserver &>/dev/null || true
        $DOCKER_CMD rm dnsserver &>/dev/null || true
    fi
    
    # 2. Deploy docker container
    deploy_container "$service" "$version" "$mode"
    
    # 3. Download q (if mode is doq)
    if [ "$mode" = "doq" ]; then
        download_q
    fi
    
    # 4. Set collector user environment variable
    local collector_user="pdns"
    if [ "$service" = "knotresolver" ] || [ "$service" = "bind9" ]; then
        collector_user="root"
    fi
    
    # 5. Run the python tests
    echo -e "\nRunning python unittest..."
    
    # We run in a subshell to avoid polluting environment
    local test_status=0
    (
        source venv/bin/activate
        export COLLECTOR_USER="$collector_user"
        python3 -m unittest "tests.dnsquery_dnstap${mode}" -v
    ) || test_status=$?
    
    if [ $test_status -ne 0 ]; then
        echo -e "${RED}Test FAILED for $service ($mode, version $version)${NC}"
        echo -e "${YELLOW}Docker logs for dnsserver:${NC}"
        $DOCKER_CMD logs dnsserver || true
    fi
    
    # 6. Stop and remove container
    echo "Stopping and removing dnsserver container..."
    $DOCKER_CMD stop dnsserver &>/dev/null || true
    $DOCKER_CMD rm dnsserver &>/dev/null || true
    
    if [ $test_status -ne 0 ]; then
        return 1
    else
        echo -e "${GREEN}Test PASSED for $service ($mode, version $version)${NC}"
        return 0
    fi
}

# Setup exit/interrupt trap
trap cleanup_on_exit EXIT INT TERM

# Parse arguments
while [[ $# -gt 0 ]]; do
    case "$1" in
        -s|--service)
            SERVICE="$2"
            shift 2
            ;;
        -m|--mode)
            MODE="$2"
            shift 2
            ;;
        -v|--version)
            VERSION="$2"
            shift 2
            ;;
        -a|--all)
            RUN_ALL=true
            shift
            ;;
        -c|--clean)
            cleanup_all
            exit 0
            ;;
        --no-build)
            NO_BUILD=true
            shift
            ;;
        -h|--help)
            show_help
            exit 0
            ;;
        *)
            echo -e "${RED}Unknown option: $1${NC}" >&2
            show_help
            exit 1
            ;;
    esac
done

# Perform common initialization
check_prereqs
build_binary
setup_unix_socket
generate_certificates
setup_python_env

# Run tests
failed_tests=()

if [ "$RUN_ALL" = true ]; then
    for item in "${MATRIX[@]}"; do
        IFS=":" read -r s m v <<< "$item"
        if ! run_test_case "$s" "$m" "$v"; then
            failed_tests+=("$s:$m:$v")
        fi
    done
else
    # If no service/mode/version specified, run defaults (unbound tcp)
    if [ -z "$SERVICE" ] && [ -z "$MODE" ]; then
        SERVICE="unbound"
        MODE="tcp"
    fi
    
    # Match default versions/modes from matrix if unspecified
    if [ -z "$VERSION" ] || [ -z "$MODE" ] || [ -z "$SERVICE" ]; then
        for item in "${MATRIX[@]}"; do
            IFS=":" read -r s m v <<< "$item"
            
            # Match service if specified, or use default
            if [ -n "$SERVICE" ] && [ "$s" != "$SERVICE" ]; then
                continue
            fi
            # Match mode if specified
            if [ -n "$MODE" ] && [ "$m" != "$MODE" ]; then
                continue
            fi
            
            # Found first matching configuration
            [ -z "$SERVICE" ] && SERVICE="$s"
            [ -z "$MODE" ] && MODE="$m"
            [ -z "$VERSION" ] && VERSION="$v"
            break
        done
    fi
    
    # Ensure variables are fully set
    if [ -z "$SERVICE" ] || [ -z "$MODE" ] || [ -z "$VERSION" ]; then
        echo -e "${RED}Error: Could not resolve service, mode or version parameters.${NC}" >&2
        exit 1
    fi
    
    if ! run_test_case "$SERVICE" "$MODE" "$VERSION"; then
        failed_tests+=("$SERVICE:$MODE:$VERSION")
    fi
fi

# Print final report
echo -e "\n${BLUE}======================================================================${NC}"
echo -e "${BLUE}Test Execution Summary${NC}"
echo -e "${BLUE}======================================================================${NC}"
if [ ${#failed_tests[@]} -eq 0 ]; then
    echo -e "${GREEN}All local DNS tests PASSED successfully!${NC}"
    exit 0
else
    echo -e "${RED}The following tests FAILED:${NC}"
    for ft in "${failed_tests[@]}"; do
        echo -e "  - ${RED}$ft${NC}"
    done
    exit 1
fi
