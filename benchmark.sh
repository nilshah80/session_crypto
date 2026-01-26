#!/bin/bash
set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Configuration
ITERATIONS=${1:-1000}
RUNS=${2:-5}
WARMUP_SLEEP=2
BETWEEN_RUNS_SLEEP=1
BETWEEN_SERVERS_SLEEP=3

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
RESULTS_FILE="${SCRIPT_DIR}/benchmark_results_${TIMESTAMP}.txt"
SUMMARY_FILE="/tmp/benchmark_summary_${TIMESTAMP}.txt"
LATENCY_FILE="/tmp/benchmark_latency_${TIMESTAMP}.txt"

log() {
    echo -e "${GREEN}[$(date '+%H:%M:%S')]${NC} $1"
}

log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

header() {
    echo ""
    echo -e "${CYAN}═══════════════════════════════════════════════════════════════${NC}"
    echo -e "${CYAN}  $1${NC}"
    echo -e "${CYAN}═══════════════════════════════════════════════════════════════${NC}"
}

# Initialize results file
init_results() {
    cat > "$RESULTS_FILE" << EOF
════════════════════════════════════════════════════════════════════════════════
  Session Crypto Benchmark Results
  Date: $(date)
  Iterations: $ITERATIONS per run
  Runs: $RUNS per client/server combination
════════════════════════════════════════════════════════════════════════════════

EOF
    echo "" > "$SUMMARY_FILE"
    echo "" > "$LATENCY_FILE"
}

# Check prerequisites
check_prerequisites() {
    header "Checking Prerequisites"

    # Check Docker
    if ! docker info > /dev/null 2>&1; then
        log_error "Docker is not running. Please start Docker first."
        exit 1
    fi
    log "Docker is running"

    # Check Redis and PostgreSQL
    if ! docker ps | grep -q session-crypto-redis; then
        log_warn "Redis container not running. Starting docker compose..."
        cd "$SCRIPT_DIR"
        docker compose up -d
        sleep 10
    fi
    log "Redis container is running"

    if ! docker ps | grep -q session-crypto-postgres; then
        log_warn "PostgreSQL container not running. Starting docker compose..."
        cd "$SCRIPT_DIR"
        docker compose up -d
        sleep 10
    fi
    log "PostgreSQL container is running"
}

# Build all servers
build_servers() {
    header "Building Servers"

    # Node.js server
    log "Building Node.js server..."
    cd "$SCRIPT_DIR/server"
    npm install > /dev/null 2>&1 || true
    npm run build > /dev/null 2>&1 || true

    # Go server
    log "Building Go server..."
    cd "$SCRIPT_DIR/server-go"
    go build -o server main.go 2>/dev/null || true

    # Rust servers
    log "Building Rust (aws-lc-rs) server..."
    cd "$SCRIPT_DIR/server-rust"
    cargo build --release > /dev/null 2>&1 || true

    log "Building Rust-ring server..."
    cd "$SCRIPT_DIR/server-rust-ring"
    cargo build --release > /dev/null 2>&1 || true

    log "Building Rust-native server..."
    cd "$SCRIPT_DIR/server-rust-native"
    cargo build --release > /dev/null 2>&1 || true

    log ".NET server will be built on first run"
    log "All servers built successfully"
}

# Build all clients
build_clients() {
    header "Building Clients"

    # Node.js client
    log "Building Node.js client..."
    cd "$SCRIPT_DIR/client/node"
    npm install > /dev/null 2>&1 || true
    npm run build > /dev/null 2>&1 || true

    # Go client
    log "Building Go client..."
    cd "$SCRIPT_DIR/client/go"
    go build -o client main.go 2>/dev/null || true

    # Rust client
    log "Building Rust client..."
    cd "$SCRIPT_DIR/client/rust"
    cargo build --release > /dev/null 2>&1 || true

    log ".NET and Java clients will be built on first run"
    log "All clients built successfully"
}

# Kill any running servers on port 3000
kill_servers() {
    pkill -f "node dist/index.js" 2>/dev/null || true
    pkill -f "dotnet.*SessionCryptoServer" 2>/dev/null || true
    pkill -f "./server" 2>/dev/null || true
    pkill -f "session-crypto-server" 2>/dev/null || true
    sleep 1
    lsof -ti:3000 | xargs kill -9 2>/dev/null || true
    sleep 1
}

# Start a server and wait for it to be ready
start_server() {
    local name=$1
    local dir=$2
    local cmd=$3

    kill_servers

    log "Starting $name server..."
    cd "$SCRIPT_DIR/$dir"

    # Start server in background
    eval "$cmd > /tmp/server_${name}.log 2>&1 &"

    # Wait for server to be ready
    local retries=0
    while ! curl -s http://localhost:3000/health > /dev/null 2>&1; do
        sleep 1
        retries=$((retries + 1))
        if [ $retries -gt 30 ]; then
            log_error "Server $name failed to start"
            cat /tmp/server_${name}.log 2>/dev/null || true
            return 1
        fi
    done

    log "$name server is ready"
    sleep $WARMUP_SLEEP
    return 0
}

# Extract latency percentiles from output
# Args: output, endpoint_name (init/purchase/combined)
# Returns: P50|P95|P99|Mean
extract_latency() {
    local output="$1"
    local endpoint="$2"

    local section=""
    case "$endpoint" in
        init)     section="/session/init:" ;;
        purchase) section="/transaction/purchase:" ;;
        combined) section="Combined" ;;
    esac

    # Extract the latency line for this endpoint
    local latency_line
    latency_line=$(echo "$output" | grep -A3 "$section" | grep "P50:" | head -1)

    if [ -n "$latency_line" ]; then
        local p50 p95 p99
        p50=$(echo "$latency_line" | grep -oE "P50: [0-9]+\.[0-9]+" | grep -oE "[0-9]+\.[0-9]+")
        p95=$(echo "$latency_line" | grep -oE "P95: [0-9]+\.[0-9]+" | grep -oE "[0-9]+\.[0-9]+")
        p99=$(echo "$latency_line" | grep -oE "P99: [0-9]+\.[0-9]+" | grep -oE "[0-9]+\.[0-9]+")

        # Also get mean from the previous line
        local mean_line
        mean_line=$(echo "$output" | grep -A2 "$section" | grep "Mean:" | head -1)
        local mean
        mean=$(echo "$mean_line" | grep -oE "Mean: [0-9]+\.[0-9]+" | grep -oE "[0-9]+\.[0-9]+")

        echo "${p50:-0}|${p95:-0}|${p99:-0}|${mean:-0}"
    else
        echo "0|0|0|0"
    fi
}

# Run a single client benchmark and return average throughput
run_client_benchmark() {
    local client_name=$1
    local client_dir=$2
    local client_cmd=$3
    local server_name=$4

    cd "$SCRIPT_DIR/$client_dir"

    local sum=0
    local count=0
    local all_results=""

    # Accumulators for latency averages
    local init_p50_sum=0 init_p95_sum=0 init_p99_sum=0 init_mean_sum=0
    local purchase_p50_sum=0 purchase_p95_sum=0 purchase_p99_sum=0 purchase_mean_sum=0
    local combined_p50_sum=0 combined_p95_sum=0 combined_p99_sum=0 combined_mean_sum=0

    for run in $(seq 1 $RUNS); do
        # Run benchmark and extract throughput
        local output
        output=$(eval "$client_cmd $ITERATIONS" 2>&1)

        # Extract combined throughput
        local throughput
        throughput=$(echo "$output" | grep -A1 "Combined" | grep "Throughput" | grep -oE "[0-9]+\.[0-9]+" | head -1)

        if [ -n "$throughput" ]; then
            all_results="$all_results $throughput"
            sum=$(echo "$sum + $throughput" | bc)
            count=$((count + 1))

            # Extract latency metrics for init endpoint
            local init_latency
            init_latency=$(extract_latency "$output" "init")
            local init_p50 init_p95 init_p99 init_mean
            IFS='|' read -r init_p50 init_p95 init_p99 init_mean <<< "$init_latency"
            init_p50_sum=$(echo "$init_p50_sum + $init_p50" | bc)
            init_p95_sum=$(echo "$init_p95_sum + $init_p95" | bc)
            init_p99_sum=$(echo "$init_p99_sum + $init_p99" | bc)
            init_mean_sum=$(echo "$init_mean_sum + $init_mean" | bc)

            # Extract latency metrics for purchase endpoint
            local purchase_latency
            purchase_latency=$(extract_latency "$output" "purchase")
            local purchase_p50 purchase_p95 purchase_p99 purchase_mean
            IFS='|' read -r purchase_p50 purchase_p95 purchase_p99 purchase_mean <<< "$purchase_latency"
            purchase_p50_sum=$(echo "$purchase_p50_sum + $purchase_p50" | bc)
            purchase_p95_sum=$(echo "$purchase_p95_sum + $purchase_p95" | bc)
            purchase_p99_sum=$(echo "$purchase_p99_sum + $purchase_p99" | bc)
            purchase_mean_sum=$(echo "$purchase_mean_sum + $purchase_mean" | bc)

            # Extract latency metrics for combined
            local combined_latency
            combined_latency=$(extract_latency "$output" "combined")
            local combined_p50 combined_p95 combined_p99 combined_mean
            IFS='|' read -r combined_p50 combined_p95 combined_p99 combined_mean <<< "$combined_latency"
            combined_p50_sum=$(echo "$combined_p50_sum + $combined_p50" | bc)
            combined_p95_sum=$(echo "$combined_p95_sum + $combined_p95" | bc)
            combined_p99_sum=$(echo "$combined_p99_sum + $combined_p99" | bc)
            combined_mean_sum=$(echo "$combined_mean_sum + $combined_mean" | bc)
        fi

        sleep $BETWEEN_RUNS_SLEEP
    done

    # Calculate averages
    local avg="0"
    if [ $count -gt 0 ]; then
        avg=$(echo "scale=1; $sum / $count" | bc)

        # Calculate average latencies
        local init_p50_avg init_p95_avg init_p99_avg init_mean_avg
        init_p50_avg=$(echo "scale=2; $init_p50_sum / $count" | bc)
        init_p95_avg=$(echo "scale=2; $init_p95_sum / $count" | bc)
        init_p99_avg=$(echo "scale=2; $init_p99_sum / $count" | bc)
        init_mean_avg=$(echo "scale=2; $init_mean_sum / $count" | bc)

        local purchase_p50_avg purchase_p95_avg purchase_p99_avg purchase_mean_avg
        purchase_p50_avg=$(echo "scale=2; $purchase_p50_sum / $count" | bc)
        purchase_p95_avg=$(echo "scale=2; $purchase_p95_sum / $count" | bc)
        purchase_p99_avg=$(echo "scale=2; $purchase_p99_sum / $count" | bc)
        purchase_mean_avg=$(echo "scale=2; $purchase_mean_sum / $count" | bc)

        local combined_p50_avg combined_p95_avg combined_p99_avg combined_mean_avg
        combined_p50_avg=$(echo "scale=2; $combined_p50_sum / $count" | bc)
        combined_p95_avg=$(echo "scale=2; $combined_p95_sum / $count" | bc)
        combined_p99_avg=$(echo "scale=2; $combined_p99_sum / $count" | bc)
        combined_mean_avg=$(echo "scale=2; $combined_mean_sum / $count" | bc)

        # Store latency data
        # Format: server|client|endpoint|mean|p50|p95|p99
        echo "${server_name}|${client_name}|init|${init_mean_avg}|${init_p50_avg}|${init_p95_avg}|${init_p99_avg}" >> "$LATENCY_FILE"
        echo "${server_name}|${client_name}|purchase|${purchase_mean_avg}|${purchase_p50_avg}|${purchase_p95_avg}|${purchase_p99_avg}" >> "$LATENCY_FILE"
        echo "${server_name}|${client_name}|combined|${combined_mean_avg}|${combined_p50_avg}|${combined_p95_avg}|${combined_p99_avg}" >> "$LATENCY_FILE"
    fi

    # Output results
    echo "  ${client_name}:${all_results} -> avg: ${avg} req/s" >> "$RESULTS_FILE"
    echo "${server_name}|${client_name}|${avg}" >> "$SUMMARY_FILE"
    echo "$avg"
}

# Test all clients against a server
test_server() {
    local server_name=$1
    local server_dir=$2
    local server_cmd=$3

    header "Testing $server_name Server"
    echo "" >> "$RESULTS_FILE"
    echo "═══ $server_name Server ═══" >> "$RESULTS_FILE"
    echo "Started at: $(date)" >> "$RESULTS_FILE"
    echo "" >> "$RESULTS_FILE"

    # Start the server
    if ! start_server "$server_name" "$server_dir" "$server_cmd"; then
        log_error "Failed to start $server_name server, skipping..."
        return 1
    fi

    # Test Go client
    log_info "Testing Go client vs $server_name server"
    echo -n "  Go client: "
    avg=$(run_client_benchmark "go" "client/go" "./client -benchmark" "$server_name")
    echo "$avg req/s"

    # Test Rust client
    log_info "Testing Rust client vs $server_name server"
    echo -n "  Rust client: "
    avg=$(run_client_benchmark "rust" "client/rust" "./target/release/session-crypto-client --benchmark" "$server_name")
    echo "$avg req/s"

    # Test Node.js client
    log_info "Testing Node.js client vs $server_name server"
    echo -n "  Node.js client: "
    avg=$(run_client_benchmark "nodejs" "client/node" "NODE_ENV=production node dist/index.js --benchmark" "$server_name")
    echo "$avg req/s"

    # Test .NET client
    log_info "Testing .NET client vs $server_name server"
    echo -n "  .NET client: "
    avg=$(run_client_benchmark "dotnet" "client/dotnet/SessionCryptoClient" "dotnet run -c Release -- --benchmark" "$server_name")
    echo "$avg req/s"

    # Test Java VT client
    log_info "Testing Java VT client vs $server_name server"
    echo -n "  Java VT client: "
    avg=$(run_client_benchmark "java-vt" "client/java-virtual-threads" "./run.sh --benchmark" "$server_name")
    echo "$avg req/s"

    # Test Java WebFlux client
    log_info "Testing Java WebFlux client vs $server_name server"
    echo -n "  Java WebFlux client: "
    avg=$(run_client_benchmark "java-webflux" "client/java-webflux" "./run.sh --benchmark" "$server_name")
    echo "$avg req/s"

    echo "" >> "$RESULTS_FILE"
    kill_servers
    sleep $BETWEEN_SERVERS_SLEEP
}

# Generate latency table for a specific endpoint
generate_latency_table() {
    local endpoint=$1
    local title=$2

    echo "" >> "$RESULTS_FILE"
    echo "$title Latency (ms):" >> "$RESULTS_FILE"
    echo "" >> "$RESULTS_FILE"
    printf "| %-12s | %-8s |" "Client" "Server" >> "$RESULTS_FILE"
    printf " %-6s |" "Mean" "P50" "P95" "P99" >> "$RESULTS_FILE"
    echo "" >> "$RESULTS_FILE"
    echo "|--------------|----------|--------|--------|--------|--------|" >> "$RESULTS_FILE"

    for client in go rust nodejs dotnet java-vt java-webflux; do
        for server in go rust-aws rust-ring; do
            local line
            line=$(grep "^${server}|${client}|${endpoint}|" "$LATENCY_FILE" 2>/dev/null | head -1)
            if [ -n "$line" ]; then
                local mean p50 p95 p99
                mean=$(echo "$line" | cut -d'|' -f4)
                p50=$(echo "$line" | cut -d'|' -f5)
                p95=$(echo "$line" | cut -d'|' -f6)
                p99=$(echo "$line" | cut -d'|' -f7)
                printf "| %-12s | %-8s |" "$client" "$server" >> "$RESULTS_FILE"
                printf " %6s |" "${mean:-N/A}" "${p50:-N/A}" "${p95:-N/A}" "${p99:-N/A}" >> "$RESULTS_FILE"
                echo "" >> "$RESULTS_FILE"
            fi
        done
    done
}

# Generate summary report
generate_summary() {
    header "Generating Summary Report"

    cat >> "$RESULTS_FILE" << 'EOF'

════════════════════════════════════════════════════════════════════════════════
  SUMMARY - Average Throughput (req/s)
════════════════════════════════════════════════════════════════════════════════

EOF

    echo "Performance Matrix (Combined init + purchase):" >> "$RESULTS_FILE"
    echo "" >> "$RESULTS_FILE"
    printf "| %-12s |" "Client" >> "$RESULTS_FILE"
    printf " %-8s |" "dotnet" "nodejs" "go" "rust-aws" "rust-ring" "rust-nat" >> "$RESULTS_FILE"
    echo "" >> "$RESULTS_FILE"
    echo "|--------------|----------|----------|----------|----------|-----------|----------|" >> "$RESULTS_FILE"

    for client in go rust nodejs dotnet java-vt java-webflux; do
        printf "| %-12s |" "$client" >> "$RESULTS_FILE"
        for server in dotnet nodejs go rust-aws rust-ring rust-native; do
            val=$(grep "^${server}|${client}|" "$SUMMARY_FILE" 2>/dev/null | cut -d'|' -f3 | head -1)
            printf " %8s |" "${val:-N/A}" >> "$RESULTS_FILE"
        done
        echo "" >> "$RESULTS_FILE"
    done

    echo "" >> "$RESULTS_FILE"
    echo "Server Rankings (peak throughput):" >> "$RESULTS_FILE"
    for server in dotnet nodejs go rust-aws rust-ring rust-native; do
        max=$(grep "^${server}|" "$SUMMARY_FILE" 2>/dev/null | cut -d'|' -f3 | sort -rn | head -1)
        echo "  $server: ${max:-0} req/s" >> "$RESULTS_FILE"
    done

    echo "" >> "$RESULTS_FILE"
    echo "Client Rankings (peak throughput):" >> "$RESULTS_FILE"
    for client in go rust nodejs dotnet java-vt java-webflux; do
        max=$(grep "|${client}|" "$SUMMARY_FILE" 2>/dev/null | cut -d'|' -f3 | sort -rn | head -1)
        echo "  $client: ${max:-0} req/s" >> "$RESULTS_FILE"
    done

    cat >> "$RESULTS_FILE" << 'EOF'

════════════════════════════════════════════════════════════════════════════════
  LATENCY PERCENTILES (Best Servers)
════════════════════════════════════════════════════════════════════════════════
EOF

    generate_latency_table "init" "/session/init"
    generate_latency_table "purchase" "/transaction/purchase"
    generate_latency_table "combined" "Combined (init + purchase)"

    cat >> "$RESULTS_FILE" << EOF

════════════════════════════════════════════════════════════════════════════════
  Benchmark completed at: $(date)
════════════════════════════════════════════════════════════════════════════════
EOF

    log "Results saved to: $RESULTS_FILE"
}

# Print summary to console
print_console_summary() {
    echo ""
    echo -e "${CYAN}════════════════════════════════════════════════════════════════${NC}"
    echo -e "${CYAN}  BENCHMARK COMPLETE - $ITERATIONS iterations x $RUNS runs${NC}"
    echo -e "${CYAN}════════════════════════════════════════════════════════════════${NC}"
    echo ""
    echo "Results saved to: $RESULTS_FILE"
    echo ""
    echo "Server Rankings (peak throughput):"
    for server in dotnet nodejs go rust-aws rust-ring rust-native; do
        max=$(grep "^${server}|" "$SUMMARY_FILE" 2>/dev/null | cut -d'|' -f3 | sort -rn | head -1)
        printf "  %-12s %8s req/s\n" "$server:" "${max:-0}"
    done
    echo ""
}

# Handle cleanup on exit
cleanup() {
    log "Cleaning up..."
    kill_servers
}
trap cleanup EXIT

# Main execution
main() {
    header "Session Crypto Benchmark Suite"
    echo "Iterations: $ITERATIONS | Runs: $RUNS"
    echo "Results will be saved to: $RESULTS_FILE"

    init_results
    check_prerequisites
    build_servers
    build_clients

    header "Starting Benchmarks"

    # Test each server
    test_server "dotnet" "server-dotnet" "dotnet run -c Release"
    test_server "nodejs" "server" "NODE_ENV=production node dist/index.js"
    test_server "go" "server-go" "./server"
    test_server "rust-aws" "server-rust" "./target/release/session-crypto-server"
    test_server "rust-ring" "server-rust-ring" "./target/release/session-crypto-server-ring"
    test_server "rust-native" "server-rust-native" "./target/release/session-crypto-server-native"

    generate_summary
    print_console_summary
}

# Run main
main "$@"
