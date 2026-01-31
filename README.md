# Session Crypto PoC

A proof-of-concept implementation of the session-based encryption design using ECDH key agreement and AES-256-GCM encryption.

## Architecture

```
┌─────────────────┐         ┌─────────────────┐         ┌─────────────────┐
│     Client      │         │     Server      │         │   PostgreSQL    │
│  (Multi-lang)   │         │  (Multi-lang)   │         │  (Persistence)  │
└────────┬────────┘         └────────┬────────┘         └────────┬────────┘
         │                           │                           │
         │                           │                   ┌───────┴───────┐
         │                           │                   │     Redis     │
         │                           │                   │    (Cache)    │
         │                           │                   └───────┬───────┘
         │  POST /session/init       │                           │
         │  + clientPublicKey        │                           │
         ├──────────────────────────►│                           │
         │                           │  Generate serverKeypair   │
         │                           │  sharedSecret = ECDH      │
         │                           │  sessionKey = HKDF        │
         │                           │  Store session ──────────►│ (PostgreSQL + Redis)
         │  sessionId                │                           │
         │  + serverPublicKey        │                           │
         │◄──────────────────────────┤                           │
         │                           │                           │
         │  Derive sessionKey        │                           │
         │                           │                           │
         │  POST /transaction/purchase                           │
         │  [encrypted with sessionKey]                          │
         ├──────────────────────────►│                           │
         │                           │  Lookup session ◄─────────│ (Redis → PostgreSQL)
         │                           │  Verify nonce ◄───────────│ (Redis)
         │                           │  Decrypt & process        │
         │  [encrypted response]     │                           │
         │◄──────────────────────────┤                           │
         │                           │                           │
         │  Decrypt response         │                           │
         └───────────────────────────┘                           │
```

## Prerequisites

- **Server** (any one): Node.js 24+, Go 1.25+, Rust 1.93+, or .NET 10.0
- **Infrastructure**: Docker (for Redis and PostgreSQL)
- **Clients** (any one):
  - Node.js 24+
  - .NET 10.0
  - Java 25
  - Go 1.25+
  - Rust 1.93+

## Quick Start

### 1. Start Redis

```bash
docker compose up -d
```

### 2. Start a Server

Choose any server implementation:

```bash
# Node.js (Fastify)
cd server
npm install
npm run dev

# Go (Chi router)
cd server-go
go run .

# Rust with aws-lc-rs (fastest)
cd server-rust
cargo run --release

# Rust with ring crypto
cd server-rust-ring
cargo run --release

# Rust with native RustCrypto
cd server-rust-native
cargo run --release

# .NET 10 (ASP.NET Core)
cd server-dotnet/SessionCryptoServer
dotnet run -c Release
```

All servers start on `http://localhost:3000`

### 3. Run a Client

Choose any client implementation:

```bash
# Node.js (single run with metrics)
cd client/node
npm install
npm start

# Node.js (benchmark mode with concurrency)
BENCHMARK_CONCURRENCY=50 npm start -- --benchmark 10000

# .NET (single run with metrics)
cd client/dotnet/SessionCryptoClient
dotnet run -c Release

# .NET (benchmark mode with concurrency)
cd client/dotnet/SessionCryptoClient
BENCHMARK_CONCURRENCY=50 dotnet run -c Release -- --benchmark 10000

# Java (Virtual Threads)
cd client/java-virtual-threads
./run.sh

# Java (WebFlux-style with Project Reactor - Properly Reactive)
cd client/java-webflux
./run.sh

# Go (single run with metrics)
cd client/go
go run .

# Go (benchmark mode with concurrency)
BENCHMARK_CONCURRENCY=50 go run . --benchmark 10000

# Rust (single run with metrics)
cd client/rust
cargo run --release

# Rust (benchmark mode with concurrency)
BENCHMARK_CONCURRENCY=50 cargo run --release -- --benchmark 10000

# Angular SPA (browser)
cd client/angular-spa
npm install
npm start
# Open http://localhost:4200

# React SPA (browser)
cd client/react-spa
npm install
npm start
# Open http://localhost:4201
```

## Client Implementations

### CLI Clients

| Language | Directory | Version | Pattern | Optimization |
|----------|-----------|---------|---------|--------------|
| Node.js | `client/node/` | Node 24+ | Async/await | Standard |
| .NET C# | `client/dotnet/` | .NET 10.0 | Async/await | **AesGcm reuse, ArrayPool** |
| Java | `client/java-virtual-threads/` | Java 25 | Virtual Threads | **ACCP, Cipher reuse, Pools** |
| Java | `client/java-webflux/` | Java 25 | Reactor Mono/Flux | **ACCP, Cipher reuse, Reactive** |
| Go | `client/go/` | Go 1.25+ | Goroutines | Standard |
| Rust | `client/rust/` | Rust 1.93+ | Tokio async | aws-lc-rs |

### Browser SPA Clients

| Framework | Directory | Version | Notes |
|-----------|-----------|---------|-------|
| Angular | `client/angular-spa/` | Angular 19 | Single-SPA, Web Crypto API |
| React | `client/react-spa/` | React 19 | Single-SPA, Web Crypto API |

All clients implement the same encryption flow and produce identical outputs.

## Server Implementations

| Language | Directory | Framework | Crypto Library |
|----------|-----------|-----------|----------------|
| Node.js | `server/` | Fastify | Node.js crypto |
| Go | `server-go/` | Chi | crypto/ecdh |
| Rust | `server-rust/` | Axum | aws-lc-rs |
| Rust | `server-rust-ring/` | Axum | ring |
| Rust | `server-rust-native/` | Axum | RustCrypto (p256, aes-gcm) |
| .NET | `server-dotnet/` | ASP.NET Core | System.Security.Cryptography |

All servers implement identical endpoints and crypto operations with PostgreSQL for persistence and Redis for caching.

## Endpoints

### `POST /session/init`

Initialize an authenticated encryption session.

**Headers:**
- `X-Idempotency-Key: <timestamp>.<nonce>` - Combined timestamp and UUID nonce (e.g., `1705234567890.550e8400-e29b-41d4-a716-446655440000`)
- `X-ClientId: <client_id>` - Client identifier (e.g., `NODE_CLI_CLIENT`, `ANGULAR_SPA_CLIENT`)

**Request Body:**
```json
{
  "clientPublicKey": "<base64>",
  "ttlSec": 1800
}
```

**Response:**
```json
{
  "sessionId": "S-<hex>",
  "serverPublicKey": "<base64>",
  "encAlg": "A256GCM",
  "expiresInSec": 1800
}
```

### `POST /transaction/purchase`

Encrypted business endpoint for testing.

**Headers:**
- `X-Kid: session:<sessionId>` - Session key identifier
- `X-Idempotency-Key: <timestamp>.<nonce>` - Combined timestamp and UUID nonce
- `X-ClientId: <client_id>` - Client identifier

**Request Body:** Binary data in format: `IV (12 bytes) || ciphertext || Tag (16 bytes)`

**Response Headers:**
- `X-Kid: session:<sessionId>`
- `X-Idempotency-Key: <timestamp>.<nonce>` - New timestamp/nonce for response
- `Server-Timing` - Performance metrics

**Response Body:** Binary data in format: `IV (12 bytes) || ciphertext || Tag (16 bytes)`

### `GET /health`

Health check endpoint.

**Response:**
```json
{
  "status": "ok",
  "timestamp": "2026-01-18T12:00:00.000Z",
  "redis": "ok",
  "postgres": "ok"
}
```

## Crypto Details

- **Key Agreement:** ECDH with P-256 curve
- **Key Derivation:** HKDF-SHA256
  - Salt: Session ID
  - Info: `SESSION|A256GCM|<clientId>`
- **Encryption:** AES-256-GCM
- **IV:** 12 bytes (96 bits), randomly generated per message
- **Auth Tag:** 16 bytes (128 bits)
- **AAD Format:** `TIMESTAMP|NONCE|KID|CLIENTID`
- **Body Format:** `IV (12 bytes) || ciphertext || Tag (16 bytes)` (binary, not base64)

## Security Features

- Replay protection via Redis (nonce uniqueness + timestamp window)
- Public key validation (point on curve)
- 128-bit session ID entropy
- AAD binding (method, path, timestamp, nonce, session)
- Generic error responses (prevents oracle attacks)
- Session TTL enforcement

## Data Storage

### PostgreSQL (Source of Truth)

```sql
CREATE TABLE sessions (
    session_id VARCHAR(255) PRIMARY KEY,
    data JSONB NOT NULL,          -- {key, type, expiresAt}
    expires_at BIGINT NOT NULL
);
CREATE INDEX idx_sessions_expires_at ON sessions(expires_at);
```

### Redis (Cache + Nonce Store)

```
sess:<sessionId>   → {key, type, expiresAt}   TTL: matches session TTL
nonce:<uuid>       → "1"                       TTL: 300s (replay protection)
```

## Project Structure

```
session_crypto/
├── docker-compose.yml          # Redis + PostgreSQL containers
├── benchmark.sh                # Comprehensive benchmark script
├── server/                     # Node.js server (Fastify)
│   ├── src/
│   │   ├── index.ts            # Server with endpoints
│   │   ├── crypto-helpers.ts   # ECDH, HKDF, AES-GCM, replay protection
│   │   ├── session-store.ts    # PostgreSQL + Redis session storage
│   │   └── metrics.ts          # Server-Timing header support
│   ├── package.json
│   └── tsconfig.json
├── server-go/                  # Go server (Chi)
│   ├── main.go                 # All-in-one server implementation
│   └── go.mod
├── server-rust/                # Rust server (Axum + aws-lc-rs)
│   ├── src/main.rs
│   └── Cargo.toml
├── server-rust-ring/           # Rust server (Axum + ring)
│   ├── src/main.rs
│   └── Cargo.toml
├── server-rust-native/         # Rust server (Axum + RustCrypto)
│   ├── src/main.rs
│   └── Cargo.toml
├── server-dotnet/              # .NET 10 server (ASP.NET Core)
│   └── SessionCryptoServer/
│       ├── Program.cs
│       └── SessionCryptoServer.csproj
├── client/
│   ├── node/                   # Node.js client
│   ├── dotnet/                 # .NET 10 client
│   ├── java-virtual-threads/   # Java 25 with Virtual Threads
│   ├── java-webflux/           # Java 25 with CompletableFuture
│   ├── go/                     # Go client
│   ├── rust/                   # Rust client
│   ├── angular-spa/            # Angular 19 browser client
│   └── react-spa/              # React 19 browser client
└── README.md
```

## Performance Metrics

All clients include built-in performance metrics and benchmark mode.

### Single Run with Metrics

```bash
# Any client - default mode shows detailed metrics
cd client/node && npm start
cd client/go && go run .
cd client/rust && cargo run --release
cd client/java-virtual-threads && ./run.sh
cd client/java-webflux && ./run.sh
cd client/dotnet/SessionCryptoClient && dotnet run -c Release
```

Example output:
```
================================================================================
  Performance Metrics Summary
================================================================================

Endpoint: /session/init
----------------------------------------
  Total Round-Trip:     2.345 ms
  HTTP Request Time:    1.567 ms

  Client Crypto Operations:
    - ecdh-keygen        0.234 ms
    - ecdh-compute       0.123 ms
    - hkdf               0.045 ms

  Server Timing:
    - replay-protection  0.234 ms
    - ecdh-keygen        0.167 ms
    - hkdf               0.023 ms
    - redis-store        0.345 ms
    - total              0.789 ms
```

### Benchmark Mode

Run N iterations with warmup and calculate throughput + percentile stats:

```bash
# Node.js (sequential - latency measurement only)
npm start -- --benchmark 1000

# Node.js (concurrent - high throughput)
BENCHMARK_CONCURRENCY=50 npm start -- --benchmark 10000

# Node.js (stress test - maximum throughput)
BENCHMARK_CONCURRENCY=100 npm start -- --benchmark 50000

# Go (sequential - latency measurement)
go run . --benchmark 1000

# Go (concurrent - high throughput)
BENCHMARK_CONCURRENCY=50 go run . --benchmark 10000

# Rust (sequential - latency measurement)
cargo run --release -- --benchmark 1000

# Rust (concurrent - high throughput)
BENCHMARK_CONCURRENCY=50 cargo run --release -- --benchmark 10000

# Java
./run.sh --benchmark 1000

# .NET (sequential - latency measurement)
dotnet run -c Release -- --benchmark 1000

# .NET (concurrent - high throughput)
BENCHMARK_CONCURRENCY=50 dotnet run -c Release -- --benchmark 10000
```

#### Node.js Client Concurrency Options

The Node.js client supports three built-in optimizations for high-throughput benchmarking:

**1. Concurrent Workers** - Automatic parallel execution
```bash
# Default: 1 worker (sequential, ~76 RPS)
npm start -- --benchmark 1000

# 25 workers (~1,900 RPS)
BENCHMARK_CONCURRENCY=25 npm start -- --benchmark 10000

# 50 workers (~3,800 RPS)
BENCHMARK_CONCURRENCY=50 npm start -- --benchmark 50000

# 100 workers (~7,600 RPS)
BENCHMARK_CONCURRENCY=100 npm start -- --benchmark 500000
```

```powershell
# Windows PowerShell
npm start -- --benchmark 1000
$env:BENCHMARK_CONCURRENCY=25; npm start -- --benchmark 10000
$env:BENCHMARK_CONCURRENCY=50; npm start -- --benchmark 50000
$env:BENCHMARK_CONCURRENCY=100; npm start -- --benchmark 500000
```

**2. HTTP Keep-Alive** - Always enabled automatically
- Connection pooling with max 100 sockets
- Eliminates TCP/TLS handshake overhead
- 2-3× improvement for HTTPS connections

**3. Configuration Options**

| Variable | Default | Description |
|----------|---------|-------------|
| `BENCHMARK_CONCURRENCY` | 1 | Number of parallel workers (1-200) |
| `SESSION_URL` | http://localhost:3001 | Identity service URL |
| `SERVER_URL` | http://localhost:3000 | API server URL |
| `CLIENT_REQUEST_TIMEOUT_MS` | 5000 | Request timeout in ms |

**Example Output:**
```
Throughput Benchmark (10000 iterations, 5 warmup, concurrency: 50)

Progress: 10000/10000 | Current RPS: 3812 | Concurrency: 50

Combined (init + purchase):
  Throughput:    3845.2 req/s (actual) | 1960.8 req/s (theoretical max)
  Latency:       Min: 18.5ms | Max: 89.2ms | Mean: 25.5ms
                 P50: 24.3ms | P95: 35.7ms | P99: 55.3ms
```

**Finding Optimal Concurrency:**
```bash
# Test different concurrency levels
for CONC in 1 10 25 50 100; do
  echo "Testing concurrency: $CONC"
  BENCHMARK_CONCURRENCY=$CONC npm start -- --benchmark 5000
  sleep 5
done
```

```powershell
# Windows PowerShell
foreach ($CONC in 1, 10, 25, 50, 100) {
  Write-Host "Testing concurrency: $CONC"
  $env:BENCHMARK_CONCURRENCY=$CONC; npm start -- --benchmark 5000
  Start-Sleep -Seconds 5
}
```

#### Go Client Concurrency Options

The Go client supports concurrent goroutine workers for high-throughput benchmarking:

**1. Concurrent Goroutine Workers** - Automatic parallel execution
```bash
# Default: 1 worker (sequential)
go run . --benchmark 1000

# 25 workers
BENCHMARK_CONCURRENCY=25 go run . --benchmark 10000

# 50 workers
BENCHMARK_CONCURRENCY=50 go run . --benchmark 50000

# 100 workers
BENCHMARK_CONCURRENCY=100 go run . --benchmark 500000
```

```powershell
# Windows PowerShell
go run . --benchmark 1000
$env:BENCHMARK_CONCURRENCY=25; go run . --benchmark 10000
$env:BENCHMARK_CONCURRENCY=50; go run . --benchmark 50000
$env:BENCHMARK_CONCURRENCY=100; go run . --benchmark 500000
```

**2. HTTP Keep-Alive** - Always enabled (Go default)
- Connection pooling with max 100 connections per host
- `MaxIdleConns`, `MaxConnsPerHost` tuned for high concurrency

**3. Configuration Options**

| Variable | Default | Description |
|----------|---------|-------------|
| `BENCHMARK_CONCURRENCY` | 1 | Number of parallel goroutine workers |
| `SESSION_URL` | http://localhost:3001 | Identity service URL |
| `SERVER_URL` | http://localhost:3000 | API server URL |

**Example Output:**
```
Throughput Benchmark (10000 iterations, 5 warmup, concurrency: 50)

Progress: 10000/10000 | Current RPS: 4200 | Concurrency: 50

Combined (init + purchase):
  Throughput:    4150.3 req/s (actual) | 2100.5 req/s (theoretical max)
  Latency:       Min: 15.2ms | Max: 78.4ms | Mean: 23.8ms
                 P50: 22.1ms | P95: 33.5ms | P99: 50.2ms
```

#### Rust Client Concurrency Options

The Rust client supports concurrent tokio task workers for high-throughput benchmarking:

**1. Concurrent Tokio Workers** - Automatic parallel execution
```bash
# Default: 1 worker (sequential)
cargo run --release -- --benchmark 1000

# 25 workers
BENCHMARK_CONCURRENCY=25 cargo run --release -- --benchmark 10000

# 50 workers
BENCHMARK_CONCURRENCY=50 cargo run --release -- --benchmark 50000

# 100 workers
BENCHMARK_CONCURRENCY=100 cargo run --release -- --benchmark 500000
```

```powershell
# Windows PowerShell
cargo run --release -- --benchmark 1000
$env:BENCHMARK_CONCURRENCY=25; cargo run --release -- --benchmark 10000
$env:BENCHMARK_CONCURRENCY=50; cargo run --release -- --benchmark 50000
$env:BENCHMARK_CONCURRENCY=100; cargo run --release -- --benchmark 500000
```

**2. HTTP Keep-Alive** - Always enabled via reqwest connection pooling
- `pool_max_idle_per_host(100)` for high concurrency
- Automatic connection reuse across workers

**3. Configuration Options**

| Variable | Default | Description |
|----------|---------|-------------|
| `BENCHMARK_CONCURRENCY` | 1 | Number of parallel tokio task workers |
| `SESSION_URL` | http://localhost:3001 | Identity service URL |
| `SERVER_URL` | http://localhost:3000 | API server URL |

**Example Output:**
```
Throughput Benchmark (10000 iterations, 5 warmup, concurrency: 50)

Progress: 10000/10000 | Current RPS: 4500 | Concurrency: 50

Combined (init + purchase):
  Throughput:    4480.1 req/s (actual) | 2250.3 req/s (theoretical max)
  Latency:       Min: 14.8ms | Max: 72.1ms | Mean: 22.2ms
                 P50: 20.5ms | P95: 31.8ms | P99: 48.7ms
```

#### .NET Client Concurrency Options

The .NET client supports concurrent Task workers for high-throughput benchmarking:

**1. Concurrent Task Workers** - Automatic parallel execution
```bash
# Default: 1 worker (sequential)
dotnet run -c Release -- --benchmark 1000

# 25 workers
BENCHMARK_CONCURRENCY=25 dotnet run -c Release -- --benchmark 10000

# 50 workers
BENCHMARK_CONCURRENCY=50 dotnet run -c Release -- --benchmark 50000

# 100 workers
BENCHMARK_CONCURRENCY=100 dotnet run -c Release -- --benchmark 500000
```

```powershell
# Windows PowerShell
dotnet run -c Release -- --benchmark 1000
$env:BENCHMARK_CONCURRENCY=25; dotnet run -c Release -- --benchmark 10000
$env:BENCHMARK_CONCURRENCY=50; dotnet run -c Release -- --benchmark 50000
$env:BENCHMARK_CONCURRENCY=100; dotnet run -c Release -- --benchmark 500000
```

**2. HTTP Keep-Alive** - Always enabled via SocketsHttpHandler
- `MaxConnectionsPerServer = 100` for high concurrency
- `PooledConnectionLifetime` and `PooledConnectionIdleTimeout` tuned

**3. Configuration Options**

| Variable | Default | Description |
|----------|---------|-------------|
| `BENCHMARK_CONCURRENCY` | 1 | Number of parallel Task workers |
| `SESSION_URL` | http://localhost:3001 | Identity service URL |
| `SERVER_URL` | http://localhost:3000 | API server URL |

**Example Output:**
```
Throughput Benchmark (10000 iterations, 5 warmup, concurrency: 50)

Progress: 10000/10000 | Current RPS: 2800 | Concurrency: 50

Combined (init + purchase):
  Throughput:    2750.5 req/s (actual) | 1400.2 req/s (theoretical max)
  Latency:       Min: 20.3ms | Max: 95.6ms | Mean: 35.7ms
                 P50: 33.2ms | P95: 48.9ms | P99: 72.1ms
```

#### Finding Optimal Concurrency (All Clients)

```bash
# Test different concurrency levels for any client
for CONC in 1 10 25 50 100; do
  echo "=== Testing concurrency: $CONC ==="

  # Node.js
  BENCHMARK_CONCURRENCY=$CONC npm start -- --benchmark 5000

  # Go
  BENCHMARK_CONCURRENCY=$CONC go run . --benchmark 5000

  # Rust
  BENCHMARK_CONCURRENCY=$CONC cargo run --release -- --benchmark 5000

  # .NET
  BENCHMARK_CONCURRENCY=$CONC dotnet run -c Release -- --benchmark 5000

  sleep 5
done
```

```powershell
# Windows PowerShell
foreach ($CONC in 1, 10, 25, 50, 100) {
  Write-Host "=== Testing concurrency: $CONC ==="

  # Node.js
  $env:BENCHMARK_CONCURRENCY=$CONC; npm start -- --benchmark 5000

  # Go
  $env:BENCHMARK_CONCURRENCY=$CONC; go run . --benchmark 5000

  # Rust
  $env:BENCHMARK_CONCURRENCY=$CONC; cargo run --release -- --benchmark 5000

  # .NET
  $env:BENCHMARK_CONCURRENCY=$CONC; dotnet run -c Release -- --benchmark 5000

  Start-Sleep -Seconds 5
}
```

### Benchmark Results

Results from concurrent benchmark testing: 10,000 iterations, 10 concurrent workers, Node.js server (Fastify) + identity-service-node.

**Test Configuration:**
- **Iterations:** 10,000 per client
- **Concurrency:** 10 parallel workers
- **Server:** Node.js (Fastify) on port 3000 + identity-service-node on port 3001
- **Infrastructure:** PostgreSQL 18 + Redis 8.0 (Docker)
- **Environment:** macOS, localhost

#### Client Performance Comparison

| Client | Combined RPS | Mean Latency | P50 | P95 | P99 | Max | Duration |
|--------|-------------|-------------|-----|-----|-----|-----|----------|
| **Go** | **3062 req/s** | 3.2ms | 3.1ms | 4.4ms | 5.6ms | 23.7ms | 3.27s |
| **Rust** | **3045 req/s** | 3.3ms | 3.1ms | 4.4ms | 5.7ms | 56.5ms | 3.28s |
| **.NET** | **2476 req/s** | 4.0ms | 3.6ms | 5.2ms | 10.4ms | 94.4ms | 4.04s |
| **Node.js** | **2362 req/s** | 4.2ms | 3.9ms | 6.1ms | 10.6ms | 63.8ms | 4.23s |

#### Endpoint Breakdown

**`/session/init` (ECDH key exchange + session creation)**

| Client | RPS | Mean | P50 | P95 | P99 |
|--------|-----|------|-----|-----|-----|
| **Go** | 3062 | 2.7ms | 2.6ms | 3.7ms | 4.8ms |
| **Rust** | 3045 | 2.7ms | 2.5ms | 3.8ms | 4.9ms |
| **.NET** | 2476 | 3.3ms | 3.0ms | 4.3ms | 8.2ms |
| **Node.js** | 2362 | 3.1ms | 2.8ms | 4.4ms | 7.9ms |

**`/transaction/purchase` (AES-256-GCM encrypt/decrypt)**

| Client | RPS | Mean | P50 | P95 | P99 |
|--------|-----|------|-----|-----|-----|
| **Go** | 3062 | 0.6ms | 0.5ms | 0.8ms | 1.3ms |
| **Rust** | 3045 | 0.6ms | 0.5ms | 0.8ms | 1.3ms |
| **.NET** | 2476 | 0.7ms | 0.6ms | 1.0ms | 2.4ms |
| **Node.js** | 2362 | 1.1ms | 1.0ms | 2.2ms | 3.4ms |

#### Client Rankings

| Rank | Client | Throughput | Notes |
|------|--------|-----------|-------|
| 1 | **Go** | **3062 req/s** | Goroutine workers, native crypto, lowest tail latency |
| 2 | **Rust** | **3045 req/s** | Tokio async, aws-lc-rs, near-identical to Go |
| 3 | **.NET** | **2476 req/s** | AesGcm reuse, ArrayPool, SocketsHttpHandler |
| 4 | **Node.js** | **2362 req/s** | Async I/O, OpenSSL bindings, highest tail latency |

#### Key Insights

- **Go and Rust** are virtually tied at ~3050 req/s with identical P50/P95 latencies
- **Go** has the best tail latency (P99: 5.6ms, Max: 23.7ms) — no GC pauses or runtime overhead
- **Rust** has occasional outliers (Max: 56.5ms) but consistent P95/P99
- **.NET** performs well at 2476 req/s, ~19% behind Go/Rust — AesGcm reuse and ArrayPool optimizations help
- **Node.js** is the slowest at 2362 req/s, ~23% behind Go/Rust — single-threaded event loop limits throughput
- **`/transaction/purchase`** is consistently sub-millisecond across all clients (0.5-1.1ms mean) — AES-GCM with cached sessions is very fast
- **`/session/init`** dominates latency (2.5-3.3ms mean) — ECDH key exchange + HKDF + PostgreSQL/Redis writes
- All clients achieve **>99% efficiency** (actual vs theoretical throughput), meaning the bottleneck is server-side, not client-side

## Development

### Stop Services

```bash
# Stop Redis and PostgreSQL
docker compose down

# Stop server
# Ctrl+C in server terminal
```

### View Redis Data

```bash
# Connect to Redis CLI
docker exec -it session-crypto-redis redis-cli

# List all keys
KEYS *

# Get session data
GET sess:S-<sessionId>

# Check TTL
TTL sess:S-<sessionId>
```

### View PostgreSQL Data

```bash
# Connect to PostgreSQL
docker exec -it session-crypto-postgres psql -U postgres -d session_crypto

# List sessions
SELECT session_id, expires_at FROM sessions;

# View session data
SELECT * FROM sessions WHERE session_id = 'S-<sessionId>';
```

## Negative Tests

Run the Node negative test suite:

```bash
cd client/node
npm run test:negative
```

### Redis Down Fallback Test

Start the server with Redis unavailable, then run tests with the Redis-down expectation:

```bash
# Terminal 1: start server with bad Redis port
cd server
REDIS_PORT=6390 npm run dev

# Terminal 2: run tests
cd client/node
EXPECT_REDIS_DOWN=1 npm run test:negative
```

### Memory Nonce Capacity Test

Run the capacity-only test with lowered memory limits (Redis must be down so the in-memory store is used):

```bash
# Terminal 1: start server with Redis down and low memory limits
cd server
REDIS_PORT=6390 MEMORY_NONCE_MAX_SIZE=1000 MEMORY_NONCE_CLEANUP_THRESHOLD=900 NONCE_TTL_SEC=600 npm run dev

# Terminal 2: run capacity-only test
cd client/node
RUN_CAPACITY_ONLY=1 EXPECT_CAPACITY_EXCEEDED=1 CAPACITY_TEST_ATTEMPTS=1100 npm run test:negative
```
