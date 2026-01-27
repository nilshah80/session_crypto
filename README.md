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
# Node.js
cd client/node
npm install
npm start

# .NET
cd client/dotnet/SessionCryptoClient
dotnet run

# Java (Virtual Threads)
cd client/java-virtual-threads
./run.sh

# Java (WebFlux-style with Project Reactor - Properly Reactive)
cd client/java-webflux
./run.sh

# Go
cd client/go
go run .

# Rust
cd client/rust
cargo run

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
cd client/dotnet/SessionCryptoClient && dotnet run
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
# Node.js
npm run start -- --benchmark 1000

# Go
go run . --benchmark 1000

# Rust
cargo run --release -- --benchmark 1000

# Java
./run.sh --benchmark 1000

# .NET
dotnet run -- --benchmark 1000
```

### Benchmark Results

Results from comprehensive cross-platform testing: 6 servers × 6 clients, 1000 iterations × 5 runs each, Release/Production mode.

#### Server Performance Matrix (Combined init + purchase throughput in req/s)

| Client \ Server | .NET | Node.js | Go | Rust (aws-lc-rs) | Rust-ring | Rust-native |
|-----------------|------|---------|-----|------------------|-----------|-------------|
| **Go** | ~525 | ~1133 | ~1285 | **~1505** | ~1478 | ~929 |
| **Rust** | ~555 | ~1083 | ~1290 | ~1482 | **~1502** | ~938 |
| **Node.js** | ~290 | ~645 | ~655 | ~873 | **~901** | ~620 |
| **.NET** | ~345 | ~585 | ~574 | ~682 | **~698** | ~558 |
| **Java VT** | ~286 | ~417 | ~403 | **~484** | ~458 | ~347 |
| **Java WebFlux** | ~269 | ~427 | ~390 | **~480** | ~459 | ~344 |

#### Server Performance Rankings

| Rank | Server | Peak Throughput | Crypto Library | Notes |
|------|--------|-----------------|----------------|-------|
| 🥇 1 | **Rust (aws-lc-rs)** | **1505 req/s** | aws-lc-rs | AWS LibCrypto, hardware-accelerated |
| 🥈 2 | **Rust-ring** | **1502 req/s** | ring | BoringSSL-derived, excellent performance |
| 🥉 3 | **Go** | **1290 req/s** | crypto/ecdh | Standard library, very efficient |
| 4 | **Node.js** | **1133 req/s** | Node crypto | OpenSSL bindings, good performance |
| 5 | **Rust-native** | **938 req/s** | RustCrypto | Pure Rust, no hardware acceleration |
| 6 | **.NET** | **555 req/s** | System.Security | Framework overhead, room for improvement |

#### Client Performance Rankings

| Rank | Client | Best Throughput | Notes |
|------|--------|-----------------|-------|
| 🥇 1 | **Go** | **1505 req/s** | Excellent HTTP client, native crypto |
| 🥈 2 | **Rust** | **1502 req/s** | Tokio async runtime, aws-lc-rs |
| 🥉 3 | **Node.js** | **901 req/s** | Async I/O, OpenSSL bindings |
| 4 | **.NET** | **698 req/s** | HttpClient with connection pooling |
| 5 | **Java VT** | **484 req/s** | Virtual threads, JCA crypto |
| 6 | **Java WebFlux** | **480 req/s** | Project Reactor, JCA crypto |

#### Key Insights

**Best Combinations:**
- 🏆 **Go/Rust client + Rust (aws-lc-rs) server** → **~1500+ req/s**
- **Go/Rust client + Go server** → **~1285-1290 req/s**
- **Node.js client + Rust servers** → **~900 req/s**

**Performance Analysis:**
- **Rust-native vs aws-lc-rs**: Pure RustCrypto is ~35% slower due to lack of hardware acceleration (AES-NI, CLMUL)
- **.NET server**: Lowest throughput, likely due to ASP.NET Core middleware overhead
- **Java clients**: Bottlenecked by JVM crypto operations; ACCP can improve this significantly
- **Go**: Consistently excellent performance with minimal optimization needed

#### Optimization Techniques

**Rust Servers:**
1. **aws-lc-rs / ring** - Hardware-accelerated AES-GCM and ECDH
2. **Tokio runtime** - Efficient async I/O
3. **Connection pooling** - Redis and PostgreSQL with timeouts
4. **Zeroization** - Secure memory handling with `zeroize` crate

**Go Server:**
1. **crypto/ecdh** - Native P-256 support
2. **Connection pooling** - Optimized Redis/PostgreSQL pools
3. **Timeouts** - Read/Write/Idle timeouts on HTTP server
4. **clearBytes()** - Secure memory clearing

**Node.js Server:**
1. **Cipher Instance Cache** - Reuse AES-GCM cipher instances
2. **Buffer Pool for IV** - Pre-allocated IV buffers
3. **Pre-allocated Result Buffers** - Avoid Buffer.concat() overhead
4. **Automatic Cache Cleanup** - TTL-based eviction

**.NET Server:**
1. **AesGcm Instance Cache** - ConcurrentDictionary with cleanup
2. **ArrayPool<byte>** - All buffer allocations from pool
3. **Connection Pool Tuning** - Optimized pool sizes

**Client Optimizations:**
- **Go/Rust**: Native crypto, minimal overhead
- **Node.js**: Cipher caching, buffer pooling
- **.NET**: AesGcm reuse, ArrayPool, SocketsHttpHandler
- **Java**: ACCP provider, Cipher instance reuse, ThreadLocal pools

#### Running Comprehensive Benchmarks

Use the included benchmark script to test all server/client combinations:

```bash
# Run full benchmark suite (default 1000 iterations, 5 runs)
./benchmark.sh

# Custom iterations
./benchmark.sh 500

# Results saved to benchmark_results_YYYYMMDD_HHMMSS.txt
```

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
