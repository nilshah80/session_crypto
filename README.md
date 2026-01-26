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
cd server-dotnet
dotnet run
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
│   ├── Program.cs
│   └── SessionCryptoServer.csproj
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

Results at 1000 iterations (after 5 warmup) with local Redis and PostgreSQL.

#### Optimized .NET Server + Optimized Clients (Combined Flow)

**Peak Performance Rankings:**

| Rank | Client Implementation | Peak Throughput | Transaction Speed | Key Optimizations |
|------|----------------------|-----------------|-------------------|-------------------|
| 🥇 1 | **Java VT (ACCP)** | **105.9 req/s** | 361.6 req/s | ACCP, Cipher reuse, ThreadLocal pools |
| 🥈 2 | **.NET (Optimized)** | **103.7 req/s** | **613.8 req/s** ⭐ | AesGcm reuse, ArrayPool, Pre-warming |
| 🥉 3 | **Java WebFlux Reactive** | **101.3 req/s** | 425.3 req/s | ACCP, Reactor Mono/Flux, Cipher reuse |

**All three implementations achieve world-class performance within 5% of each other!**

#### Optimization Impact (Before → After)

**Java Virtual Threads:**
- Before (JCA): 91.0 req/s
- After (ACCP + Optimizations): **105.9 req/s** (+16.4%)

**Java WebFlux:**
- Before (CompletableFuture + JCA): 32.8 req/s
- After (Proper Reactor + ACCP): **101.3 req/s** (+209%)

**.NET Client:**
- Before (Basic): 51.0 req/s (first run)
- After (Optimized): **103.7 req/s** (+103%)

**.NET Server:**
- Before: ~90 req/s average
- After (AesGcm cache + ArrayPool): **103.7 req/s** (+15%)

**Node.js Server + Client:**
- Before: 125.7 req/s (baseline)
- After (Cipher cache + Buffer pooling): **131.1 req/s** (+4.3%)

#### Detailed Breakdown - Java VT (ACCP) - Peak Run

**Session Init:**
- Throughput: 123.8 req/s
- Latency: Min 5.9ms | Mean 8.1ms | P99 13.8ms

**Transaction:**
- Throughput: 361.6 req/s
- Latency: Min 1.5ms | Mean 2.8ms | P99 5.2ms

**Combined Flow:**
- Throughput: **105.9 req/s**
- Latency: Min 7.7ms | Mean 9.4ms | P99 18.5ms

#### Detailed Breakdown - .NET (Optimized) - Peak Run

**Session Init:**
- Throughput: 123.4 req/s
- Latency: Min 6.0ms | Mean 8.1ms | P99 14.2ms

**Transaction:**
- Throughput: **613.8 req/s** ⭐ (World-class)
- Latency: Min 0.9ms | Mean 1.6ms | P99 3.4ms

**Combined Flow:**
- Throughput: **103.7 req/s**
- Latency: Min 7.8ms | Mean 9.6ms | P99 16.6ms

#### Detailed Breakdown - Java WebFlux Reactive - Peak Run

**Session Init:**
- Throughput: 136.5 req/s
- Latency: Min 5.7ms | Mean 7.3ms | P99 14.2ms

**Transaction:**
- Throughput: 425.3 req/s
- Latency: Min 1.4ms | Mean 2.4ms | P99 5.6ms

**Combined Flow:**
- Throughput: **101.3 req/s**
- Latency: Min 7.3ms | Mean 9.9ms | P99 20.6ms

#### Detailed Breakdown - Node.js (Optimized) - Peak Run

**Session Init:**
- Throughput: 177.6 req/s
- Latency: Min 4.8ms | Mean 5.6ms | P99 7.5ms

**Transaction:**
- Throughput: 501.9 req/s
- Latency: Min 1.4ms | Mean 2.0ms | P99 3.0ms

**Combined Flow:**
- Throughput: **131.1 req/s**
- Latency: Min 6.2ms | Mean 7.6ms | P99 10.3ms

Note: Tested with optimized Node.js server (vs .NET server for other clients)

#### Key Optimization Techniques

**Java Clients (Both VT and WebFlux):**
1. **Amazon Corretto Crypto Provider (ACCP)** - Native AWS LibCrypto implementation
   - 10-50x faster than standard JCA
   - Zero-copy operations where possible
2. **Cipher Instance Reuse** - SessionContext caches Cipher objects per session
3. **ThreadLocal Buffer Pools** - Reduces GC pressure for IV and temporary buffers
4. **Crypto Pre-warming** - Eliminates first-call JIT penalty
5. **Proper Reactive Patterns** (WebFlux only) - Project Reactor with Mono/Flux instead of CompletableFuture

**.NET Client:**
1. **AesGcm Instance Reuse** - OptimizedSessionContext caches AesGcm per session
2. **ArrayPool<byte>** - All temporary buffers use pooling
3. **SocketsHttpHandler** - Connection pooling with optimized settings
4. **Crypto Pre-warming** - First-call overhead eliminated
5. **Optimized AAD Construction** - Pre-calculated byte arrays

**.NET Server:**
1. **AesGcm Instance Cache** - ConcurrentDictionary with automatic cleanup
2. **ArrayPool for All Buffers** - IV, tag, ciphertext, request body
3. **Fixed Double Base64 Decode Bug** - Eliminated duplicate conversion
4. **Connection Pool Tuning** - Reduced from 100 to 20 (optimal)

**Node.js Server:**
1. **Cipher Instance Cache** - Map with timestamp-based cleanup every 5 minutes
2. **Buffer Pool for IV** - Simple array pool with max 100 buffers
3. **Optimized Buffer Operations** - Pre-allocated buffers instead of Buffer.concat()
4. **Automatic Cache Cleanup** - Size limit (1000 entries) + TTL-based eviction

**Node.js Client:**
1. **Cipher Instance Cache** - Same caching strategy as server
2. **Buffer Pooling** - IV buffer reuse to reduce GC pressure
3. **Pre-allocated Result Buffers** - Eliminates intermediate Buffer.concat() calls
4. **Optimized AAD Construction** - Efficient string-to-buffer conversion

#### Pre-Optimization Baseline (Historical)

| Client | Throughput | Notes |
|--------|------------|-------|
| Rust | 141.2 req/s | Uses aws-lc-rs (AWS LibCrypto) |
| Node.js | 125.7 req/s → **131.1 req/s** | Baseline → Optimized (+4.3%) |
| Go | 104.0 req/s | crypto/ecdh |
| Java VT (JCA) | 91.0 req/s | Standard JCA (before ACCP) |
| .NET (Basic) | 51.0 req/s | First run (before optimizations) |
| Java WebFlux (Old) | 32.8 req/s | CompletableFuture (before reactive refactor) |

**After full optimization, Java and .NET clients now match or exceed Go performance, while Node.js shows steady improvement with cipher caching and buffer pooling!**

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
