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

# Java (WebFlux-style with CompletableFuture)
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

| Language | Directory | Version | Pattern |
|----------|-----------|---------|---------|
| Node.js | `client/node/` | Node 24+ | Async/await |
| .NET C# | `client/dotnet/` | .NET 10.0 | Async/await |
| Java | `client/java-virtual-threads/` | Java 25 | Virtual Threads |
| Java | `client/java-webflux/` | Java 25 | CompletableFuture |
| Go | `client/go/` | Go 1.25+ | Goroutines |
| Rust | `client/rust/` | Rust 1.93+ | Tokio async |

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

#### .NET Server Benchmark (Combined Flow)

| Client | Throughput | Mean Latency | P50 | P95 | P99 |
|--------|------------|--------------|-----|-----|-----|
| **Rust** | **141.2 req/s** | 7.1ms | 6.8ms | 8.9ms | 11.4ms |
| **Node.js** | 125.7 req/s | 8.0ms | 7.8ms | 9.4ms | 11.2ms |
| **.NET** | 107.9 req/s | 9.3ms | 8.9ms | 10.8ms | 17.8ms |
| **Go** | 104.0 req/s | 9.6ms | 9.5ms | 12.6ms | 16.9ms |

#### .NET Server - Endpoint Breakdown

**Session Init (`/session/init`):**

| Client | Throughput | Mean Latency | P99 |
|--------|------------|--------------|-----|
| **Rust** | 165.0 req/s | 6.1ms | 9.9ms |
| **Node.js** | 154.5 req/s | 6.5ms | 9.4ms |
| **Go** | 137.8 req/s | 7.3ms | 14.3ms |
| **.NET** | 123.4 req/s | 8.1ms | 16.4ms |

**Transaction (`/transaction/purchase`):**

| Client | Throughput | Mean Latency | P99 |
|--------|------------|--------------|-----|
| **Rust** | 982.1 req/s | 1.0ms | 1.7ms |
| **.NET** | 920.0 req/s | 1.1ms | 2.4ms |
| **Node.js** | 677.7 req/s | 1.5ms | 2.7ms |
| **Go** | 426.2 req/s | 2.3ms | 4.3ms |

#### Client Performance Ranking

| Rank | Client | Best Throughput | Notes |
|------|--------|-----------------|-------|
| 1 | Rust | 141.2 req/s | Uses aws-lc-rs (AWS LibCrypto) |
| 2 | Node.js | 125.7 req/s | tsx runtime |
| 3 | .NET | 107.9 req/s | System.Security.Cryptography |
| 4 | Go | 104.0 req/s | crypto/ecdh |

**Notes:**
- Rust client achieves ~982 req/s on transaction endpoint
- Session init is slower due to ECDH key generation and database writes
- All clients maintain sub-18ms P99 latency

#### Why Java Clients Are Slower

Java crypto operations through JCA (Java Cryptography Architecture) are significantly slower than native implementations:

| Operation | Go | Java (JCA) | Slowdown |
|-----------|-----|------------|----------|
| ECDH keygen | 0.03ms | ~1ms* | ~33x |
| ECDH compute | 0.04ms | ~1.3ms | ~32x |
| AES-GCM | 0.002ms | ~0.3ms | ~150x |

*First call ~16ms due to JIT warmup and provider initialization

This is a known limitation of JCA. For better Java crypto performance, consider:
- Amazon Corretto Crypto Provider (ACCP) - native crypto for AWS environments
- BouncyCastle with native provider
- GraalVM native image compilation

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
