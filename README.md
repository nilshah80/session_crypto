# Session Crypto PoC

A proof-of-concept implementation of the session-based encryption design using ECDH key agreement and AES-256-GCM encryption.

## Architecture

```
┌─────────────────┐         ┌─────────────────┐         ┌─────────────────┐
│     Client      │         │     Server      │         │     Redis       │
│  (Multi-lang)   │         │   (Fastify)     │         │   (Sessions)    │
└────────┬────────┘         └────────┬────────┘         └────────┬────────┘
         │                           │                           │
         │  POST /session/init       │                           │
         │  + clientPublicKey        │                           │
         ├──────────────────────────►│                           │
         │                           │  Generate serverKeypair   │
         │                           │  sharedSecret = ECDH      │
         │                           │  sessionKey = HKDF        │
         │                           │  Store session ──────────►│
         │  sessionId                │                           │
         │  + serverPublicKey        │                           │
         │◄──────────────────────────┤                           │
         │                           │                           │
         │  Derive sessionKey        │                           │
         │                           │                           │
         │  POST /transaction/purchase                           │
         │  [encrypted with sessionKey]                          │
         ├──────────────────────────►│                           │
         │                           │  Lookup session ◄─────────│
         │                           │  Verify nonce ◄───────────│
         │                           │  Decrypt & process        │
         │  [encrypted response]     │                           │
         │◄──────────────────────────┤                           │
         │                           │                           │
         │  Decrypt response         │                           │
         └───────────────────────────┘                           │
```

## Prerequisites

- **Server**: Node.js 20+, Docker (for Redis)
- **Clients** (any one):
  - Node.js 20+
  - .NET 10.0
  - Java 25
  - Go 1.25+
  - Rust 1.92+

## Quick Start

### 1. Start Redis

```bash
docker compose up -d
```

### 2. Start the Server

```bash
cd server
npm install
npm run dev
```

Server will start on `http://localhost:3000`

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
```

## Client Implementations

| Language | Directory | Version | Pattern |
|----------|-----------|---------|---------|
| Node.js | `client/node/` | Node 20+ | Async/await |
| .NET C# | `client/dotnet/` | .NET 10.0 | Async/await |
| Java | `client/java-virtual-threads/` | Java 25 | Virtual Threads |
| Java | `client/java-webflux/` | Java 25 | CompletableFuture |
| Go | `client/go/` | Go 1.25 | Goroutines |
| Rust | `client/rust/` | Rust 1.92 | Tokio async |

All clients implement the same encryption flow and produce identical outputs.

## Endpoints

### `POST /session/init`

Initialize an authenticated encryption session.

**Headers:**
- `X-Nonce: <uuid>` - Unique request nonce
- `X-Timestamp: <epoch_ms>` - Request timestamp

**Request Body:**
```json
{
  "keyAgreement": "ECDH_P256",
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
- `X-Kid: session:<sessionId>`
- `X-Enc-Alg: A256GCM`
- `X-IV: <base64>` (12 bytes)
- `X-Tag: <base64>` (16 bytes)
- `X-AAD: <base64>`
- `X-Nonce: <uuid>`
- `X-Timestamp: <epoch_ms>`

**Request Body:** Base64-encoded ciphertext

**Response:** Same header pattern with encrypted response body

### `GET /health`

Health check endpoint.

**Response:**
```json
{
  "status": "ok",
  "timestamp": "2026-01-18T12:00:00.000Z",
  "redis": "ok"
}
```

## Crypto Details

- **Key Agreement:** ECDH with P-256 curve
- **Key Derivation:** HKDF-SHA256
- **Encryption:** AES-256-GCM
- **IV:** 12 bytes (96 bits), randomly generated per message
- **Auth Tag:** 16 bytes (128 bits)
- **AAD Format:** `METHOD|PATH|TIMESTAMP|NONCE|KID`

## Security Features

- Replay protection via Redis (nonce uniqueness + timestamp window)
- Public key validation (point on curve)
- 128-bit session ID entropy
- AAD binding (method, path, timestamp, nonce, session)
- Generic error responses (prevents oracle attacks)
- Session TTL enforcement

## Redis Schema

```
sess:<sessionId>   → {key, type, expiresAt, principal}   TTL: 1800s (auth) / 120s (anon)
nonce:<uuid>       → "1"                                  TTL: 300s
```

## Project Structure

```
session_crypto/
├── docker-compose.yml          # Redis 8 container
├── server/
│   ├── src/
│   │   ├── index.ts            # Fastify server with endpoints
│   │   ├── crypto-helpers.ts   # ECDH, HKDF, AES-GCM, replay protection
│   │   └── session-store.ts    # Redis session storage
│   ├── package.json
│   └── tsconfig.json
├── client/
│   ├── node/                   # Node.js reference client
│   ├── dotnet/                 # .NET 10 client
│   ├── java-virtual-threads/   # Java 25 with Virtual Threads
│   ├── java-webflux/           # Java 25 with CompletableFuture
│   ├── go/                     # Go 1.25 client
│   └── rust/                   # Rust 1.92 client
├── session-init-design.md      # Full design document
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

All benchmarks run on local machine with Redis. Results at 1000 iterations (after 5 warmup):

#### Combined Flow Throughput (init + purchase)

| Client | Throughput | Mean Latency | P50 | P95 | P99 |
|--------|------------|--------------|-----|-----|-----|
| Go | 781.1 req/s | 1.3ms | 1.2ms | 1.9ms | 2.5ms |
| Rust | 576.2 req/s | 1.7ms | 1.6ms | 2.8ms | 3.6ms |
| Node.js | 533.6 req/s | 1.9ms | 1.7ms | 2.6ms | 3.2ms |
| .NET | 411.8 req/s | 2.4ms | 2.3ms | 3.9ms | 5.0ms |
| Java Virtual Threads | 321.9 req/s | 3.1ms | 2.7ms | 5.2ms | 6.6ms |
| Java WebFlux | 271.1 req/s | 3.7ms | 3.5ms | 5.4ms | 6.6ms |

#### /session/init Endpoint

| Client | Throughput | Mean Latency | P50 | P95 | P99 |
|--------|------------|--------------|-----|-----|-----|
| Go | 1377.0 req/s | 0.7ms | 0.7ms | 0.9ms | 1.8ms |
| Rust | 1021.4 req/s | 1.0ms | 0.9ms | 1.6ms | 2.1ms |
| Node.js | 954.6 req/s | 1.0ms | 1.0ms | 1.6ms | 1.9ms |
| .NET | 666.7 req/s | 1.5ms | 1.4ms | 2.3ms | 3.0ms |
| Java Virtual Threads | 529.6 req/s | 1.9ms | 1.7ms | 3.1ms | 4.4ms |
| Java WebFlux | 452.9 req/s | 2.2ms | 2.1ms | 3.3ms | 4.1ms |

#### /transaction/purchase Endpoint

| Client | Throughput | Mean Latency | P50 | P95 | P99 |
|--------|------------|--------------|-----|-----|-----|
| Go | 1808.0 req/s | 0.6ms | 0.5ms | 0.7ms | 1.5ms |
| Rust | 1323.2 req/s | 0.8ms | 0.7ms | 1.3ms | 2.0ms |
| Node.js | 1212.3 req/s | 0.8ms | 0.8ms | 1.2ms | 1.9ms |
| .NET | 1081.1 req/s | 0.9ms | 0.8ms | 1.7ms | 2.4ms |
| Java Virtual Threads | 822.1 req/s | 1.2ms | 1.0ms | 2.3ms | 3.0ms |
| Java WebFlux | 679.5 req/s | 1.5ms | 1.3ms | 2.4ms | 3.2ms |

#### Scaling Behavior (10000 iterations)

| Client | Combined Throughput | Combined Mean Latency | Combined P99 |
|--------|---------------------|----------------------|--------------|
| Go | 819.9 req/s | 1.2ms | 2.3ms |
| Rust | 772.2 req/s | 1.3ms | 2.6ms |
| Node.js | 553.6 req/s | 1.8ms | 4.7ms |
| .NET | 425.1 req/s | 2.4ms | 5.6ms |
| Java Virtual Threads | 294.3 req/s | 3.4ms | 6.4ms |
| Java WebFlux | 290.6 req/s | 3.4ms | 6.4ms |

**Notes:**
- Go and Rust show best performance (~800 req/s at 10k iterations)
- Rust uses `aws-lc-rs` crate (AWS LibCrypto) for optimized crypto - within 6% of Go
- Node.js follows at ~550 req/s at scale
- .NET improved after HttpClient connection pooling fix (~425 req/s)
- Go benefits from efficient goroutines and optimized crypto implementation
- Java clients show consistent performance with JIT warmup
- P99 tail latency stays under 6ms for all implementations

### Server Benchmarks

Server-side performance measured using `wrk` and the fastest client (Go):

#### Raw HTTP Performance (wrk)

| Endpoint | Connections | Throughput | Mean Latency | Max Latency |
|----------|-------------|------------|--------------|-------------|
| /health | 100 | 52,091 req/s | 2.08ms | 119ms |
| /session/init | 10 | 4,375 req/s | 2.28ms | 7.6ms |
| /session/init | 50 | 5,073 req/s | 9.45ms | 30ms |
| /session/init | 100 | 4,984 req/s | 20.9ms | 333ms |

#### End-to-End Crypto Flow (Go client, 5000 iterations)

| Endpoint | Throughput | Mean Latency | P50 | P95 | P99 |
|----------|------------|--------------|-----|-----|-----|
| /session/init | 1,416 req/s | 0.7ms | 0.7ms | 0.9ms | 1.7ms |
| /transaction/purchase | 1,892 req/s | 0.5ms | 0.5ms | 0.7ms | 1.5ms |
| Combined flow | 809 req/s | 1.2ms | 1.1ms | 1.9ms | 2.4ms |

**Server Performance Notes:**
- Raw HTTP baseline: ~52k req/s on /health (no crypto, no Redis)
- Session init with ECDH + HKDF + Redis: ~5k req/s (10x overhead from crypto)
- Encrypted transaction: ~1.9k req/s per client connection
- Server can handle ~800 complete flows/second (init + encrypted request)
- Bottleneck is ECDH key generation (~0.2ms per operation)

## Development

### Stop Services

```bash
# Stop Redis
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
