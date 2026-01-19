# Session Crypto PoC

A proof-of-concept implementation of the session-based encryption design using ECDH key agreement and AES-256-GCM encryption.

## Architecture

```
┌─────────────────┐         ┌─────────────────┐         ┌─────────────────┐
│     Client      │         │     Server      │         │     Redis       │
│  (Multi-lang)   │         │  (Multi-lang)   │         │   (Sessions)    │
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

- **Server** (any one): Node.js 20+, Go 1.25+, or Rust 1.92+
- **Infrastructure**: Docker (for Redis)
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

### 2. Start a Server

Choose any server implementation:

```bash
# Node.js (Fastify)
cd server
npm install
npm run dev

# Go (Chi router)
cd server-go
go build -o server-go .
./server-go

# Rust (Axum)
cd server-rust
cargo build --release
./target/release/session-crypto-server
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
| Node.js | `client/node/` | Node 20+ | Async/await |
| .NET C# | `client/dotnet/` | .NET 10.0 | Async/await |
| Java | `client/java-virtual-threads/` | Java 25 | Virtual Threads |
| Java | `client/java-webflux/` | Java 25 | CompletableFuture |
| Go | `client/go/` | Go 1.25 | Goroutines |
| Rust | `client/rust/` | Rust 1.92 | Tokio async |

### Browser SPA Clients

| Framework | Directory | Version | Notes |
|-----------|-----------|---------|-------|
| Angular | `client/angular-spa/` | Angular 19 | Single-SPA, Web Crypto API |
| React | `client/react-spa/` | React 19 | Single-SPA, Web Crypto API |

All clients implement the same encryption flow and produce identical outputs.

## Server Implementations

| Language | Directory | Framework | Pattern |
|----------|-----------|-----------|---------|
| Node.js | `server/` | Fastify | Async/await |
| Go | `server-go/` | Chi | Goroutines |
| Rust | `server-rust/` | Axum | Tokio async |

All servers implement identical endpoints and crypto operations.

## Endpoints

### `POST /session/init`

Initialize an authenticated encryption session.

**Headers:**
- `X-Nonce: <uuid>` - Unique request nonce
- `X-Timestamp: <epoch_ms>` - Request timestamp
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
- `X-Kid: session:<sessionId>`
- `X-Enc-Alg: A256GCM`
- `X-IV: <base64>` (12 bytes)
- `X-Tag: <base64>` (16 bytes)
- `X-AAD: <base64>`
- `X-Nonce: <uuid>`
- `X-Timestamp: <epoch_ms>`
- `X-ClientId: <client_id>`

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
  - Salt: Session ID
  - Info: `SESSION|A256GCM|<clientId>`
- **Encryption:** AES-256-GCM
- **IV:** 12 bytes (96 bits), randomly generated per message
- **Auth Tag:** 16 bytes (128 bits)
- **AAD Format:** `TIMESTAMP|NONCE|KID|CLIENTID`

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
├── server/                     # Node.js server (Fastify)
│   ├── src/
│   │   ├── index.ts            # Server with endpoints
│   │   ├── crypto-helpers.ts   # ECDH, HKDF, AES-GCM, replay protection
│   │   ├── session-store.ts    # Redis session storage
│   │   └── metrics.ts          # Server-Timing header support
│   ├── package.json
│   └── tsconfig.json
├── server-go/                  # Go server (Chi)
│   ├── main.go                 # All-in-one server implementation
│   └── go.mod
├── server-rust/                # Rust server (Axum)
│   ├── src/main.rs             # All-in-one server implementation
│   └── Cargo.toml
├── client/
│   ├── node/                   # Node.js reference client
│   ├── dotnet/                 # .NET 10 client
│   ├── java-virtual-threads/   # Java 25 with Virtual Threads
│   ├── java-webflux/           # Java 25 with CompletableFuture
│   ├── go/                     # Go 1.25 client
│   ├── rust/                   # Rust 1.92 client
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

All benchmarks run on Apple M4 Max with local Redis. Results at 1000 iterations (after 5 warmup).

#### Server Comparison (Combined Flow Throughput in req/s)

| Client \ Server | Node.js | Go | Rust |
|-----------------|---------|-----|------|
| **Go** | 768.5 | **945.3** | 923.4 |
| **Rust** | 773.2 | 903.9 | **921.2** |
| **Node.js** | 427.6 | 597.1 | **631.5** |
| **.NET** | 362.3 | 464.3 | **521.9** |
| **Java VT** | 330.0 | **404.8** | 330.3 |
| **Java WebFlux** | 311.0 | **369.1** | 343.7 |

**Key Findings:**
- Go server is fastest overall (~945 req/s with Go/Rust clients)
- Rust server very close to Go (~921 req/s), best for Node.js/.NET clients
- Go/Rust servers provide 20-48% improvement over Node.js server

#### Detailed Results by Server

**Node.js Server (Fastify):**

| Client | /session/init | /transaction/purchase | Combined |
|--------|---------------|----------------------|----------|
| Go | 1365.2 req/s | 1760.7 req/s | 768.5 req/s |
| Rust | 1367.2 req/s | 1781.6 req/s | 773.2 req/s |
| Node.js | 780.3 req/s | 947.7 req/s | 427.6 req/s |
| .NET | 598.5 req/s | 920.9 req/s | 362.3 req/s |
| Java VT | 543.5 req/s | 841.5 req/s | 330.0 req/s |
| Java WebFlux | 510.4 req/s | 803.3 req/s | 311.0 req/s |

**Go Server (Chi):**

| Client | /session/init | /transaction/purchase | Combined |
|--------|---------------|----------------------|----------|
| Go | 1775.6 req/s | 2024.9 req/s | **945.3 req/s** |
| Rust | 1698.0 req/s | 1935.5 req/s | 903.9 req/s |
| Node.js | 1128.7 req/s | 1270.1 req/s | 597.1 req/s |
| .NET | 781.2 req/s | 1148.0 req/s | 464.3 req/s |
| Java VT | 668.5 req/s | 1028.4 req/s | 404.8 req/s |
| Java WebFlux | 616.6 req/s | 926.8 req/s | 369.1 req/s |

**Rust Server (Axum):**

| Client | /session/init | /transaction/purchase | Combined |
|--------|---------------|----------------------|----------|
| Go | 1721.9 req/s | 1994.4 req/s | 923.4 req/s |
| Rust | 1711.9 req/s | 1997.4 req/s | **921.2 req/s** |
| Node.js | 1191.1 req/s | 1346.4 req/s | 631.5 req/s |
| .NET | 866.6 req/s | 1316.5 req/s | 521.9 req/s |
| Java VT | 553.7 req/s | 819.6 req/s | 330.3 req/s |
| Java WebFlux | 576.6 req/s | 856.7 req/s | 343.7 req/s |

#### Server Speed Improvement vs Node.js

| Client | Go Server | Rust Server |
|--------|-----------|-------------|
| Go | +23% | +20% |
| Rust | +17% | +19% |
| Node.js | +40% | +48% |
| .NET | +28% | +44% |
| Java VT | +23% | 0% |
| Java WebFlux | +19% | +11% |

#### Client Performance Ranking

| Rank | Client | Best Throughput | Notes |
|------|--------|-----------------|-------|
| 1 | Go | 945.3 req/s | Fastest with Go server |
| 2 | Rust | 921.2 req/s | Uses aws-lc-rs (AWS LibCrypto) |
| 3 | Node.js | 631.5 req/s | Best with Rust server |
| 4 | .NET | 521.9 req/s | Best with Rust server |
| 5 | Java VT | 404.8 req/s | Best with Go server |
| 6 | Java WebFlux | 369.1 req/s | Best with Go server |

**Notes:**
- Go and Rust clients show nearly identical performance (~900-950 req/s)
- Go server excels with Go/Rust clients due to efficient goroutines
- Rust server provides best performance for Node.js and .NET clients
- Java clients perform consistently across all servers (~300-400 req/s)
- All implementations stay under 3ms P50 latency

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
