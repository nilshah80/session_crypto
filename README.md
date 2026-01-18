# Session Crypto PoC

A proof-of-concept implementation of the session-based encryption design using ECDH key agreement and AES-256-GCM encryption.

## Architecture

```
┌─────────────────┐         ┌─────────────────┐
│     Client      │         │     Server      │
│  (Node.js)      │         │   (Fastify)     │
└────────┬────────┘         └────────┬────────┘
         │                           │
         │  POST /session/init       │
         │  + clientPublicKey        │
         ├──────────────────────────►│
         │                           │  Generate serverKeypair
         │                           │  sharedSecret = ECDH(serverPriv, clientPub)
         │                           │  sessionKey = HKDF(sharedSecret, sessionId)
         │  sessionId                │  Store sessionKey in memory
         │  + serverPublicKey        │
         │◄──────────────────────────┤
         │                           │
         │  sharedSecret = ECDH(clientPriv, serverPub)
         │  sessionKey = HKDF(sharedSecret, sessionId)
         │                           │
         │  POST /transaction/purchase│
         │  [encrypted with sessionKey]
         ├──────────────────────────►│
         │                           │  Lookup sessionKey
         │                           │  Decrypt request
         │                           │  Process business logic
         │  [encrypted response]     │  Encrypt response
         │◄──────────────────────────┤
         │                           │
         │  Decrypt response         │
         │  Display result           │
         └───────────────────────────┘
```

## Prerequisites

- Node.js 20+ (for native fetch support)
- npm or pnpm

## Quick Start

### 1. Start the Server

```bash
cd server
npm install
npm run dev
```

Server will start on `http://localhost:3000`

### 2. Run the Client

In a new terminal:

```bash
cd client/node
npm install
npm start
```

## Endpoints

### `POST /session/init`

Initialize an authenticated encryption session.

**Headers:**
- `Authorization: Bearer <token>` - Access token
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
- `Authorization: Bearer <token>`
- `X-Kid: session:<sessionId>`
- `X-Enc-Alg: A256GCM`
- `X-IV: <base64>` (12 bytes)
- `X-Tag: <base64>` (16 bytes)
- `X-AAD: <base64>`
- `X-Nonce: <uuid>`
- `X-Timestamp: <epoch_ms>`

**Request Body:** Base64-encoded ciphertext

**Response:** Same header pattern with encrypted response body

## Crypto Details

- **Key Agreement:** ECDH with P-256 curve
- **Key Derivation:** HKDF-SHA256
- **Encryption:** AES-256-GCM
- **IV:** 12 bytes (96 bits), randomly generated per message
- **Auth Tag:** 16 bytes (128 bits)
- **AAD Format:** `METHOD|PATH|TIMESTAMP|NONCE|KID`

## Security Features

- ✅ Replay protection (nonce + timestamp window)
- ✅ Public key validation (point on curve)
- ✅ 128-bit session ID entropy
- ✅ AAD binding (method, path, timestamp, nonce, session)
- ✅ Generic error responses

## Project Structure

```
session_crypto/
├── server/
│   ├── src/
│   │   ├── index.ts           # Fastify server with endpoints
│   │   ├── crypto-helpers.ts  # ECDH, HKDF, AES-GCM utilities
│   │   └── session-store.ts   # In-memory session storage
│   ├── package.json
│   └── tsconfig.json
├── client/
│   └── node/
│       ├── src/
│       │   ├── index.ts           # Client demo script
│       │   └── crypto-helpers.ts  # Crypto utilities
│       ├── package.json
│       └── tsconfig.json
├── session-init-design.md     # Full design document
└── README.md
```

## Notes

- This is a **PoC implementation**. For production:
  - Use Redis for session storage
  - Implement proper token introspection
  - Add rate limiting at APIM layer
  - Use proper logging and monitoring
