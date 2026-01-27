# Identity Service Node

Production-ready identity service with session management via ECDH key exchange. Implements the `/session/init` endpoint following the [SESSION_INIT_MIGRATION_PLAN.md](../SESSION_INIT_MIGRATION_PLAN.md).

## Features

- **ECDH P-256 Key Exchange** - Secure session establishment
- **AES-256-GCM Encryption** - Session key derivation and storage
- **Replay Protection** - Timestamp window + nonce uniqueness checks
- **High Availability** - Redis cache with LRU fallback
- **Repository Pattern** - Clean separation of concerns
- **Production Ready** - Comprehensive error handling, logging, graceful shutdown

## Architecture

```
src/
├── config/           # Configuration management
├── constants/        # Application constants
├── controllers/      # HTTP request handlers
├── repositories/     # Data access layer (PostgreSQL)
│   ├── interfaces/   # Repository contracts
│   └── implementations/  # Repository implementations
├── services/         # Business logic layer
├── types/            # TypeScript type definitions
├── utils/            # Utility functions (crypto, logger, LRU cache)
├── routes/           # Route registration
└── server.ts         # Application entry point
```

## Prerequisites

- Node.js ≥ 22.0.0
- PostgreSQL 12+
- Redis 6+

## Installation

```bash
cd identity-service-node
npm install
```

## Configuration

Copy `.env.example` to `.env` and configure:

```bash
# Server
PORT=3000
HOST=0.0.0.0
NODE_ENV=development
LOG_LEVEL=info

# Database
DATABASE_HOST=localhost
DATABASE_PORT=5432
DATABASE_NAME=identity_db
DATABASE_USER=postgres
DATABASE_PASSWORD=postgres

# Redis
REDIS_URL=redis://localhost:6379

# Session Configuration
SESSION_TTL_MIN_SEC=60
SESSION_TTL_MAX_SEC=3600
SESSION_TTL_DEFAULT_SEC=900

# Replay Protection
REPLAY_TIMESTAMP_WINDOW_SEC=300
REPLAY_NONCE_TTL_SEC=600
```

## Database Setup

The application automatically creates the `sessions` table on startup. Alternatively, run the migration manually:

```bash
psql -U postgres -d identity_db -f migrations/20260128_create_sessions_table.sql
```

## Running

### Development

```bash
npm run dev
```

### Production

```bash
npm run build
npm start
```

## API Endpoints

### Health Checks

**GET /health** - Basic health check
```bash
curl http://localhost:3000/health
```

**GET /ready** - Readiness check (database + cache)
```bash
curl http://localhost:3000/ready
```

### Session Initialization

**POST /v1/session/init** - Initialize new session with ECDH key exchange

Headers:
- `X-Idempotency-Key` (required): `{timestamp}.{nonce}` format
- `X-ClientId` (required): Client identifier
- `Content-Type: application/json`

Request Body:
```json
{
  "clientPublicKey": "base64-encoded-P256-public-key",
  "ttlSec": 900
}
```

Response:
```json
{
  "sessionId": "S-<32-hex-chars>",
  "serverPublicKey": "base64-encoded-P256-public-key",
  "encAlg": "aes-256-gcm",
  "expiresInSec": 900
}
```

Response Headers:
- `X-Kid`: Session ID (key identifier)

### Example Request

```bash
TIMESTAMP=$(date +%s%3N)
NONCE=$(openssl rand -hex 16)

curl -X POST http://localhost:3000/v1/session/init \
  -H "X-Idempotency-Key: ${TIMESTAMP}.${NONCE}" \
  -H "X-ClientId: client-123" \
  -H "Content-Type: application/json" \
  -d '{
    "clientPublicKey": "BKxT...",
    "ttlSec": 900
  }'
```

## Security Features

### Replay Protection

- **Timestamp Window**: ±5 minutes (configurable)
- **Nonce Uniqueness**: 10-minute TTL (configurable)
- **Fail Closed**: Rejects requests if Redis unavailable

### Key Management

- **ECDH P-256**: Industry-standard elliptic curve
- **HKDF-SHA256**: Secure key derivation
- **Buffer Zeroization**: Sensitive data cleared after use

### Storage

- **PostgreSQL**: Source of truth
- **Redis**: Distributed cache (primary)
- **LRU Cache**: In-memory fallback (bounded)

## Architecture Patterns

### Repository Pattern

Follows identity-service architecture:

```typescript
// Interface
interface SessionRepository extends BaseRepository {
  createSession(sessionId, data, expiresAt): Promise<void>;
  getSessionById(sessionId): Promise<SessionData | null>;
}

// Implementation
class SessionRepositoryImpl extends BaseRepositoryImpl {
  // PostgreSQL operations only
}

// Singleton
export const sessionRepository = new SessionRepositoryImpl();
```

### Service Layer

```
RequestValidationService  → Replay protection (timestamp + nonce)
SessionStoreService       → Coordinates cache + repository
SessionService            → Business logic (ECDH, HKDF, session creation)
CacheService              → Redis + LRU fallback abstraction
DatabaseService           → Connection pool management
```

### Cache Strategy

```
1. Write: PostgreSQL → Redis (best effort)
2. Read:  Redis → LRU → PostgreSQL (fallback chain)
3. Delete: Both Redis and PostgreSQL
```

## Error Handling

| Error Code | Description |
|------------|-------------|
| 400 | Invalid request (missing headers, invalid public key) |
| 409 | Replay detected (nonce reuse) |
| 503 | Service unavailable (Redis down, database error) |
| 500 | Internal server error |

## Monitoring

### Logs

Structured JSON logs with Winston:

```json
{
  "timestamp": "2026-01-28 12:00:00",
  "level": "info",
  "context": "SessionService",
  "message": "Session created successfully",
  "sessionId": "S-abc123...",
  "clientId": "client-123",
  "ttlSec": 900
}
```

### Metrics

Pool status available via `/ready` endpoint:

```json
{
  "status": "ready",
  "database": "up",
  "cache": "up",
  "pool": {
    "totalCount": 5,
    "idleCount": 3,
    "waitingCount": 0
  }
}
```

## Testing

```bash
# Unit tests
npm run test:unit

# Integration tests
npm run test:integration

# All tests
npm test

# Coverage
npm run test:coverage
```

## Development

### Code Style

```bash
# Lint
npm run lint

# Format
npm run format
```

### TypeScript

Strict mode enabled with comprehensive type checking:

```typescript
{
  "strict": true,
  "noImplicitAny": true,
  "noImplicitReturns": true,
  "noUnusedLocals": true,
  "noUnusedParameters": true
}
```

## Production Deployment

### Environment Variables

- Set `NODE_ENV=production`
- Configure connection pooling based on load
- Set appropriate log level (`LOG_LEVEL=info`)
- Enable Redis password if applicable

### Database

- Set `statement_timeout` at database level (recommended: 5s)
- Configure connection pool based on expected load
- Monitor pool metrics via `/ready`

### Caching

- Redis: Primary distributed cache
- LRU: Bounded in-memory fallback per pod
- Automatic reconnection with exponential backoff

### Security

- Deploy behind APIM with subscription key authentication
- No CORS at application level (handled by APIM)
- Helmet security headers enabled
- Request timeout: 60s (configurable)

## References

- [SESSION_INIT_MIGRATION_PLAN.md](../SESSION_INIT_MIGRATION_PLAN.md) - Migration plan
- [Session Crypto Server](../server/) - Original implementation
- [Identity Service](../../prj/identity-service/) - Architecture reference

## License

MIT
