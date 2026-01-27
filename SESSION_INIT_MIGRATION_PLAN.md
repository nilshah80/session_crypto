# Session Init Endpoint Migration Plan

## Overview

This document outlines the plan to migrate **ONLY** the `/session/init` endpoint from the standalone `session-crypto` service to the `identity-service`.

**Status**: Ready for Review
**Owner**: Architecture Team

### Scope

**In Scope:**
1. ✅ `/session/init` endpoint migration (ECDH key exchange)
2. ✅ Idempotency key header format (`X-Idempotency-Key: timestamp.nonce`)
3. ✅ Create `RequestValidationService` for shared replay protection
4. ✅ Session storage in identity-service (PostgreSQL + Redis cache)
5. ✅ Repository layer for PostgreSQL operations
6. ✅ APIM routing configuration with subscription key authentication

**Out of Scope:**
- ❌ Other endpoints (session-crypto PoC endpoints not migrated)
- ❌ OAuth2 endpoints (already in identity-service)
- ❌ Client SDK updates (separate effort)
- ❌ Traffic migration (endpoint deployed directly with identity-service)

### Key Migration Strategy

1. **Authentication**: `/session/init` is publicly available - authentication via APIM subscription key (no HMAC/Basic Auth at identity-service)
2. **Header Format**: Use `X-Idempotency-Key: timestamp.nonce` format (matches session-crypto)
3. **Replay Protection**: Create `RequestValidationService` - reused by both authenticated and public endpoints
4. **Repository Pattern**: Separate repository layer for PostgreSQL operations
5. **Caching**: Use identity-service's existing CacheService (Redis + LRU fallback) in `src/services/`
6. **No Code Duplication**: Both HMAC and session/init call same validation service

**Result**: Publicly accessible endpoint with APIM authentication + replay protection + simpler client integration

---

## Key Differences

| Aspect | Session-Crypto | Identity Service /session/init |
|--------|---------------|--------------------------------|
| **Header Format** | `X-Idempotency-Key: timestamp.nonce` | `X-Idempotency-Key: timestamp.nonce` ✓ |
| **Authentication** | APIM subscription key | APIM subscription key ✓ |
| **Signature** | No (public) | No (public) ✓ |
| **Redis Client** | `ioredis` | `redis` (npm) |
| **Fallback Cache** | Simple Map | LRU Cache |
| **Cache Abstraction** | Direct calls | CacheService |
| **Data Access** | Direct DB queries | Repository pattern |

**Migration Impact:**
- ✅ Public endpoint - no HMAC/signature required
- ✅ Simpler client integration (no signature calculation)
- ✅ Unified header format across services
- ✅ Replay protection without authentication coupling
- ✅ Cleaner separation of concerns with repository pattern

---

## Implementation Plan

### Phase 1: Preparation

#### 1.1 Create RequestValidationService

**New File**: `identity-service/src/services/request-validation.service.ts`

**Purpose**: Generic replay protection service reusable across all endpoints

**Key Method**: `validateTimestampAndNonce(timestamp: string, nonce: string): Promise<void>`
- Validates timestamp within ±5 minute window
- Checks nonce uniqueness via CacheService (Redis → LRU fallback)
- Stores nonce with 10-minute TTL

**Reference Implementation**: `session-crypto/server/src/crypto-helpers.ts` (validateReplayProtection function)

**Note**: CacheService remains in `src/services/cache.service.ts` (not moved to repository - it's a service layer component)

#### 1.2 Update HMAC Service (OAuth2 Endpoints)

**File**: `identity-service/src/services/hmac.service.ts`

**Changes**:
- Update to support `X-Idempotency-Key: timestamp.nonce` format (replace separate X-Timestamp/X-Nonce)
- Use RequestValidationService for replay protection
- Remove duplicate replay protection logic

#### 1.3 Copy Crypto Utilities

**Source**: `session-crypto/server/src/crypto-helpers.ts`
**Target**: `identity-service/src/utils/crypto-helpers.ts`

**Functions to Copy**:
- `createEcdhKeypair()` - ECDH P-256 keypair generation
- `validateP256PublicKey()` - EC public key validation
- `hkdf32()` - HKDF-SHA256 key derivation
- `aesGcmEncrypt()` / `aesGcmDecrypt()` - AES-256-GCM operations
- `buildAad()` - AAD construction
- `generateSessionId()` - Secure session ID generation

**Do NOT Copy**: Replay protection functions (use RequestValidationService instead)

---

### Phase 2: Implementation

#### 2.1 Create Type Definitions

**File**: `identity-service/src/types/session.types.ts`

**Interfaces**:
- `SessionInitBody` - Request body (clientPublicKey, ttlSec)
- `SessionInitResponse` - Response (sessionId, serverPublicKey, encAlg, expiresInSec)
- `SessionData` - Stored data (key, type, expiresAt, principal, clientId)

#### 2.2 Create Session Repository (PostgreSQL Layer)

**New Files**:
- `identity-service/src/repositories/interfaces/session.repository.ts` - Repository interface
- `identity-service/src/repositories/implementations/session.repository.impl.ts` - Repository implementation

**Purpose**: Handle all PostgreSQL operations for sessions (separation of concerns)

**Pattern**: Follow same pattern as ClientRepository and TokenRepository
- Extend `BaseRepositoryImpl` for common database operations
- Implement `SessionRepository` interface
- PostgreSQL operations only (no caching - handled by SessionStoreService)
- Export singleton instance in `repositories/index.ts`

**Key Methods**:
- `createSession(sessionId, sessionData, expiresAt)` - Insert session into PostgreSQL
- `getSessionById(sessionId)` - Retrieve session from PostgreSQL
- `deleteSession(sessionId)` - Delete session from PostgreSQL
- `ensureSessionsTable()` - Create table if not exists

**Reference**:
- `session-crypto/server/src/session-store.ts` (extract PostgreSQL logic)
- `identity-service/src/repositories/implementations/client.repository.impl.ts` (pattern example)

#### 2.3 Create Session Store Service (Cache + Repository)

**File**: `identity-service/src/services/session-store.service.ts`

**Reference**: `session-crypto/server/src/session-store.ts`

**Key Changes**:
- Use CacheService (from `src/services/cache.service.ts`) for Redis/LRU operations
- Use SessionRepository (from `src/repositories/session.repository.ts`) for PostgreSQL operations
- Coordinate between cache and database
- PostgreSQL as source of truth, Redis as cache

**Flow**:
- `storeSession()`: Write to PostgreSQL via repository, then cache via CacheService
- `getSession()`: Try cache first (CacheService), fallback to PostgreSQL (repository)
- `deleteSession()`: Delete from both cache and PostgreSQL

#### 2.4 Create Session Service

**File**: `identity-service/src/services/session.service.ts`

**Reference**: `session-crypto/server/src/crypto-helpers.ts` (createSession logic)

**Flow**:
1. Call `requestValidationService.validateTimestampAndNonce()` (no authentication)
2. ECDH key exchange (P-256)
3. HKDF key derivation
4. Store session via sessionStoreService
5. Zeroize sensitive buffers

#### 2.5 Create Session Controller

**File**: `identity-service/src/controllers/session.controller.ts`

**Key Points**:
- Public endpoint - no authentication middleware
- Extract X-Idempotency-Key and X-ClientId headers
- Call sessionService.createSession()
- Return session response with X-Kid header

#### 2.6 Register Routes

**File**: `identity-service/src/routes/index.ts`

**Change**:
```typescript
// No authentication middleware
api.post('/session/init', initSession);
```

#### 2.7 Update Server Initialization

**File**: `identity-service/src/server.ts`

**Add**:
- Initialize sessionStoreService with pool
- CacheService already initialized (no changes needed)

#### 2.8 Configuration

**File**: `identity-service/src/config/index.ts`

**Add**:
- SESSION_TTL_MIN_SEC, SESSION_TTL_MAX_SEC, SESSION_TTL_DEFAULT_SEC
- (Replay protection config already exists)

#### 2.9 Database Migration

**File**: `identity-service/migrations/YYYYMMDD_create_sessions_table.sql`

**Tables**:
- `sessions` table (session_id, data JSONB, expires_at, created_at)
- Indexes on expires_at and created_at

---

## File Structure

```
identity-service/
├── src/
│   ├── controllers/
│   │   └── session.controller.ts          # NEW: Session endpoint handler
│   ├── services/
│   │   ├── request-validation.service.ts  # NEW: Generic replay protection
│   │   ├── cache.service.ts               # EXISTING: Redis + LRU abstraction
│   │   ├── session-store.service.ts       # NEW: Cache + Repository coordination
│   │   ├── session.service.ts             # NEW: Session business logic
│   │   └── hmac.service.ts                # UPDATED: Use RequestValidationService
│   ├── repositories/
│   │   ├── interfaces/
│   │   │   └── session.repository.ts      # NEW: Repository interface
│   │   ├── implementations/
│   │   │   └── session.repository.impl.ts # NEW: Repository implementation
│   │   └── index.ts                       # UPDATED: Export session repository singleton
│   ├── types/
│   │   └── session.types.ts               # NEW: Session interfaces
│   ├── utils/
│   │   └── crypto-helpers.ts              # NEW: ECDH, HKDF, AES-GCM utilities
│   ├── routes/
│   │   └── index.ts                       # UPDATED: Add /session/init route
│   ├── config/
│   │   └── index.ts                       # UPDATED: Add session config
│   └── server.ts                          # UPDATED: Initialize session store
├── migrations/
│   └── YYYYMMDD_create_sessions_table.sql # NEW: Database migration
└── tests/
    ├── unit/
    │   └── services/
    │       ├── session.service.test.ts
    │       └── request-validation.service.test.ts
    └── integration/
        └── session.integration.test.ts
```

---

## Critical Considerations

### 1. Replay Protection

**Implementation**: `RequestValidationService` (`src/services/request-validation.service.ts`)
- Timestamp window: ±5 minutes
- Nonce TTL: 10 minutes
- Works independently of authentication
- Used by both HMAC (OAuth2) and session/init (public) endpoints

**Storage**: CacheService (`src/services/cache.service.ts`) - Redis primary, LRU fallback

### 2. Authentication Model

- `/session/init`: Public endpoint, APIM subscription key only
- OAuth2 endpoints: HMAC/Basic Auth (unchanged)
- No signature calculation needed for session initialization

### 3. Repository Pattern (Separation of Concerns)

**Repository Layer** (`src/repositories/`):
- Follow existing pattern used by ClientRepository and TokenRepository
- Extend BaseRepositoryImpl for common operations
- Interface + Implementation structure (`interfaces/` and `implementations/` subdirectories)
- Handles all PostgreSQL operations
- Single responsibility - database access only
- No business logic or caching
- Export singleton instance in `repositories/index.ts`

**Service Layer** (`src/services/`):
- Session Store Service - coordinates cache + repository
- Cache Service - manages Redis + LRU (stays in services, not a repository)
- Session Service - business logic (ECDH, HKDF)
- Request Validation Service - replay protection

### 4. Header Format Alignment

**Before**: `X-Timestamp` + `X-Nonce` (OAuth2 only)
**After**: `X-Idempotency-Key: timestamp.nonce` (all endpoints)

**Migration**: Single deployment, no gradual rollout needed

### 5. Caching Strategy

- **Redis**: Primary cache (distributed)
- **LRU**: In-memory fallback (per-pod, bounded)
- **PostgreSQL**: Source of truth
- **CacheService**: Abstraction layer (`src/services/cache.service.ts`)

### 6. Security

**Key Zeroization**: Shared secret and session key zeroized after use
**Replay Protection**: Independent of authentication (timestamp + nonce)
**Session ID**: 128-bit entropy, format `S-{32-char-hex}`

---

## Conclusion

This migration plan provides a streamlined approach to migrating the `/session/init` endpoint from session-crypto to identity-service.

### Key Benefits

1. **Public Endpoint** - No HMAC/signature required, simpler client integration
2. **Shared Replay Protection** - `RequestValidationService` reused across endpoints
3. **Repository Pattern** - Clean separation: repositories (data access), services (business logic, caching)
4. **Aligned Architecture** - Uses identity-service patterns (CacheService, LRU cache)
5. **High Availability** - LRU fallback ensures continuity during Redis downtime
6. **No Traffic Migration** - Endpoint deployed directly (nothing in production)

### Critical Alignment

| Aspect | Session-Crypto | Identity Service |
|--------|---------------|------------------|
| Redis Client | `ioredis` | `redis` (npm) ✓ |
| Fallback | Simple Map | LRU Cache ✓ |
| Auth | APIM subscription | APIM subscription ✓ |
| Headers | `X-Idempotency-Key` | `X-Idempotency-Key` ✓ |
| Data Access | Direct queries | Repository pattern ✓ |

### Related Documentation

- Session Crypto PoC: [README.md](./README.md)
- Identity Service HMAC: `identity-service/src/services/hmac.service.ts`
- Identity Service Cache: `identity-service/src/services/cache.service.ts`
- Identity Service LRU Cache: `identity-service/src/utils/lru-cache.ts`
