# Session Init Endpoint Migration Plan

## Overview

This document outlines the plan to migrate the `/session/init` endpoint from the standalone `session-crypto` service to the `identity-service`, unifying authentication and session management in a single service.

**Migration Date**: TBD
**Status**: Planning Phase
**Owner**: Architecture Team

---

## Table of Contents

1. [Current Architecture](#current-architecture)
2. [Target Architecture](#target-architecture)
3. [Key Differences](#key-differences)
4. [Implementation Plan](#implementation-plan)
5. [File Structure](#file-structure)
6. [Code Examples](#code-examples)
7. [Migration Checklist](#migration-checklist)
8. [Testing Strategy](#testing-strategy)
9. [Rollback Plan](#rollback-plan)
10. [Critical Considerations](#critical-considerations)

---

## Current Architecture

### Session-Crypto Service (Current)

```
┌─────────────┐      ┌──────────────────┐      ┌──────────────┐
│   Client    │─────▶│  Session-Crypto  │─────▶│  PostgreSQL  │
│             │      │     Service      │      │  (sessions)  │
└─────────────┘      └──────────────────┘      └──────────────┘
                            │
                            ▼
                     ┌──────────────┐
                     │    Redis     │
                     │ (cache+nonce)│
                     └──────────────┘
```

**Endpoints:**
- `POST /session/init` - ECDH key exchange and session creation
- `POST /transaction/purchase` - Encrypted business operations

**Headers:**
- `X-ClientId`: Client identifier
- `X-Idempotency-Key`: `timestamp.nonce` (combined format)
- `X-Kid`: Session identifier for subsequent requests

**Authentication:** Handled by APIM (external API gateway)

---

## Target Architecture

### Identity Service (Target)

```
┌─────────────┐      ┌──────────────────┐      ┌──────────────┐
│   Client    │─────▶│ Identity Service │─────▶│  PostgreSQL  │
│             │      │  (OAuth2 + Sess) │      │ (tokens+sess)│
└─────────────┘      └──────────────────┘      └──────────────┘
                            │
                            ▼
                     ┌──────────────┐
                     │    Redis     │
                     │ (cache+nonce)│
                     └──────────────┘
```

**New Endpoints:**
- `POST /v1/session/init` - ECDH key exchange (NEW)
- Existing OAuth2 endpoints remain unchanged

**Headers:**
- `X-ClientId`: Client identifier (unified)
- `X-Idempotency-Key`: `timestamp.nonce` (NEW - replaces separate headers)
- `X-Signature`: HMAC signature (existing)

**Authentication:** HMAC or Basic Auth (existing middleware)

---

## Key Differences

### Header Format Comparison

| Aspect | Session-Crypto Service | Identity Service (Current) | Identity Service (Target) |
|--------|----------------------|---------------------------|--------------------------|
| **Client ID** | `X-ClientId` | `X-Client-ID` | `X-ClientId` ✓ |
| **Timestamp** | Part of `X-Idempotency-Key` | `X-Timestamp` (separate) | Part of `X-Idempotency-Key` ✓ |
| **Nonce** | Part of `X-Idempotency-Key` | `X-Nonce` (separate) | Part of `X-Idempotency-Key` ✓ |
| **Signature** | N/A (via APIM) | `X-Signature` | `X-Signature` ✓ |
| **Format** | `timestamp.nonce` | Separate headers | `timestamp.nonce` ✓ |

### Architecture Patterns

| Aspect | Session-Crypto | Identity Service |
|--------|---------------|------------------|
| **Structure** | Routes in main file | Controller → Service pattern |
| **Auth Pattern** | Headers only (APIM) | HMAC + Basic Auth middleware |
| **Error Handling** | Generic middleware | OAuth2Error middleware |
| **Logging** | Fastify logger | Structured logger with audit |
| **Framework** | Fastify | Fastify |
| **Database** | PostgreSQL | PostgreSQL |
| **Cache** | Redis (with fallback) | Redis (with fallback) |

---

## Implementation Plan

### Phase 1: Preparation (Identity Service)

**Duration:** 1 week

#### 1.1 Update HMAC Service

**File:** `src/services/hmac.service.ts`

**Changes:**
- Support combined `X-Idempotency-Key: timestamp.nonce` format
- Maintain backward compatibility with separate headers
- Update header extraction logic

```typescript
extractHmacHeaders(
  headers: Record<string, string | string[] | undefined>
): HmacHeaders | null {
  const clientId = this.getHeader(headers, 'x-clientid'); // lowercase 'id'
  const signature = this.getHeader(headers, 'x-signature');

  // Try combined format first (new)
  const idempotencyKey = this.getHeader(headers, 'x-idempotency-key');
  if (idempotencyKey) {
    const [timestamp, nonce] = idempotencyKey.split('.');
    if (clientId && timestamp && nonce && signature) {
      return { clientId, timestamp, nonce, signature };
    }
  }

  // Fallback to separate headers (legacy)
  const timestamp = this.getHeader(headers, 'x-timestamp');
  const nonce = this.getHeader(headers, 'x-nonce');

  if (!clientId || !timestamp || !nonce || !signature) {
    return null;
  }

  return { clientId, timestamp, nonce, signature };
}
```

#### 1.2 Update CORS Configuration

**File:** `src/server.ts`

Add new headers to CORS allowedHeaders:
```typescript
allowedHeaders: [
  'Content-Type',
  'Authorization',
  'X-Client-ID',      // existing
  'X-ClientId',       // NEW - unified format
  'X-Timestamp',      // existing - keep for backward compatibility
  'X-Nonce',          // existing - keep for backward compatibility
  'X-Idempotency-Key', // NEW - combined format
  'X-Signature',
  'X-Kid',            // NEW - for session operations
],
exposedHeaders: [
  'X-Kid',            // NEW
  'X-Idempotency-Key', // NEW
],
```

#### 1.3 Copy Crypto Utilities

**Source:** `session-crypto/server/src/crypto-helpers.ts`
**Target:** `identity-service/src/utils/crypto-helpers.ts`

**Functions to copy:**
- `createEcdhKeypair()` - Generate ECDH P-256 keypair
- `validateP256PublicKey()` - Validate EC public key
- `hkdf32()` - HKDF-SHA256 key derivation
- `aesGcmEncrypt()` - AES-256-GCM encryption
- `aesGcmDecrypt()` - AES-256-GCM decryption
- `buildAad()` - AAD construction for AEAD
- `generateSessionId()` - Secure session ID generation
- `validateReplayProtection()` - Nonce + timestamp validation
- `initReplayProtection()` - Initialize replay protection with Redis
- `disposeReplayProtection()` - Cleanup resources

**Note:** Replay protection already supports in-memory fallback (same as identity service)

---

### Phase 2: Implementation (Identity Service)

**Duration:** 2 weeks

#### 2.1 Create Type Definitions

**File:** `src/types/session.types.ts`

```typescript
/**
 * Session initialization request body
 */
export interface SessionInitBody {
  /**
   * Client's ECDH public key (P-256, base64-encoded)
   */
  clientPublicKey: string;

  /**
   * Requested session TTL in seconds (optional)
   * Min: 300 (5 minutes), Max: 3600 (1 hour)
   * Default: 1800 (30 minutes)
   */
  ttlSec?: number;
}

/**
 * Session initialization response
 */
export interface SessionInitResponse {
  /**
   * Unique session identifier (used as X-Kid in subsequent requests)
   */
  sessionId: string;

  /**
   * Server's ECDH public key (P-256, base64-encoded)
   */
  serverPublicKey: string;

  /**
   * Encryption algorithm (always "A256GCM")
   */
  encAlg: string;

  /**
   * Session expiration time in seconds
   */
  expiresInSec: number;
}

/**
 * Session data stored in database/cache
 */
export interface SessionData {
  /**
   * Session key (base64-encoded, derived via HKDF)
   */
  key: string;

  /**
   * Session type (ANON or AUTH)
   */
  type: 'ANON' | 'AUTH';

  /**
   * Expiration timestamp (milliseconds since epoch)
   */
  expiresAt: number;

  /**
   * Optional principal/user identifier
   */
  principal?: string;

  /**
   * Client identifier
   */
  clientId?: string;
}
```

#### 2.2 Create Session Store Service

**File:** `src/services/session-store.service.ts`

```typescript
import { Pool } from 'pg';
import { Redis } from 'ioredis';
import { SessionData } from '../types/session.types';
import { logger } from '../utils/logger';

const SESSION_PREFIX = 'session:';

class SessionStoreService {
  private pool: Pool | null = null;
  private redis: Redis | null = null;
  private logger: any = null;

  /**
   * Initialize session store with PostgreSQL and Redis
   */
  async init(pool: Pool, redis: Redis, loggerInstance?: any): Promise<void> {
    this.pool = pool;
    this.redis = redis;
    this.logger = loggerInstance;

    // Ensure sessions table exists
    await this.ensureTable();
  }

  /**
   * Ensure sessions table exists
   */
  private async ensureTable(): Promise<void> {
    if (!this.pool) throw new Error('Pool not initialized');

    await this.pool.query(`
      CREATE TABLE IF NOT EXISTS sessions (
        session_id VARCHAR(255) PRIMARY KEY,
        data JSONB NOT NULL,
        expires_at BIGINT NOT NULL
      )
    `);

    await this.pool.query(`
      CREATE INDEX IF NOT EXISTS idx_sessions_expires_at
      ON sessions(expires_at)
    `);
  }

  /**
   * Store session in PostgreSQL (source of truth) and Redis (cache)
   */
  async storeSession(
    sessionId: string,
    key: Buffer,
    type: 'ANON' | 'AUTH',
    ttlSec: number,
    principal?: string,
    clientId?: string
  ): Promise<void> {
    if (!this.pool) throw new Error('Session store not initialized');

    const expiresAt = Date.now() + ttlSec * 1000;

    // Create a copy of the key buffer to avoid modifying original
    const keyCopy = Buffer.from(key);

    const sessionData: SessionData = {
      key: keyCopy.toString('base64'),
      type,
      expiresAt,
      ...(principal && { principal }),
      ...(clientId && { clientId }),
    };
    const value = JSON.stringify(sessionData);

    // SECURITY: Zeroize the key copy after encoding
    keyCopy.fill(0);

    // 1. Write to PostgreSQL (Source of Truth)
    await this.pool.query(
      `INSERT INTO sessions (session_id, data, expires_at)
       VALUES ($1, $2, $3)
       ON CONFLICT (session_id) DO UPDATE
       SET data = $2, expires_at = $3`,
      [sessionId, value, expiresAt]
    );

    // 2. Write to Redis (Cache) - optional, skip if Redis unavailable
    if (this.redis && this.redis.status === 'ready') {
      try {
        await this.redis.set(
          `${SESSION_PREFIX}${sessionId}`,
          value,
          'EX',
          ttlSec
        );
      } catch (err) {
        if (this.logger) {
          this.logger.warn({ err, sessionId }, 'Failed to cache session in Redis');
        }
      }
    }
  }

  /**
   * Get session from Redis (cache) with PostgreSQL fallback
   */
  async getSession(sessionId: string): Promise<SessionData | null> {
    if (!this.pool) throw new Error('Session store not initialized');

    // 1. Try Redis (if available)
    if (this.redis && this.redis.status === 'ready') {
      try {
        const cachedValue = await this.redis.get(`${SESSION_PREFIX}${sessionId}`);
        if (cachedValue) {
          return this.parseSession(cachedValue, sessionId);
        }
      } catch (err) {
        if (this.logger) {
          this.logger.warn({ err, sessionId }, 'Redis read failed, falling back to PostgreSQL');
        }
      }
    }

    // 2. Fallback to PostgreSQL
    const res = await this.pool.query(
      'SELECT data FROM sessions WHERE session_id = $1',
      [sessionId]
    );

    if (res.rows.length === 0) {
      return null;
    }

    // Handle JSONB: pg returns parsed object, not string
    const rawData = res.rows[0].data;
    const dbValue = typeof rawData === 'string' ? rawData : JSON.stringify(rawData);
    const parsed = this.parseSession(dbValue, sessionId);

    // Populate Redis if found, valid, and Redis available
    if (parsed && this.redis && this.redis.status === 'ready') {
      const ttl = Math.ceil((parsed.expiresAt - Date.now()) / 1000);
      if (ttl > 0) {
        try {
          await this.redis.set(`${SESSION_PREFIX}${sessionId}`, dbValue, 'EX', ttl);
        } catch (err) {
          if (this.logger) {
            this.logger.warn({ err, sessionId }, 'Failed to populate Redis cache');
          }
        }
      }
    }

    return parsed;
  }

  /**
   * Parse and validate session data
   */
  private parseSession(value: string, sessionId: string): SessionData | null {
    try {
      const data: SessionData = JSON.parse(value);

      // Check expiration
      if (data.expiresAt <= Date.now()) {
        if (this.logger) {
          this.logger.debug({ sessionId }, 'Session expired');
        }
        return null;
      }

      // Decode key from base64
      const keyBuffer = Buffer.from(data.key, 'base64');

      return {
        ...data,
        key: keyBuffer.toString('base64'), // Keep as base64 string
      };
    } catch (err) {
      if (this.logger) {
        this.logger.error({ err, sessionId }, 'Failed to parse session data');
      }
      return null;
    }
  }

  /**
   * Delete session from both PostgreSQL and Redis
   */
  async deleteSession(sessionId: string): Promise<boolean> {
    if (!this.pool) throw new Error('Session store not initialized');

    const promises: Promise<any>[] = [];

    // Delete from Redis if available
    if (this.redis && this.redis.status === 'ready') {
      promises.push(
        this.redis.del(`${SESSION_PREFIX}${sessionId}`).catch((err) => {
          if (this.logger) {
            this.logger.warn({ err, sessionId }, 'Failed to delete session from Redis');
          }
          return 0;
        })
      );
    }

    // Delete from PostgreSQL
    promises.push(
      this.pool.query('DELETE FROM sessions WHERE session_id = $1', [sessionId])
    );

    const results = await Promise.all(promises);
    const pgRes = promises.length === 2 ? results[1] : results[0];

    return (pgRes.rowCount ?? 0) > 0;
  }

  /**
   * Close connections
   */
  async close(): Promise<void> {
    // Redis is managed externally
    // Pool is managed externally
  }
}

export const sessionStoreService = new SessionStoreService();
```

#### 2.3 Create Session Service

**File:** `src/services/session.service.ts`

```typescript
import {
  createEcdhKeypair,
  validateP256PublicKey,
  hkdf32,
  generateSessionId,
  validateReplayProtection,
} from '../utils/crypto-helpers';
import { SessionInitResponse } from '../types/session.types';
import { sessionStoreService } from './session-store.service';
import { logger } from '../utils/logger';
import { config } from '../config';

class SessionService {
  /**
   * Create a new encrypted session via ECDH key exchange
   */
  async createSession(params: {
    clientPublicKey: string;
    ttlSec?: number;
    clientId: string;
    timestamp: string;
    nonce: string;
  }): Promise<SessionInitResponse> {
    const { clientPublicKey, ttlSec, clientId, timestamp, nonce } = params;

    // 1. Replay protection (uses Redis with in-memory fallback)
    await validateReplayProtection(nonce, timestamp);

    // 2. Validate and decode client public key
    const clientPub = Buffer.from(clientPublicKey, 'base64');
    validateP256PublicKey(clientPub);

    // 3. Generate server ECDH keypair (P-256)
    const { ecdh: serverECDH, publicKey: serverPub } = createEcdhKeypair();

    // 4. Compute shared secret via ECDH
    const sharedSecret = serverECDH.computeSecret(clientPub);

    // 5. Generate unique session ID
    const sessionId = generateSessionId('S');

    // 6. Derive session key using HKDF-SHA256
    // Info includes clientId for domain separation
    const salt = Buffer.from(sessionId, 'utf8');
    const info = Buffer.from(`SESSION|A256GCM|${clientId}`, 'utf8');
    const sessionKey = hkdf32(sharedSecret, salt, info);

    // SECURITY: Zeroize shared secret immediately after key derivation
    sharedSecret.fill(0);

    // 7. Validate and cap TTL
    const allowedTtl = this.validateAndCapTtl(ttlSec);

    // 8. Store session in PostgreSQL + Redis
    await sessionStoreService.storeSession(
      sessionId,
      sessionKey,
      'AUTH',
      allowedTtl,
      undefined, // principal - not applicable for ECDH sessions
      clientId
    );

    // SECURITY: Zeroize session key after storing
    sessionKey.fill(0);

    logger.info('SessionService', 'Session created', 'session_init', {
      sessionId,
      clientId,
      ttl: allowedTtl,
    });

    return {
      sessionId,
      serverPublicKey: serverPub.toString('base64'),
      encAlg: 'A256GCM',
      expiresInSec: allowedTtl,
    };
  }

  /**
   * Retrieve session by ID
   */
  async getSession(sessionId: string): Promise<{
    key: Buffer;
    type: string;
    expiresAt: number;
    principal?: string;
    clientId?: string;
  } | null> {
    const session = await sessionStoreService.getSession(sessionId);
    if (!session) return null;

    return {
      ...session,
      key: Buffer.from(session.key, 'base64'),
    };
  }

  /**
   * Delete session
   */
  async deleteSession(sessionId: string): Promise<boolean> {
    return sessionStoreService.deleteSession(sessionId);
  }

  /**
   * Validate and cap TTL within configured bounds
   */
  private validateAndCapTtl(ttlSec?: number): number {
    const min = config.SESSION_TTL_MIN_SEC || 300; // 5 minutes
    const max = config.SESSION_TTL_MAX_SEC || 3600; // 1 hour
    const defaultTtl = config.SESSION_TTL_DEFAULT_SEC || 1800; // 30 minutes

    if (ttlSec === undefined) return defaultTtl;
    if (ttlSec < 0 || !Number.isInteger(ttlSec)) return defaultTtl;

    return Math.min(Math.max(ttlSec, min), max);
  }
}

export const sessionService = new SessionService();
```

#### 2.4 Create Session Controller

**File:** `src/controllers/session.controller.ts`

```typescript
import { FastifyRequest, FastifyReply } from 'fastify';
import { SessionInitBody, SessionInitResponse } from '../types/session.types';
import { sessionService } from '../services/session.service';
import { logger } from '../utils/logger';
import { createOAuth2Error } from '../middleware/error.middleware';

/**
 * Initialize encrypted session via ECDH key exchange
 * POST /v1/session/init
 *
 * Requires client authentication (HMAC or Basic Auth).
 */
export async function initSession(
  request: FastifyRequest<{ Body: SessionInitBody }>,
  reply: FastifyReply
): Promise<SessionInitResponse> {
  try {
    // Extract headers
    const idempotencyKey = request.headers['x-idempotency-key'] as string | undefined;
    const clientId = request.headers['x-clientid'] as string | undefined;

    // Validate required headers
    if (!idempotencyKey || !clientId) {
      logger.warn('SessionController', 'Missing required headers', 'session_init', {
        hasIdempotencyKey: !!idempotencyKey,
        hasClientId: !!clientId,
      });
      throw createOAuth2Error('invalid_request', 'Missing required headers');
    }

    // Parse combined idempotency key: timestamp.nonce
    const [timestamp, nonce] = idempotencyKey.split('.');
    if (!timestamp || !nonce) {
      logger.warn('SessionController', 'Invalid idempotency key format', 'session_init', {
        idempotencyKey,
      });
      throw createOAuth2Error('invalid_request', 'Invalid idempotency key format');
    }

    // Validate request body
    const { clientPublicKey, ttlSec } = request.body;

    if (!clientPublicKey) {
      logger.warn('SessionController', 'Missing client public key', 'session_init');
      throw createOAuth2Error('invalid_request', 'Missing client public key');
    }

    // Create session via service layer
    const sessionResponse = await sessionService.createSession({
      clientPublicKey,
      ttlSec,
      clientId,
      timestamp,
      nonce,
    });

    logger.info('SessionController', 'Session created successfully', 'session_init', {
      sessionId: sessionResponse.sessionId,
      clientId,
      expiresIn: sessionResponse.expiresInSec,
    });

    // Set response headers for session tracking
    return reply
      .status(200)
      .header('X-Kid', sessionResponse.sessionId)
      .header('X-Idempotency-Key', idempotencyKey)
      .send(sessionResponse);
  } catch (error) {
    logger.error('SessionController', 'Session init failed', 'session_init', {
      error: (error as Error).message,
    });

    // If it's already an OAuth2 error, re-throw
    if ((error as any).oauth2Error) {
      throw error;
    }

    // Generic error response
    throw createOAuth2Error('server_error', 'Session initialization failed');
  }
}
```

#### 2.5 Register Routes

**File:** `src/routes/index.ts`

```typescript
import { FastifyInstance } from 'fastify';
import { authenticateClient } from '../middleware/auth.middleware';
import { initSession } from '../controllers/session.controller';
// ... existing imports

const API_VERSION = '/v1';

export async function registerRoutes(fastify: FastifyInstance): Promise<void> {
  // Health endpoints (no authentication, no version prefix)
  fastify.get('/health', healthCheck);
  fastify.get('/ready', readinessCheck);

  // Versioned API routes
  await fastify.register(
    async api => {
      // ========================================
      // Session Management (NEW)
      // ========================================

      /**
       * Initialize encrypted session via ECDH
       * Requires HMAC or Basic Auth
       */
      api.post(
        '/session/init',
        {
          preHandler: [authenticateClient],
        },
        initSession
      );

      // ========================================
      // OAuth2 Token Endpoints (EXISTING)
      // ========================================

      api.post(
        '/token/issue',
        {
          preHandler: [authenticateClient],
        },
        issueToken
      );

      api.post(
        '/token',
        {
          preHandler: [authenticateByTokenAllowExpired],
        },
        tokenEndpoint
      );

      api.post(
        '/introspect',
        {
          preHandler: [authenticateByToken],
        },
        introspectToken
      );

      api.post(
        '/revoke',
        {
          preHandler: [authenticateByToken],
        },
        revokeToken
      );
    },
    { prefix: API_VERSION }
  );

  // Admin endpoints
  await registerAdminRoutes(fastify);
}
```

#### 2.6 Update Server Initialization

**File:** `src/server.ts`

```typescript
import { sessionStoreService } from './services/session-store.service';
import { initReplayProtection, disposeReplayProtection } from './utils/crypto-helpers';

// ... existing code ...

// Initialize session store
await sessionStoreService.init(pool, redis, logger);

// Initialize replay protection
initReplayProtection(redis, logger);

// ... existing code ...

// Graceful shutdown
const shutdown = async () => {
  logger.info('Server', 'Shutting down gracefully', 'shutdown');

  // Dispose replay protection resources
  disposeReplayProtection();

  await sessionStoreService.close();
  await redis.quit();
  await pool.end();
  await server.close();

  process.exit(0);
};
```

#### 2.7 Add Configuration

**File:** `src/config/index.ts`

```typescript
export const config = {
  // ... existing config ...

  // Session Management Configuration
  SESSION_TTL_MIN_SEC: getEnvNumber('SESSION_TTL_MIN_SEC', 300), // 5 minutes
  SESSION_TTL_MAX_SEC: getEnvNumber('SESSION_TTL_MAX_SEC', 3600), // 1 hour
  SESSION_TTL_DEFAULT_SEC: getEnvNumber('SESSION_TTL_DEFAULT_SEC', 1800), // 30 minutes

  // Replay Protection (already exists, reuse)
  HMAC_TIMESTAMP_TOLERANCE_MS: getEnvNumber('HMAC_TIMESTAMP_TOLERANCE_MS', 300000), // 5 minutes
  HMAC_NONCE_TTL_SECONDS: getEnvNumber('HMAC_NONCE_TTL_SECONDS', 600), // 10 minutes
};
```

---

### Phase 3: Testing

**Duration:** 1 week

#### 3.1 Unit Tests

**File:** `tests/unit/services/session.service.test.ts`

```typescript
import { sessionService } from '../../../src/services/session.service';
import { sessionStoreService } from '../../../src/services/session-store.service';
import * as cryptoHelpers from '../../../src/utils/crypto-helpers';

jest.mock('../../../src/services/session-store.service');
jest.mock('../../../src/utils/crypto-helpers');

describe('SessionService', () => {
  describe('createSession', () => {
    it('should create session with valid input', async () => {
      // Mock crypto operations
      jest.spyOn(cryptoHelpers, 'validateReplayProtection').mockResolvedValue();
      jest.spyOn(cryptoHelpers, 'validateP256PublicKey').mockReturnValue();
      jest.spyOn(cryptoHelpers, 'createEcdhKeypair').mockReturnValue({
        ecdh: {
          computeSecret: jest.fn().mockReturnValue(Buffer.alloc(32)),
        },
        publicKey: Buffer.from('server-pub-key'),
      });
      jest.spyOn(cryptoHelpers, 'generateSessionId').mockReturnValue('S-123456');
      jest.spyOn(cryptoHelpers, 'hkdf32').mockReturnValue(Buffer.alloc(32));

      const result = await sessionService.createSession({
        clientPublicKey: Buffer.from('client-pub-key').toString('base64'),
        ttlSec: 1800,
        clientId: 'client123',
        timestamp: Date.now().toString(),
        nonce: 'nonce123',
      });

      expect(result.sessionId).toBe('S-123456');
      expect(result.encAlg).toBe('A256GCM');
      expect(result.expiresInSec).toBe(1800);
    });

    it('should reject replay attacks', async () => {
      jest.spyOn(cryptoHelpers, 'validateReplayProtection').mockRejectedValue(
        new Error('REPLAY_DETECTED')
      );

      await expect(
        sessionService.createSession({
          clientPublicKey: 'pubkey',
          clientId: 'client123',
          timestamp: Date.now().toString(),
          nonce: 'used-nonce',
        })
      ).rejects.toThrow('REPLAY_DETECTED');
    });
  });
});
```

#### 3.2 Integration Tests

**File:** `tests/integration/session.integration.test.ts`

```typescript
import { FastifyInstance } from 'fastify';
import { createServer } from '../../src/server';

describe('POST /v1/session/init', () => {
  let server: FastifyInstance;

  beforeAll(async () => {
    server = await createServer();
  });

  afterAll(async () => {
    await server.close();
  });

  it('should create session with valid HMAC authentication', async () => {
    const timestamp = Date.now().toString();
    const nonce = `nonce-${Date.now()}`;
    const idempotencyKey = `${timestamp}.${nonce}`;

    // Generate HMAC signature
    const signature = generateHmacSignature({
      method: 'POST',
      path: '/v1/session/init',
      timestamp,
      nonce,
      body: { clientPublicKey: 'base64-encoded-key', ttlSec: 1800 },
      clientSecret: 'test-secret',
    });

    const response = await server.inject({
      method: 'POST',
      url: '/v1/session/init',
      headers: {
        'x-clientid': 'test-client',
        'x-idempotency-key': idempotencyKey,
        'x-signature': signature,
        'content-type': 'application/json',
      },
      payload: {
        clientPublicKey: 'BHCn3V7lZ/6yx0gSB4xOJ+TQEocGT5h7qC8TZqPVxq8r2aK8jlNw0L5sYBD3Y8xPQMzJ2T+vB5xL1sYBD3Y8xPQ=',
        ttlSec: 1800,
      },
    });

    expect(response.statusCode).toBe(200);
    expect(response.json()).toMatchObject({
      sessionId: expect.stringMatching(/^S-[a-f0-9]{32}$/),
      serverPublicKey: expect.any(String),
      encAlg: 'A256GCM',
      expiresInSec: 1800,
    });
  });

  it('should reject request with missing idempotency key', async () => {
    const response = await server.inject({
      method: 'POST',
      url: '/v1/session/init',
      headers: {
        'x-clientid': 'test-client',
        'content-type': 'application/json',
      },
      payload: {
        clientPublicKey: 'base64-key',
      },
    });

    expect(response.statusCode).toBe(400);
    expect(response.json().error).toBe('invalid_request');
  });

  it('should reject replay attack', async () => {
    const timestamp = Date.now().toString();
    const nonce = 'fixed-nonce';
    const idempotencyKey = `${timestamp}.${nonce}`;

    // First request
    await server.inject({
      method: 'POST',
      url: '/v1/session/init',
      headers: {
        'x-clientid': 'test-client',
        'x-idempotency-key': idempotencyKey,
        'x-signature': 'valid-signature',
      },
      payload: { clientPublicKey: 'key' },
    });

    // Replay attack (same nonce)
    const response = await server.inject({
      method: 'POST',
      url: '/v1/session/init',
      headers: {
        'x-clientid': 'test-client',
        'x-idempotency-key': idempotencyKey,
        'x-signature': 'valid-signature',
      },
      payload: { clientPublicKey: 'key' },
    });

    expect(response.statusCode).toBe(400);
  });
});
```

#### 3.3 Load Testing

**File:** `load-tests/session-init.artillery.yml`

```yaml
config:
  target: 'http://localhost:3000'
  phases:
    - duration: 60
      arrivalRate: 10
      name: Warmup
    - duration: 300
      arrivalRate: 50
      name: Sustained load
    - duration: 120
      arrivalRate: 100
      name: Spike
  processor: './session-init-processor.js'

scenarios:
  - name: Session initialization
    flow:
      - function: 'generateSessionInitRequest'
      - post:
          url: '/v1/session/init'
          headers:
            X-ClientId: '{{ clientId }}'
            X-Idempotency-Key: '{{ idempotencyKey }}'
            X-Signature: '{{ signature }}'
            Content-Type: 'application/json'
          json:
            clientPublicKey: '{{ clientPublicKey }}'
            ttlSec: 1800
          capture:
            - json: '$.sessionId'
              as: 'sessionId'
      - think: 1
```

---

### Phase 4: Deployment & Migration

**Duration:** 2 weeks

#### 4.1 Database Migration

**File:** `migrations/YYYYMMDD_create_sessions_table.sql`

```sql
-- Create sessions table
CREATE TABLE IF NOT EXISTS sessions (
  session_id VARCHAR(255) PRIMARY KEY,
  data JSONB NOT NULL,
  expires_at BIGINT NOT NULL,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Index for expiration queries (cleanup jobs)
CREATE INDEX IF NOT EXISTS idx_sessions_expires_at
ON sessions(expires_at);

-- Index for created_at (analytics)
CREATE INDEX IF NOT EXISTS idx_sessions_created_at
ON sessions(created_at);

-- Grant permissions
GRANT SELECT, INSERT, UPDATE, DELETE ON sessions TO identity_service_user;
```

#### 4.2 Configuration Updates

**File:** `.env.example` (identity-service)

```bash
# ============================================
# Session Management Configuration
# ============================================

# Session TTL boundaries (seconds)
SESSION_TTL_MIN_SEC=300        # 5 minutes
SESSION_TTL_MAX_SEC=3600       # 1 hour
SESSION_TTL_DEFAULT_SEC=1800   # 30 minutes

# Replay Protection (reuses existing HMAC config)
# HMAC_TIMESTAMP_TOLERANCE_MS=300000  # 5 minutes (already exists)
# HMAC_NONCE_TTL_SECONDS=600          # 10 minutes (already exists)
```

#### 4.3 APIM Configuration

Update API Management (APIM) to route `/session/init` to identity service:

```yaml
# APIM Route Configuration
routes:
  - path: /v1/session/init
    method: POST
    backend:
      service: identity-service
      url: http://identity-service:3000/v1/session/init
    rate_limit:
      requests_per_minute: 1000
    cors:
      enabled: true
      allowed_origins: ['*']
      allowed_methods: ['POST']
      allowed_headers: ['Content-Type', 'X-ClientId', 'X-Idempotency-Key', 'X-Signature']
      exposed_headers: ['X-Kid', 'X-Idempotency-Key']
```

#### 4.4 Deployment Steps

1. **Deploy Identity Service** (with new `/session/init` endpoint)
   ```bash
   # Build
   cd identity-service
   npm run build

   # Run migrations
   npm run migrate:up

   # Deploy to staging
   kubectl apply -f k8s/identity-service-staging.yaml

   # Verify health
   curl https://identity-service-staging/health
   ```

2. **Update APIM** (route traffic to identity service)
   ```bash
   # Deploy APIM configuration
   kubectl apply -f apim-config/session-routes.yaml

   # Verify routing
   curl -X POST https://api-gateway/v1/session/init \
     -H "X-ClientId: test" \
     -H "X-Idempotency-Key: $(date +%s).test-nonce" \
     -d '{"clientPublicKey":"test"}'
   ```

3. **Gradual Traffic Migration**
   - Week 1: 10% traffic to identity service
   - Week 2: 50% traffic
   - Week 3: 100% traffic
   - Monitor error rates, latency, and throughput

4. **Decommission Session-Crypto Service**
   - After 2 weeks of 100% traffic on identity service
   - Backup session-crypto database
   - Scale down session-crypto pods
   - Archive codebase

---

## Migration Checklist

### Pre-Migration

- [ ] Review and approve migration plan
- [ ] Set up monitoring dashboards for identity service
- [ ] Set up alerts for session-init endpoint
- [ ] Create rollback plan
- [ ] Schedule maintenance window (if needed)
- [ ] Notify stakeholders

### Phase 1: Preparation (Week 1)

- [ ] Update HMAC service to support combined idempotency format
- [ ] Add backward compatibility for legacy header format
- [ ] Update CORS configuration
- [ ] Copy crypto utilities from session-crypto
- [ ] Copy session-store logic
- [ ] Code review (2 reviewers minimum)
- [ ] Security review

### Phase 2: Implementation (Week 2-3)

- [ ] Create type definitions (session.types.ts)
- [ ] Implement session-store service
- [ ] Implement session service
- [ ] Implement session controller
- [ ] Register routes
- [ ] Update server initialization
- [ ] Add configuration
- [ ] Code review
- [ ] Security review

### Phase 3: Testing (Week 4)

- [ ] Write unit tests (>80% coverage)
- [ ] Write integration tests
- [ ] Run load tests (baseline performance)
- [ ] Test with Redis down (in-memory fallback)
- [ ] Test replay attack protection
- [ ] Test with both header formats (legacy + new)
- [ ] Penetration testing
- [ ] Performance testing vs. session-crypto baseline

### Phase 4: Staging Deployment (Week 5)

- [ ] Deploy to staging environment
- [ ] Run database migrations
- [ ] Configure APIM routing (staging)
- [ ] End-to-end testing in staging
- [ ] Load testing in staging
- [ ] Verify monitoring and alerts
- [ ] Verify logging
- [ ] Test rollback procedure

### Phase 5: Production Rollout (Week 6-8)

- [ ] Deploy identity service to production (blue-green)
- [ ] Run database migrations in production
- [ ] Update APIM configuration
- [ ] Enable 10% traffic to identity service (Week 6)
- [ ] Monitor for 48 hours
- [ ] Increase to 50% traffic (Week 7)
- [ ] Monitor for 48 hours
- [ ] Increase to 100% traffic (Week 8)
- [ ] Monitor for 1 week
- [ ] Decommission session-crypto service

### Post-Migration

- [ ] Archive session-crypto codebase
- [ ] Update documentation
- [ ] Update client SDKs (if needed)
- [ ] Post-mortem review
- [ ] Update runbooks

---

## Testing Strategy

### 1. Unit Testing

**Coverage Target:** >80%

**Test Cases:**
- ✓ Session creation with valid input
- ✓ Invalid client public key rejection
- ✓ TTL validation and capping
- ✓ Replay attack detection
- ✓ Timestamp window validation
- ✓ Nonce uniqueness enforcement
- ✓ Session retrieval from cache
- ✓ Session retrieval from database (cache miss)
- ✓ Session expiration handling
- ✓ Buffer zeroization (security)

### 2. Integration Testing

**Test Cases:**
- ✓ End-to-end ECDH key exchange
- ✓ HMAC authentication
- ✓ Basic auth authentication
- ✓ Combined idempotency header format
- ✓ Legacy separate header format (backward compatibility)
- ✓ Redis cache hit/miss scenarios
- ✓ Redis unavailable (in-memory fallback)
- ✓ PostgreSQL failover
- ✓ Concurrent session creation
- ✓ Session cleanup (expired sessions)

### 3. Load Testing

**Scenarios:**
- Baseline: 50 req/s sustained
- Peak: 200 req/s spike
- Endurance: 100 req/s for 1 hour

**Metrics:**
- P50 latency < 20ms
- P95 latency < 50ms
- P99 latency < 100ms
- Error rate < 0.1%
- CPU usage < 70%
- Memory usage < 80%

### 4. Security Testing

**Test Cases:**
- ✓ Replay attack prevention
- ✓ Invalid signature rejection
- ✓ Expired timestamp rejection
- ✓ SQL injection attempts
- ✓ Buffer overflow attempts
- ✓ Key zeroization verification
- ✓ Session hijacking prevention
- ✓ Brute force protection
- ✓ CORS policy enforcement

### 5. Chaos Engineering

**Scenarios:**
- Redis failure (verify in-memory fallback)
- PostgreSQL failure (verify error handling)
- Network partition
- High CPU load
- High memory pressure
- Pod restart during request

---

## Rollback Plan

### Scenario 1: Critical Bug in Identity Service

**Symptoms:**
- Error rate > 5%
- P99 latency > 1s
- Security vulnerability discovered

**Action:**
1. Immediately route 100% traffic back to session-crypto service via APIM
2. Scale down identity service pods
3. Investigate and fix issue
4. Re-deploy to staging
5. Re-test before production rollout

**Estimated Time:** 5-10 minutes

---

### Scenario 2: Performance Degradation

**Symptoms:**
- P95 latency > 100ms
- CPU usage > 90%
- Memory leaks

**Action:**
1. Gradually reduce traffic to identity service (100% → 50% → 10%)
2. Scale up identity service pods if needed
3. Investigate performance issue
4. Optimize and re-deploy
5. Gradually increase traffic again

**Estimated Time:** 30-60 minutes

---

### Scenario 3: Database Issues

**Symptoms:**
- Session storage failures
- Connection pool exhaustion
- Deadlocks

**Action:**
1. Check PostgreSQL health and connections
2. Scale up connection pool if needed
3. Route traffic back to session-crypto if issue persists
4. Investigate and fix database configuration
5. Re-deploy and re-test

**Estimated Time:** 15-30 minutes

---

## Critical Considerations

### 1. Database Schema

**Sessions Table Requirements:**
```sql
CREATE TABLE sessions (
  session_id VARCHAR(255) PRIMARY KEY,  -- S-{32-char-hex}
  data JSONB NOT NULL,                  -- Session metadata + encrypted key
  expires_at BIGINT NOT NULL,           -- Milliseconds since epoch
  created_at TIMESTAMP DEFAULT NOW()    -- Audit trail
);
```

**Indexes:**
- `idx_sessions_expires_at` - For cleanup jobs
- `idx_sessions_created_at` - For analytics

**Estimated Size:**
- 1M sessions: ~500 MB
- 10M sessions: ~5 GB
- TTL: 30 minutes → ~100K active sessions at peak

---

### 2. Sticky Sessions

**Current Setup:**
- Identity service already uses sticky sessions for multi-pod deployments
- Session affinity based on `X-Client-ID` header
- Load balancer: Nginx with `ip_hash` or `consistent_hash`

**Configuration:**
```nginx
upstream identity_service {
  consistent_hash $http_x_clientid;
  server identity-pod-1:3000;
  server identity-pod-2:3000;
  server identity-pod-3:3000;
}
```

**Impact:**
- In-memory nonce store provides full replay protection with sticky sessions
- No cross-pod replay attacks possible
- Session cache locality improved

---

### 3. Header Compatibility

**Backward Compatibility Period:** 3 months

**Support Matrix:**

| Period | Legacy Headers (Separate) | New Headers (Combined) |
|--------|--------------------------|------------------------|
| Month 1-2 | ✓ Supported | ✓ Supported |
| Month 3 | ⚠️ Deprecated (warnings) | ✓ Supported |
| Month 4+ | ✗ Removed | ✓ Supported |

**Migration Path:**
1. Deploy identity service with dual support
2. Update client SDKs to use combined format
3. Monitor usage of legacy headers
4. Send deprecation warnings in response headers
5. Remove legacy header support after 3 months

---

### 4. Replay Protection

**Two-Factor Protection:**
1. **Timestamp Window:** ±5 minutes tolerance
2. **Nonce Uniqueness:** Tracked for 10 minutes (2x timestamp window)

**Storage Strategy:**
- **Primary:** Redis (distributed, atomic operations)
- **Fallback:** In-memory Map (single-pod protection with sticky sessions)

**Performance:**
- Redis SET NX: <1ms (local)
- In-memory Map: <0.1ms
- Cleanup: Every 5 minutes

---

### 5. Dependencies

**Identity Service Already Has:**
- ✓ Fastify framework
- ✓ PostgreSQL client (pg)
- ✓ Redis client (ioredis)
- ✓ Node.js crypto module (ECDH, HKDF)

**No New Dependencies Required!**

---

### 6. Monitoring & Alerts

**Key Metrics:**

| Metric | Threshold | Alert |
|--------|-----------|-------|
| Error rate | >1% | Warning |
| Error rate | >5% | Critical |
| P99 latency | >100ms | Warning |
| P99 latency | >500ms | Critical |
| Redis cache hit rate | <80% | Warning |
| PostgreSQL connection pool | >90% | Warning |
| In-memory nonce store size | >100K | Warning |
| Replay attack rate | >0.1% | Warning |

**Dashboards:**
- Request rate (req/s)
- Latency percentiles (P50, P95, P99)
- Error rate by type
- Redis cache hit/miss ratio
- PostgreSQL query performance
- In-memory fallback usage
- Replay attack attempts

---

### 7. Security Considerations

**Key Zeroization:**
- Shared secret zeroized immediately after HKDF
- Session key zeroized after storage
- Critical for preventing memory dumps

**Buffer Management:**
- Always copy buffers before encoding (prevent mutation)
- Use `Buffer.fill(0)` for zeroization
- Avoid string conversions of sensitive data

**Replay Protection:**
- Timestamp window: ±5 minutes (prevents clock skew issues)
- Nonce TTL: 10 minutes (2x timestamp window for safety)
- HMAC signature verification before nonce check (prevent nonce exhaustion attacks)

**Session ID Generation:**
- 128-bit entropy (crypto.randomBytes(16))
- Prefix: "S-" for SESSION or "A-" for AUTH
- Format: `S-{32-char-hex}`

---

### 8. Performance Optimization

**Caching Strategy:**
- Redis: L1 cache (distributed)
- In-memory: L2 fallback (local)
- PostgreSQL: Source of truth

**Connection Pooling:**
- PostgreSQL: 25 connections (configurable)
- Redis: Single persistent connection per pod

**Lazy Loading:**
- Session data fetched only when needed
- No pre-loading or warming

**Cleanup:**
- PostgreSQL: Expired sessions deleted via cron job (daily)
- Redis: TTL-based expiration (automatic)
- In-memory: Periodic cleanup every 5 minutes

---

## Conclusion

This migration plan provides a comprehensive, step-by-step approach to integrating the `/session/init` endpoint into the identity service. Key benefits:

1. **Unified Authentication & Session Management** - Single service for OAuth2 tokens and encrypted sessions
2. **Consistent Header Format** - Simplified client integration with combined idempotency header
3. **High Availability** - In-memory fallback ensures service continuity during Redis downtime
4. **Backward Compatibility** - Gradual migration with support for legacy header format
5. **Production-Ready** - Comprehensive testing, monitoring, and rollback procedures

**Estimated Timeline:** 8 weeks from planning to full production deployment

**Risk Level:** Medium (mitigated by gradual rollout and comprehensive testing)

**Next Steps:**
1. Review and approve this plan
2. Allocate development resources
3. Begin Phase 1 implementation
4. Schedule stakeholder meetings

---

## Appendix

### A. Related Documentation

- [Session Crypto PoC Architecture](./README.md)
- [Identity Service API Documentation](../identity-service/docs/API_ENDPOINTS_REFERENCE.md)
- [HMAC Authentication Guide](../identity-service/docs/PARTNER_INTEGRATION_GUIDE.md)
- [Security Best Practices](./docs/SECURITY.md)

### B. Contact Information

**Technical Leads:**
- Architecture: [Name] <email>
- Security: [Name] <email>
- DevOps: [Name] <email>

**On-Call:**
- Identity Service: [Slack Channel / PagerDuty]
- Database: [Slack Channel / PagerDuty]

### C. Glossary

- **ECDH**: Elliptic Curve Diffie-Hellman (key exchange)
- **HKDF**: HMAC-based Key Derivation Function
- **AAD**: Additional Authenticated Data (for AEAD)
- **AEAD**: Authenticated Encryption with Associated Data
- **P-256**: NIST P-256 elliptic curve (secp256r1)
- **AES-256-GCM**: AES with 256-bit key in Galois/Counter Mode

---

**Document Version:** 1.0
**Last Updated:** 2026-01-27
**Status:** Draft - Pending Approval
