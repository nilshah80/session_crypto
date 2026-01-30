/**
 * Session types and interfaces
 * Based on session-crypto/server/src/session-store.ts
 */

/**
 * Request body for /session/init endpoint
 */
export interface SessionInitBody {
  /** Client's ECDH P-256 public key (base64 encoded, 65 bytes uncompressed) */
  clientPublicKey: string;

  /** Requested session TTL in seconds (clamped to configured min/max) */
  ttlSec?: number;
}

/**
 * Response from /session/init endpoint
 */
export interface SessionInitResponse {
  /** Generated session ID (format: S-{32-hex-chars}) */
  sessionId: string;

  /** Server's ECDH P-256 public key (base64 encoded) */
  serverPublicKey: string;

  /** Encryption algorithm identifier */
  encAlg: string;

  /** Session expiration time in seconds from now */
  expiresInSec: number;
}

/**
 * Session data stored in cache (Redis/LRU)
 * Used for in-memory session representation
 */
export interface SessionData {
  /** Derived AES-256-GCM session key (base64 encoded, 32 bytes) */
  key: string;

  /** Session type identifier */
  type: string;

  /** Expiration timestamp (Unix milliseconds) - required for server compatibility */
  expiresAt: number;

  /** Principal/user identifier (optional) */
  principal?: string;

  /** Client identifier */
  clientId: string;
}

/**
 * Session data with expiration timestamp
 * Used internally when retrieving from database for cache warming
 */
export interface SessionWithExpiry {
  /** Session data */
  data: SessionData;

  /** Expiration timestamp */
  expiresAt: Date;
}

/**
 * Session record in PostgreSQL
 * Uses separate columns instead of JSONB
 */
export interface SessionRow {
  session_id: string;
  session_key: string;
  session_type: string;
  client_id: string;
  principal?: string;
  expires_at: Date;
  created_at: Date;
}

/**
 * Response from GET /v1/session/:sessionId endpoint
 */
export interface SessionKeyResponse {
  /** Session ID */
  sessionId: string;

  /** Session key (base64 encoded) */
  sessionKey: string;

  /** Expiration timestamp (Unix milliseconds) */
  expiresAt: number;
}
