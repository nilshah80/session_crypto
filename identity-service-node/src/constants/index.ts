/**
 * Application Constants
 *
 * This file contains internal constants that do not require external configuration.
 * For values that should be configurable via environment variables, use config/index.ts
 */

// ============================================================================
// Time Conversion Constants
// ============================================================================
export const TIME = {
  /** Milliseconds in one second */
  MS_PER_SECOND: 1000,

  /** Seconds in one minute */
  SECONDS_PER_MINUTE: 60,

  /** Minutes in one hour */
  MINUTES_PER_HOUR: 60,

  /** Hours in one day */
  HOURS_PER_DAY: 24,

  /** Milliseconds in one day */
  MS_PER_DAY: 24 * 60 * 60 * 1000,
} as const;

// ============================================================================
// Cache Constants
// ============================================================================
export const CACHE = {
  /** Default max size for LRU cache */
  LRU_DEFAULT_MAX_SIZE: 10000,

  /** Default TTL for LRU cache in milliseconds (5 minutes) */
  LRU_DEFAULT_TTL_MS: 300000,

  /** LRU cache cleanup interval in milliseconds (60 seconds) */
  LRU_CLEANUP_INTERVAL_MS: 60000,

  /** Redis periodic reconnect interval in milliseconds (30 seconds) */
  REDIS_PERIODIC_RECONNECT_INTERVAL_MS: 30000,

  /** Redis fallback cache max size */
  REDIS_FALLBACK_MAX_SIZE: 50000,

  /** Redis connection timeout in milliseconds (5 seconds) */
  REDIS_CONNECTION_TIMEOUT_MS: 5000,

  /** Memory nonce cleanup interval in milliseconds (60 seconds) */
  MEMORY_NONCE_CLEANUP_INTERVAL_MS: 60000,

  /** Maximum size for in-memory nonce store (fail-closed when exceeded) */
  MEMORY_NONCE_MAX_SIZE: 50000,
} as const;

// ============================================================================
// Repository Constants
// ============================================================================
export const REPOSITORY = {
  /** Cleanup interval for stale pending queries in milliseconds (1 minute) */
  CLEANUP_INTERVAL_MS: 60000,
} as const;

// ============================================================================
// Crypto Constants
// ============================================================================
export const CRYPTO = {
  /** ECDH curve name */
  ECDH_CURVE: 'prime256v1',

  /** ECDH key format */
  ECDH_KEY_FORMAT: 'spki',

  /** AES-GCM algorithm */
  AES_ALGORITHM: 'aes-256-gcm',

  /** AES-GCM key length in bytes */
  AES_KEY_LENGTH: 32,

  /** AES-GCM IV length in bytes */
  AES_IV_LENGTH: 12,

  /** AES-GCM auth tag length in bytes */
  AES_TAG_LENGTH: 16,

  /** Session ID length in bytes */
  SESSION_ID_LENGTH: 16,

  /** Session ID prefix */
  SESSION_ID_PREFIX: 'S-',

  /** Minimum nonce length in characters */
  MIN_NONCE_LENGTH: 16,
} as const;

// ============================================================================
// Session Constants
// ============================================================================
export const SESSION = {
  /** Session type for ECDH sessions */
  TYPE_ECDH: 'ecdh',

  /** Encryption algorithm identifier */
  ENCRYPTION_ALGORITHM: 'aes-256-gcm',
} as const;
