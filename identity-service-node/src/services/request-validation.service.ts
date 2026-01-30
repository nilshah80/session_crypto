import { cacheService } from './cache.service';
import { config } from '../config';
import { CRYPTO, CACHE } from '../constants';
import { logger } from '../utils/logger';

/**
 * RequestValidationService - Generic replay protection service
 * Reusable across all endpoints (both authenticated and public)
 *
 * Based on session-crypto/server/src/crypto-helpers.ts (validateReplayProtection)
 * 
 * Storage: Redis primary with in-memory fallback for high availability
 * 
 * Deployment: Uses sticky sessions (session affinity) so all requests from
 * a client route to the same pod. This ensures in-memory fallback provides
 * full replay protection even when Redis is unavailable.
 */

const NONCE_PREFIX = 'nonce:';

export class RequestValidationService {
  private readonly timestampWindowMs: number;
  private readonly nonceTtlSec: number;

  /**
   * In-memory nonce store as fallback when Redis is unavailable
   * Key: nonce key, Value: timestamp when stored
   */
  private memoryNonceStore = new Map<string, number>();
  private cleanupInterval: NodeJS.Timeout | null = null;

  constructor() {
    this.timestampWindowMs = config.REPLAY_TIMESTAMP_WINDOW_SEC * 1000;
    this.nonceTtlSec = config.REPLAY_NONCE_TTL_SEC;

    // Start periodic cleanup of expired nonces from memory
    this.startMemoryCleanup();
  }

  /**
   * Start periodic cleanup of expired nonces from in-memory fallback store
   */
  private startMemoryCleanup(): void {
    this.cleanupInterval = setInterval(() => {
      this.cleanupExpiredMemoryNonces();
    }, CACHE.MEMORY_NONCE_CLEANUP_INTERVAL_MS);

    // Don't prevent Node.js from exiting
    this.cleanupInterval.unref?.();
  }

  /**
   * Cleanup expired nonces from in-memory fallback store
   */
  private cleanupExpiredMemoryNonces(): void {
    const now = Date.now();
    const ttlMs = this.nonceTtlSec * 1000;
    let cleaned = 0;

    for (const [key, timestamp] of this.memoryNonceStore) {
      if (now - timestamp > ttlMs) {
        this.memoryNonceStore.delete(key);
        cleaned++;
      }
    }

    if (cleaned > 0) {
      logger.debug('RequestValidationService', 'Cleaned expired memory nonces', undefined, {
        cleaned,
        remaining: this.memoryNonceStore.size,
      });
    }
  }

  /**
   * Dispose resources (call during graceful shutdown)
   */
  dispose(): void {
    if (this.cleanupInterval) {
      clearInterval(this.cleanupInterval);
      this.cleanupInterval = null;
    }
    this.memoryNonceStore.clear();
  }

  /**
   * Validate timestamp and nonce for replay protection
   *
   * Two-factor replay protection:
   * 1. Timestamp window check (±5 minutes by default)
   * 2. Nonce uniqueness check (atomic SET NX operation)
   *
   * @param timestamp Timestamp string (milliseconds since epoch)
   * @param nonce Unique nonce string (min 16 characters)
   * @param clientId Client identifier (scopes nonce per-client)
   * @throws Error if timestamp is invalid or nonce has been used
   */
  async validateTimestampAndNonce(timestamp: string, nonce: string, clientId: string): Promise<void> {
    // 1. Validate nonce length
    if (!nonce || nonce.length < CRYPTO.MIN_NONCE_LENGTH) {
      logger.warn('RequestValidationService', 'Nonce too short', undefined, undefined, undefined, undefined, {
        nonceLength: nonce?.length || 0,
      });
      throw new Error('NONCE_INVALID');
    }

    // 2. Timestamp window check
    const ts = parseInt(timestamp, 10);
    const now = Date.now();

    if (isNaN(ts)) {
      logger.warn('RequestValidationService', 'Invalid timestamp format', undefined, undefined, undefined, undefined, { timestamp });
      throw new Error('TIMESTAMP_INVALID');
    }

    if (Math.abs(now - ts) > this.timestampWindowMs) {
      logger.warn('RequestValidationService', 'Timestamp outside window', undefined, undefined, undefined, undefined, {
        timestamp: ts,
        now,
        diff: now - ts,
        windowMs: this.timestampWindowMs,
      });
      throw new Error('TIMESTAMP_INVALID');
    }

    // 3. Nonce uniqueness check (CRITICAL for replay protection)
    // SECURITY: Use atomic SET NX operation to prevent race conditions
    const nonceKey = `${NONCE_PREFIX}${clientId}:${nonce}`;

    try {
      // Atomic set-if-not-exists (STRICT mode - throws if Redis unavailable)
      // This prevents race conditions where two requests with same nonce could both pass
      const wasSet = await cacheService.setIfNotExistsStrict(nonceKey, true, this.nonceTtlSec);

      if (!wasSet) {
        // Nonce already exists - replay attack detected
        logger.warn('RequestValidationService', 'Replay attack detected', undefined, undefined, undefined, undefined, {
          nonce,
          timestamp: ts,
        });
        throw new Error('REPLAY_DETECTED');
      }

      logger.debug('RequestValidationService', 'Request validated', undefined, {
        timestamp: ts,
        nonceTtl: this.nonceTtlSec,
      });
    } catch (error) {
      // Re-throw REPLAY_DETECTED - don't mask it
      if ((error as Error).message === 'REPLAY_DETECTED') {
        throw error;
      }

      // Redis unavailable - fall back to in-memory nonce tracking
      // With sticky sessions, this provides full replay protection
      logger.warn(
        'RequestValidationService',
        'Redis unavailable for nonce check - using in-memory fallback',
        undefined,
        undefined,
        undefined,
        undefined,
        { nonce: nonce.substring(0, 8) + '...', error: (error as Error).message }
      );

      this.checkAndStoreNonceInMemory(nonceKey, ts);
    }
  }

  /**
   * In-memory nonce check fallback
   * Provides single-pod replay protection when Redis is unavailable
   * @throws Error if nonce has already been used
   */
  private checkAndStoreNonceInMemory(nonceKey: string, timestamp: number): void {
    const now = Date.now();
    const existingTimestamp = this.memoryNonceStore.get(nonceKey);

    if (existingTimestamp !== undefined) {
      // Check if nonce has expired in memory
      const ttlMs = this.nonceTtlSec * 1000;
      if (now - existingTimestamp < ttlMs) {
        logger.warn('RequestValidationService', 'Replay attack detected (in-memory)', undefined, undefined, undefined, undefined, {
          nonceKey: nonceKey.substring(0, 20) + '...',
        });
        throw new Error('REPLAY_DETECTED');
      }
      // Nonce expired in memory, allow reuse
    }

    // Capacity guard: fail-closed if memory store is full
    if (this.memoryNonceStore.size >= CACHE.MEMORY_NONCE_MAX_SIZE) {
      logger.error('RequestValidationService', 'Memory nonce store at capacity - rejecting request', undefined, undefined, undefined, undefined, {
        size: this.memoryNonceStore.size,
        maxSize: CACHE.MEMORY_NONCE_MAX_SIZE,
      });
      throw new Error('SERVICE_UNAVAILABLE');
    }

    // Store nonce with current timestamp
    this.memoryNonceStore.set(nonceKey, now);

    logger.debug('RequestValidationService', 'Request validated (in-memory fallback)', undefined, {
      timestamp,
      nonceTtl: this.nonceTtlSec,
    });
  }

  /**
   * Parse idempotency key header format: timestamp.nonce
   * @param idempotencyKey Header value
   * @returns Parsed timestamp and nonce
   * @throws Error if format is invalid
   */
  parseIdempotencyKey(idempotencyKey: string): { timestamp: string; nonce: string } {
    const parts = idempotencyKey.split('.');
    if (parts.length !== 2) {
      throw new Error('INVALID_IDEMPOTENCY_KEY_FORMAT');
    }

    const [timestamp, nonce] = parts;
    if (!timestamp || !nonce) {
      throw new Error('INVALID_IDEMPOTENCY_KEY_FORMAT');
    }

    return { timestamp, nonce };
  }
}

// Export singleton instance
export const requestValidationService = new RequestValidationService();
