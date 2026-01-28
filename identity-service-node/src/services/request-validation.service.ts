import { cacheService } from './cache.service';
import { config } from '../config';
import { CRYPTO } from '../constants';
import { logger } from '../utils/logger';

/**
 * RequestValidationService - Generic replay protection service
 * Reusable across all endpoints (both authenticated and public)
 *
 * Based on session-crypto/server/src/crypto-helpers.ts (validateReplayProtection)
 */

const NONCE_PREFIX = 'nonce:';

export class RequestValidationService {
  private readonly timestampWindowMs: number;
  private readonly nonceTtlSec: number;

  constructor() {
    this.timestampWindowMs = config.REPLAY_TIMESTAMP_WINDOW_SEC * 1000;
    this.nonceTtlSec = config.REPLAY_NONCE_TTL_SEC;
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
   * @throws Error if timestamp is invalid or nonce has been used
   */
  async validateTimestampAndNonce(timestamp: string, nonce: string): Promise<void> {
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
    const nonceKey = `${NONCE_PREFIX}${nonce}`;

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

      // Redis unavailable - fail closed for security
      logger.error(
        'RequestValidationService',
        'Redis unavailable for replay protection',
        error as Error
      );
      throw new Error('SERVICE_UNAVAILABLE');
    }
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
