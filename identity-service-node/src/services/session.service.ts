import { requestValidationService } from './request-validation.service';
import { sessionStoreService } from './session-store.service';
import { SessionInitBody, SessionInitResponse, SessionData } from '../types/session.types';
import { config } from '../config';
import { SESSION } from '../constants';
import {
  createEcdhKeypair,
  validateP256PublicKey,
  hkdf32,
  unb64,
  b64,
  generateSessionId,
  zeroizeBuffer,
} from '../utils/crypto-helpers';
import { logger } from '../utils/logger';

/**
 * SessionService - Business logic for session management
 * Handles ECDH key exchange, HKDF key derivation, and session creation
 *
 * Based on session-crypto/server/src/crypto-helpers.ts (createSession logic)
 */

export class SessionService {
  /**
   * Create a new session via ECDH key exchange
   * @param body Request body with client public key and optional TTL
   * @param idempotencyKey Idempotency key (timestamp.nonce)
   * @param clientId Client identifier
   * @returns Session init response with server public key and session ID
   */
  async createSession(
    body: SessionInitBody,
    idempotencyKey: string,
    clientId: string
  ): Promise<SessionInitResponse> {
    // 1. Validate replay protection (timestamp + nonce)
    const { timestamp, nonce } = requestValidationService.parseIdempotencyKey(idempotencyKey);
    await requestValidationService.validateTimestampAndNonce(timestamp, nonce);

    // 2. Validate and parse client public key
    const clientPublicKeyBytes = unb64(body.clientPublicKey);
    validateP256PublicKey(clientPublicKeyBytes);

    // 3. Generate server ECDH keypair
    const { ecdh: serverEcdh, publicKey: serverPublicKey } = createEcdhKeypair();

    // 4. Compute ECDH shared secret
    const sharedSecret = serverEcdh.computeSecret(clientPublicKeyBytes);

    // Declare sessionKey outside try block for proper cleanup on all error paths
    let sessionKey: Buffer | undefined;

    try {
      // 5. Generate session ID (needed for HKDF salt)
      const sessionId = generateSessionId('S');

      // 6. Derive session key using HKDF
      // Salt: sessionId provides per-session uniqueness
      // Info: includes clientId for domain separation (matches server behavior)
      // Format: SESSION|A256GCM|{clientId} (A256GCM is the JWE algorithm identifier)
      const salt = Buffer.from(sessionId, 'utf8');
      const info = Buffer.from(`SESSION|A256GCM|${clientId}`, 'utf8');
      sessionKey = hkdf32(sharedSecret, salt, info);

      // 7. Validate and calculate TTL
      // Reject negative or non-integer TTL values (matches server behavior)
      if (body.ttlSec !== undefined && (body.ttlSec < 0 || !Number.isInteger(body.ttlSec))) {
        throw new Error('TTL_INVALID');
      }

      // 8. Cap TTL between configured min and max
      // NOTE: TTL clamping behavior - values outside [SESSION_TTL_MIN_SEC, SESSION_TTL_MAX_SEC]
      // are silently clamped to the nearest boundary. TTL of 0 is clamped to SESSION_TTL_MIN_SEC.
      const requestedTtl = body.ttlSec ?? config.SESSION_TTL_DEFAULT_SEC;
      const ttlSec = Math.max(
        config.SESSION_TTL_MIN_SEC,
        Math.min(requestedTtl, config.SESSION_TTL_MAX_SEC)
      );

      // 9. Create session data
      const sessionData: SessionData = {
        key: b64(sessionKey),
        type: SESSION.TYPE_ECDH,
        clientId,
      };

      // 10. Store session (expiration calculated in sessionStoreService from ttlSec)
      await sessionStoreService.storeSession(sessionId, sessionData, ttlSec);

      // 11. Return response
      return {
        sessionId,
        serverPublicKey: b64(serverPublicKey),
        encAlg: SESSION.ENCRYPTION_ALGORITHM,
        expiresInSec: ttlSec,
      };
    } catch (error) {
      logger.error('SessionService', 'Failed to create session', error, undefined, undefined, undefined, {
        clientId,
      });
      throw error;
    } finally {
      // SECURITY: Always zeroize sensitive buffers, even on error paths
      // This matches the pattern used in server/src/index.ts for /transaction/purchase
      zeroizeBuffer(sharedSecret);
      if (sessionKey) {
        zeroizeBuffer(sessionKey);
      }
    }
  }

  /**
   * Get session by ID
   * @param sessionId Session identifier
   * @returns Session data or null if not found
   */
  async getSession(sessionId: string): Promise<SessionData | null> {
    return await sessionStoreService.getSession(sessionId);
  }

  /**
   * Delete session by ID
   * @param sessionId Session identifier
   * @returns true if session was deleted
   */
  async deleteSession(sessionId: string): Promise<boolean> {
    return await sessionStoreService.deleteSession(sessionId);
  }
}

// Export singleton instance
export const sessionService = new SessionService();
