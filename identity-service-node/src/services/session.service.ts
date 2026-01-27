import { requestValidationService } from './request-validation.service';
import { sessionStoreService } from './session-store.service';
import { SessionInitBody, SessionInitResponse, SessionData } from '../types/session.types';
import { config } from '../config';
import { SESSION, CRYPTO } from '../constants';
import {
  createEcdhKeypair,
  validateP256PublicKey,
  hkdf32,
  unb64,
  b64,
  generateSessionId,
  zeroizeBuffer,
} from '../utils/crypto-helpers';
import log from '../utils/logger';

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

    try {
      // 5. Derive session key using HKDF
      const salt = Buffer.from(CRYPTO.HKDF_SALT, 'utf8');
      const info = Buffer.from(CRYPTO.HKDF_INFO, 'utf8');
      const sessionKey = hkdf32(sharedSecret, salt, info);

      // 6. Generate session ID
      const sessionId = generateSessionId('S');

      // 7. Validate and calculate TTL
      // Reject negative or non-integer TTL values (matches server behavior)
      if (body.ttlSec !== undefined && (body.ttlSec < 0 || !Number.isInteger(body.ttlSec))) {
        throw new Error('TTL_INVALID');
      }

      // Cap TTL between configured min and max (clamping behavior matches server)
      const requestedTtl = body.ttlSec ?? config.SESSION_TTL_DEFAULT_SEC;
      const ttlSec = Math.max(
        config.SESSION_TTL_MIN_SEC,
        Math.min(requestedTtl, config.SESSION_TTL_MAX_SEC)
      );

      // 8. Create session data
      const sessionData: SessionData = {
        key: b64(sessionKey),
        type: SESSION.TYPE_ECDH,
        clientId,
      };

      // 9. Store session (expiration calculated in sessionStoreService from ttlSec)
      await sessionStoreService.storeSession(sessionId, sessionData, ttlSec);

      // 10. Zeroize sensitive buffers
      zeroizeBuffer(sharedSecret);
      zeroizeBuffer(sessionKey);

      log.info('SessionService', 'Session created successfully', {
        sessionId,
        clientId,
        ttlSec,
      });

      // 11. Return response
      return {
        sessionId,
        serverPublicKey: b64(serverPublicKey),
        encAlg: SESSION.ENCRYPTION_ALGORITHM,
        expiresInSec: ttlSec,
      };
    } catch (error) {
      // Ensure sensitive data is zeroized even on error
      zeroizeBuffer(sharedSecret);
      log.error('SessionService', 'Failed to create session', error as Error, {
        clientId,
      });
      throw error;
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
