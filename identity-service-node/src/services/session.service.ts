import { requestValidationService } from './request-validation.service';
import { sessionStoreService } from './session-store.service';
import { SessionInitBody, SessionInitResponse, SessionData, SessionKeyResponse } from '../types/session.types';
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
   * @param body Request body with client public key
   * @param idempotencyKey Idempotency key (timestamp.nonce)
   * @param clientId Client identifier
   * @param isAuthenticated Whether the request has a valid Authorization header (authenticated flow)
   * @returns Session init response with server public key and session ID
   */
  async createSession(
    body: SessionInitBody,
    idempotencyKey: string,
    clientId: string,
    isAuthenticated: boolean
  ): Promise<SessionInitResponse> {
    // 1. Validate replay protection (timestamp + nonce)
    const { timestamp, nonce } = requestValidationService.parseIdempotencyKey(idempotencyKey);
    await requestValidationService.validateTimestampAndNonce(timestamp, nonce, clientId);

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

      // 7. Determine TTL based on authentication status
      // Anonymous flow (no Authorization header): 30 minutes
      // Authenticated flow (Authorization header present): 1 hour
      const ttlSec = isAuthenticated
        ? config.SESSION_TTL_AUTHENTICATED_SEC
        : config.SESSION_TTL_ANONYMOUS_SEC;

      // 8. Determine session type based on authentication status
      const sessionType = isAuthenticated
        ? SESSION.TYPE_AUTHENTICATED
        : SESSION.TYPE_ANONYMOUS;

      // 9. Create session data with expiration
      const expiresAt = Date.now() + ttlSec * 1000;
      const sessionData: SessionData = {
        key: b64(sessionKey),
        type: sessionType,
        expiresAt,
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

  /**
   * Get session key for a specific client (with authorization check)
   * @param sessionId Session identifier
   * @param clientId Client identifier (for authorization)
   * @returns Session key response
   * @throws Error if session not found or client not authorized
   */
  async getSessionKeyForClient(sessionId: string, clientId: string): Promise<SessionKeyResponse> {
    const session = await sessionStoreService.getSession(sessionId);

    if (!session) {
      logger.warn('SessionService', 'Session not found', undefined, undefined, undefined, undefined, {
        sessionId,
        clientId,
      });
      throw new Error('SESSION_NOT_FOUND');
    }

    // Authorization check: verify client owns this session
    if (session.clientId !== clientId) {
      logger.warn('SessionService', 'Unauthorized session access attempt', undefined, undefined, undefined, undefined, {
        sessionId,
        requestingClientId: clientId,
        sessionClientId: session.clientId,
      });
      throw new Error('SESSION_UNAUTHORIZED');
    }

    // Check if session has expired
    if (session.expiresAt < Date.now()) {
      logger.warn('SessionService', 'Session expired', undefined, undefined, undefined, undefined, {
        sessionId,
        expiresAt: session.expiresAt,
      });
      throw new Error('SESSION_EXPIRED');
    }

    return {
      sessionId,
      sessionKey: session.key,
      expiresAt: session.expiresAt,
    };
  }
}

// Export singleton instance
export const sessionService = new SessionService();
