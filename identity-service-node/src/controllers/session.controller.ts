import { FastifyRequest, FastifyReply } from 'fastify';
import { sessionService } from '../services/session.service';
import { SessionInitBody } from '../types/session.types';
import { logger } from '../utils/logger';

/**
 * Session controller - HTTP handlers for session endpoints
 * Public endpoint - no authentication required
 */

/**
 * POST /v1/session/init - Initialize new session with ECDH key exchange
 * Public endpoint authenticated via APIM subscription key
 */
export async function initSession(
  request: FastifyRequest<{ Body: SessionInitBody }>,
  reply: FastifyReply
): Promise<void> {
  try {
    // Extract required headers
    const idempotencyKey = request.headers['x-idempotency-key'] as string | undefined;
    const clientId = request.headers['x-clientid'] as string | undefined;

    // Validate required headers
    if (!idempotencyKey) {
      logger.warn('SessionController', 'Missing X-Idempotency-Key header');
      reply.code(400).send({
        error: 'Bad Request',
        message: 'X-Idempotency-Key header is required',
      });
      return;
    }

    if (!clientId) {
      logger.warn('SessionController', 'Missing X-ClientId header');
      reply.code(400).send({
        error: 'Bad Request',
        message: 'X-ClientId header is required',
      });
      return;
    }

    // Validate request body
    const { clientPublicKey, ttlSec } = request.body;

    if (!clientPublicKey) {
      logger.warn('SessionController', 'Missing clientPublicKey in body');
      reply.code(400).send({
        error: 'Bad Request',
        message: 'clientPublicKey is required',
      });
      return;
    }

    // Create session
    const body: SessionInitBody = { clientPublicKey };
    if (ttlSec !== undefined) {
      body.ttlSec = ttlSec;
    }
    const response = await sessionService.createSession(
      body,
      idempotencyKey,
      clientId
    );

    // Set X-Kid header (session ID as key identifier)
    reply.header('X-Kid', response.sessionId);

    // Return session init response
    reply.code(200).send(response);
  } catch (error) {
    const err = error as Error;

    // Handle specific error types
    if (err.message === 'TIMESTAMP_INVALID') {
      logger.warn('SessionController', 'Invalid timestamp', undefined, undefined, undefined, undefined, { error: err.message });
      reply.code(400).send({
        error: 'Bad Request',
        message: 'Invalid or expired timestamp',
      });
      return;
    }

    if (err.message === 'NONCE_INVALID') {
      logger.warn('SessionController', 'Invalid nonce', undefined, undefined, undefined, undefined, { error: err.message });
      reply.code(400).send({
        error: 'Bad Request',
        message: 'Invalid nonce format',
      });
      return;
    }

    if (err.message === 'REPLAY_DETECTED') {
      logger.warn('SessionController', 'Replay attack detected', undefined, undefined, undefined, undefined, { error: err.message });
      reply.code(409).send({
        error: 'Conflict',
        message: 'Request already processed (replay detected)',
      });
      return;
    }

    if (err.message === 'SERVICE_UNAVAILABLE') {
      logger.error('SessionController', 'Service unavailable', err);
      reply.code(503).send({
        error: 'Service Unavailable',
        message: 'Replay protection service temporarily unavailable',
      });
      return;
    }

    if (
      err.message === 'INVALID_KEY_LENGTH' ||
      err.message === 'INVALID_KEY_FORMAT' ||
      err.message === 'POINT_NOT_ON_CURVE' ||
      err.message === 'INVALID_KEY_TYPE'
    ) {
      logger.warn('SessionController', 'Invalid client public key', undefined, undefined, undefined, undefined, { error: err.message });
      reply.code(400).send({
        error: 'Bad Request',
        message: 'Invalid client public key',
      });
      return;
    }

    if (err.message === 'INVALID_IDEMPOTENCY_KEY_FORMAT') {
      logger.warn('SessionController', 'Invalid idempotency key format', undefined, undefined, undefined, undefined, {
        error: err.message,
      });
      reply.code(400).send({
        error: 'Bad Request',
        message: 'Invalid X-Idempotency-Key format (expected: timestamp.nonce)',
      });
      return;
    }

    if (err.message === 'TTL_INVALID') {
      logger.warn('SessionController', 'Invalid TTL value', undefined, undefined, undefined, undefined, { error: err.message });
      reply.code(400).send({
        error: 'Bad Request',
        message: 'TTL must be a non-negative integer',
      });
      return;
    }

    // Generic error handling
    logger.error('SessionController', 'Session init failed', err);
    reply.code(500).send({
      error: 'Internal Server Error',
      message: 'Failed to initialize session',
    });
  }
}

/**
 * GET /v1/session/:sessionId - Get session key by session ID
 * Requires X-ClientId header for authorization
 * No replay protection check - handled during decryption
 */
export async function getSessionKey(
  request: FastifyRequest<{ Params: { sessionId: string } }>,
  reply: FastifyReply
): Promise<void> {
  try {
    const { sessionId } = request.params;
    const clientId = request.headers['x-clientid'] as string | undefined;

    // Validate required header
    if (!clientId) {
      logger.warn('SessionController', 'Missing X-ClientId header for get session');
      reply.code(400).send({
        error: 'Bad Request',
        message: 'X-ClientId header is required',
      });
      return;
    }

    // Validate sessionId format (S-{32-hex-chars})
    if (!sessionId || !/^S-[a-f0-9]{32}$/.test(sessionId)) {
      logger.warn('SessionController', 'Invalid session ID format', undefined, undefined, undefined, undefined, {
        sessionId,
      });
      reply.code(400).send({
        error: 'Bad Request',
        message: 'Invalid session ID format',
      });
      return;
    }

    // Get session key
    const response = await sessionService.getSessionKeyForClient(sessionId, clientId);

    reply.code(200).send(response);
  } catch (error) {
    const err = error as Error;

    if (err.message === 'SESSION_NOT_FOUND') {
      reply.code(404).send({
        error: 'Not Found',
        message: 'Session not found',
      });
      return;
    }

    if (err.message === 'SESSION_UNAUTHORIZED') {
      reply.code(403).send({
        error: 'Forbidden',
        message: 'Not authorized to access this session',
      });
      return;
    }

    if (err.message === 'SESSION_EXPIRED') {
      reply.code(410).send({
        error: 'Gone',
        message: 'Session has expired',
      });
      return;
    }

    // Generic error handling
    logger.error('SessionController', 'Get session key failed', err);
    reply.code(500).send({
      error: 'Internal Server Error',
      message: 'Failed to get session key',
    });
  }
}
