import { FastifyRequest, FastifyReply } from 'fastify';
import { sessionService } from '../services/session.service';
import { SessionInitBody } from '../types/session.types';
import log from '../utils/logger';

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
      log.warn('SessionController', 'Missing X-Idempotency-Key header');
      reply.code(400).send({
        error: 'Bad Request',
        message: 'X-Idempotency-Key header is required',
      });
      return;
    }

    if (!clientId) {
      log.warn('SessionController', 'Missing X-ClientId header');
      reply.code(400).send({
        error: 'Bad Request',
        message: 'X-ClientId header is required',
      });
      return;
    }

    // Validate request body
    const { clientPublicKey, ttlSec } = request.body;

    if (!clientPublicKey) {
      log.warn('SessionController', 'Missing clientPublicKey in body');
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
      log.warn('SessionController', 'Invalid timestamp', { error: err.message });
      reply.code(400).send({
        error: 'Bad Request',
        message: 'Invalid or expired timestamp',
      });
      return;
    }

    if (err.message === 'NONCE_INVALID') {
      log.warn('SessionController', 'Invalid nonce', { error: err.message });
      reply.code(400).send({
        error: 'Bad Request',
        message: 'Invalid nonce format',
      });
      return;
    }

    if (err.message === 'REPLAY_DETECTED') {
      log.warn('SessionController', 'Replay attack detected', { error: err.message });
      reply.code(409).send({
        error: 'Conflict',
        message: 'Request already processed (replay detected)',
      });
      return;
    }

    if (err.message === 'SERVICE_UNAVAILABLE') {
      log.error('SessionController', 'Service unavailable', err);
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
      log.warn('SessionController', 'Invalid client public key', { error: err.message });
      reply.code(400).send({
        error: 'Bad Request',
        message: 'Invalid client public key',
      });
      return;
    }

    if (err.message === 'INVALID_IDEMPOTENCY_KEY_FORMAT') {
      log.warn('SessionController', 'Invalid idempotency key format', {
        error: err.message,
      });
      reply.code(400).send({
        error: 'Bad Request',
        message: 'Invalid X-Idempotency-Key format (expected: timestamp.nonce)',
      });
      return;
    }

    if (err.message === 'TTL_INVALID') {
      log.warn('SessionController', 'Invalid TTL value', { error: err.message });
      reply.code(400).send({
        error: 'Bad Request',
        message: 'TTL must be a non-negative integer',
      });
      return;
    }

    // Generic error handling
    log.error('SessionController', 'Session init failed', err);
    reply.code(500).send({
      error: 'Internal Server Error',
      message: 'Failed to initialize session',
    });
  }
}
