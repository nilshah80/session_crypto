import { FastifyInstance } from 'fastify';
import { healthCheck, readinessCheck } from '../controllers/health.controller';
import { initSession, getSessionKey } from '../controllers/session.controller';

/**
 * API version prefix
 */
const API_VERSION = '/v1';

/**
 * Register all application routes
 */
export async function registerRoutes(fastify: FastifyInstance): Promise<void> {
  // Health endpoints (no authentication required, no version prefix)
  fastify.get('/health', healthCheck);
  fastify.get('/ready', readinessCheck);

  // Versioned API routes
  await fastify.register(
    async api => {
      // Session initialization endpoint (public - no authentication middleware)
      // Authentication handled via APIM subscription key
      api.post('/session/init', initSession);

      // Get session key endpoint
      // No replay protection - handled during decryption
      api.get('/session/:sessionId', getSessionKey);
    },
    { prefix: API_VERSION }
  );
}
