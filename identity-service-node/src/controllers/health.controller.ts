import { FastifyRequest, FastifyReply } from 'fastify';
import { baseRepository } from '../repositories';
import { cacheService } from '../services/cache.service';
import { databaseService } from '../services/database.service';

/**
 * Health check controllers
 */

/**
 * GET /health - Basic health check
 * Returns 200 if service is running
 */
export async function healthCheck(
  _request: FastifyRequest,
  reply: FastifyReply
): Promise<void> {
  reply.code(200).send({
    status: 'ok',
    timestamp: new Date().toISOString(),
  });
}

/**
 * GET /ready - Readiness check
 * Checks database and cache connectivity
 */
export async function readinessCheck(
  _request: FastifyRequest,
  reply: FastifyReply
): Promise<void> {
  try {
    // Check database
    const dbHealthy = await baseRepository.healthCheck();

    // Check cache (Redis)
    const cacheHealthy = await cacheService.healthCheck();

    // Get database pool status
    const poolStatus = databaseService.getPoolStatus();

    if (!dbHealthy) {
      reply.code(503).send({
        status: 'unhealthy',
        database: 'down',
        cache: cacheHealthy ? 'up' : 'down',
        timestamp: new Date().toISOString(),
      });
      return;
    }

    reply.code(200).send({
      status: 'ready',
      database: 'up',
      cache: cacheHealthy ? 'up' : 'degraded',
      pool: poolStatus,
      timestamp: new Date().toISOString(),
    });
  } catch (error) {
    reply.code(503).send({
      status: 'error',
      message: (error as Error).message,
      timestamp: new Date().toISOString(),
    });
  }
}
