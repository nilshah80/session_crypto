import Fastify, { FastifyInstance } from 'fastify';
import helmet from '@fastify/helmet';
import cors from '@fastify/cors';
import formbody from '@fastify/formbody';
import { config } from './config';
import { registerRoutes } from './routes';
import { databaseService } from './services/database.service';
import { cacheService } from './services/cache.service';
import { requestValidationService } from './services/request-validation.service';
import { sessionCleanupJob } from './jobs/session-cleanup.job';
import { sessionRepository } from './repositories';
import { logger } from './utils/logger';

/**
 * Identity Service Node - Main server
 * Provides /session/init endpoint for ECDH session establishment
 */

// Create Fastify instance
const fastify: FastifyInstance = Fastify({
  logger: false, // Use custom Winston logger instead
  requestTimeout: config.REQUEST_TIMEOUT_MS,
  connectionTimeout: config.CONNECTION_TIMEOUT_MS,
  bodyLimit: config.BODY_LIMIT_BYTES,
  trustProxy: true,
});

/**
 * Register plugins
 */
async function registerPlugins(): Promise<void> {
  // Security headers
  await fastify.register(helmet, {
    contentSecurityPolicy: {
      directives: {
        defaultSrc: ["'self'"],
        styleSrc: ["'self'", "'unsafe-inline'"],
      },
    },
  });

  // CORS (configure based on requirements)
  await fastify.register(cors, {
    origin: false, // Disable CORS at application level (handled by APIM)
  });

  // Form body parser
  await fastify.register(formbody);
}

/**
 * Initialize application
 */
async function initialize(): Promise<void> {
  // Ensure database tables exist
  await sessionRepository.ensureSessionsTable();
}

/**
 * Start server
 */
async function start(): Promise<void> {
  try {
    // Register plugins
    await registerPlugins();

    // Register routes
    await registerRoutes(fastify);

    // Initialize application
    await initialize();

    // Start session cleanup job
    sessionCleanupJob.start();

    // Start listening
    await fastify.listen({
      port: config.PORT,
      host: config.HOST,
    });
  } catch (error) {
    logger.error('Server', 'Failed to start server', error as Error);
    process.exit(1);
  }
}

/**
 * Graceful shutdown
 */
async function shutdown(signal: string): Promise<void> {
  logger.info('Server', `Received ${signal}, starting graceful shutdown`);

  try {
    // Stop accepting new connections
    await fastify.close();
    logger.info('Server', 'Fastify closed');

    // Stop session cleanup job
    await sessionCleanupJob.stop();

    // Dispose request validation service (cleanup memory nonce store)
    requestValidationService.dispose();

    // Close cache connection
    await cacheService.close();
    logger.info('Server', 'Cache closed');

    // Close database connection
    await databaseService.close();
    logger.info('Server', 'Database closed');

    logger.info('Server', 'Graceful shutdown completed');
    process.exit(0);
  } catch (error) {
    logger.error('Server', 'Error during shutdown', error as Error);
    process.exit(1);
  }
}

// Register shutdown handlers
process.on('SIGTERM', () => shutdown('SIGTERM'));
process.on('SIGINT', () => shutdown('SIGINT'));

// Handle uncaught errors
process.on('uncaughtException', error => {
  logger.error('Server', 'Uncaught exception', error);
  shutdown('uncaughtException');
});

process.on('unhandledRejection', (reason) => {
  logger.error('Server', 'Unhandled rejection', reason instanceof Error ? reason : new Error(String(reason)));
  shutdown('unhandledRejection');
});

// Start the server
start();
