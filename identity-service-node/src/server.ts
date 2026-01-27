import Fastify, { FastifyInstance } from 'fastify';
import helmet from '@fastify/helmet';
import cors from '@fastify/cors';
import formbody from '@fastify/formbody';
import { config } from './config';
import { registerRoutes } from './routes';
import { databaseService } from './services/database.service';
import { cacheService } from './services/cache.service';
import { sessionRepository } from './repositories';
import log from './utils/logger';

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
  log.info('Server', 'Initializing application');

  // Ensure database tables exist
  await sessionRepository.ensureSessionsTable();

  log.info('Server', 'Application initialized successfully');
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

    // Start listening
    await fastify.listen({
      port: config.PORT,
      host: config.HOST,
    });

    log.info('Server', `Server listening on ${config.HOST}:${config.PORT}`, {
      env: config.NODE_ENV,
      port: config.PORT,
    });
  } catch (error) {
    log.error('Server', 'Failed to start server', error as Error);
    process.exit(1);
  }
}

/**
 * Graceful shutdown
 */
async function shutdown(signal: string): Promise<void> {
  log.info('Server', `Received ${signal}, starting graceful shutdown`);

  try {
    // Stop accepting new connections
    await fastify.close();
    log.info('Server', 'Fastify closed');

    // Close cache connection
    await cacheService.close();
    log.info('Server', 'Cache closed');

    // Close database connection
    await databaseService.close();
    log.info('Server', 'Database closed');

    log.info('Server', 'Graceful shutdown completed');
    process.exit(0);
  } catch (error) {
    log.error('Server', 'Error during shutdown', error as Error);
    process.exit(1);
  }
}

// Register shutdown handlers
process.on('SIGTERM', () => shutdown('SIGTERM'));
process.on('SIGINT', () => shutdown('SIGINT'));

// Handle uncaught errors
process.on('uncaughtException', error => {
  log.error('Server', 'Uncaught exception', error);
  shutdown('uncaughtException');
});

process.on('unhandledRejection', (reason, promise) => {
  log.error('Server', 'Unhandled rejection', reason as Error, {
    promise: promise.toString(),
  });
  shutdown('unhandledRejection');
});

// Start the server
start();
