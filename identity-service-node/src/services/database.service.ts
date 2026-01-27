import { Pool, PoolClient } from 'pg';
import { config } from '../config';
import log from '../utils/logger';

/**
 * Database connection pool service
 * Handles only connection pooling and lifecycle management
 */
class DatabaseService {
  private pool: Pool;

  constructor() {
    this.pool = new Pool({
      host: config.DATABASE_HOST,
      port: config.DATABASE_PORT,
      database: config.DATABASE_NAME,
      user: config.DATABASE_USER,
      password: config.DATABASE_PASSWORD,
      max: config.DATABASE_POOL_MAX,
      min: config.DATABASE_POOL_MIN,
      idleTimeoutMillis: config.DATABASE_IDLE_TIMEOUT_MS,
      connectionTimeoutMillis: config.DATABASE_CONNECTION_TIMEOUT_MS,
      statement_timeout: config.DATABASE_STATEMENT_TIMEOUT_MS,
      query_timeout: config.DATABASE_QUERY_TIMEOUT_MS,
      application_name: 'identity-service-node',
    });

    // Handle pool errors
    this.pool.on('error', err => {
      log.error('DatabaseService', 'Unexpected error on idle client', err as Error);
    });

    // Log pool events in development
    if (config.NODE_ENV === 'development') {
      this.pool.on('connect', () => {
        log.debug('DatabaseService', 'New client connected to database');
      });

      this.pool.on('remove', () => {
        log.debug('DatabaseService', 'Client removed from pool');
      });
    }
  }

  /**
   * Get the connection pool for repository use
   */
  getPool(): Pool {
    return this.pool;
  }

  /**
   * Get a client from the pool for transactions
   */
  async getClient(): Promise<PoolClient> {
    return this.pool.connect();
  }

  /**
   * Get pool status for monitoring
   */
  getPoolStatus() {
    return {
      totalCount: this.pool.totalCount,
      idleCount: this.pool.idleCount,
      waitingCount: this.pool.waitingCount,
    };
  }

  /**
   * Close all connections (for graceful shutdown)
   */
  async close(): Promise<void> {
    log.info('DatabaseService', 'Closing database pool');
    await this.pool.end();
  }
}

// Export singleton instance
export const databaseService = new DatabaseService();
