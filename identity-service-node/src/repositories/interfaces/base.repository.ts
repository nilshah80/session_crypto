import { PoolClient } from 'pg';

/**
 * Base repository interface with common database operations
 */
export interface BaseRepository {
  /**
   * Execute operation within a database transaction
   */
  withTransaction<T>(operation: (client: PoolClient) => Promise<T>): Promise<T>;

  /**
   * Health check for database connectivity
   */
  healthCheck(): Promise<boolean>;
}
