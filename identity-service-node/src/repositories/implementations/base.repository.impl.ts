import { PoolClient, QueryResult, QueryResultRow } from 'pg';
import { BaseRepository } from '../interfaces/base.repository';
import { databaseService } from '../../services/database.service';
import { logger } from '../../utils/logger';
import { config } from '../../config';

/**
 * Base repository implementation providing common database operations
 * Based on identity-service/src/repositories/implementations/base.repository.impl.ts
 */
export abstract class BaseRepositoryImpl implements BaseRepository {
  /**
   * Execute a query with optional parameters
   */
  protected async query<T extends QueryResultRow = any>(
    text: string,
    params?: any[]
  ): Promise<QueryResult<T>> {
    const start = Date.now();
    try {
      const pool = databaseService.getPool();
      const result = await pool.query<T>(text, params);
      const duration = Date.now() - start;

      if (config.NODE_ENV === 'development' && config.LOG_LEVEL === 'debug') {
        logger.debug('BaseRepository', 'Query executed', undefined, {
          query: text.substring(0, 100) + (text.length > 100 ? '...' : ''),
          duration: `${duration}ms`,
          rows: result.rowCount || 0,
        });
      }

      return result;
    } catch (error) {
      const duration = Date.now() - start;
      logger.error('BaseRepository', 'Query failed', error, undefined, undefined, undefined, {
        query: text.substring(0, 100) + (text.length > 100 ? '...' : ''),
        duration: `${duration}ms`,
        params: params ? '[REDACTED]' : undefined,
      });
      throw error;
    }
  }

  /**
   * Execute operation within a database transaction
   */
  async withTransaction<T>(operation: (client: PoolClient) => Promise<T>): Promise<T> {
    const client = await databaseService.getClient();
    try {
      await client.query('BEGIN');
      const result = await operation(client);
      await client.query('COMMIT');
      return result;
    } catch (error) {
      await client.query('ROLLBACK');
      throw error;
    } finally {
      client.release();
    }
  }

  /**
   * Check database connectivity
   */
  async healthCheck(): Promise<boolean> {
    try {
      const result = await this.query('SELECT 1 as health');
      return result.rows.length === 1 && result.rows[0]?.health === 1;
    } catch (error) {
      logger.error('BaseRepository', 'Database health check failed', error as Error);
      return false;
    }
  }

  /**
   * Convert database row to domain entity
   * Subclasses must implement this method
   */
  protected abstract mapRowToEntity(row: any): any;

  /**
   * Convert domain entity to database row
   * Subclasses must implement this method
   */
  protected abstract mapEntityToRow(entity: any): any;
}
