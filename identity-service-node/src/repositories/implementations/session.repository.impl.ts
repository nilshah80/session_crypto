import { SessionRepository } from '../interfaces/session.repository';
import { BaseRepositoryImpl } from './base.repository.impl';
import { SessionData, SessionWithExpiry, SessionRow } from '../../types/session.types';
import { logger } from '../../utils/logger';

/**
 * Session repository implementation
 * Handles all PostgreSQL operations for sessions
 * Based on session-crypto/server/src/session-store.ts
 */
export class SessionRepositoryImpl extends BaseRepositoryImpl implements SessionRepository {
  /**
   * Ensure sessions table exists with separate columns
   */
  async ensureSessionsTable(): Promise<void> {
    const migrationSql = `
      CREATE TABLE IF NOT EXISTS sessions (
        session_id VARCHAR(255) PRIMARY KEY,
        session_key TEXT NOT NULL,
        session_type VARCHAR(50) NOT NULL,
        client_id VARCHAR(255) NOT NULL,
        principal VARCHAR(255),
        expires_at TIMESTAMPTZ NOT NULL,
        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
      );
      CREATE INDEX IF NOT EXISTS idx_sessions_expires_at ON sessions(expires_at);
      CREATE INDEX IF NOT EXISTS idx_sessions_created_at ON sessions(created_at);
      CREATE INDEX IF NOT EXISTS idx_sessions_client_id ON sessions(client_id);
    `;

    try {
      await this.query(migrationSql);
    } catch (error) {
      logger.error('SessionRepository', 'Failed to ensure sessions table', error as Error);
      throw error;
    }
  }

  /**
   * Create a new session in PostgreSQL with separate columns
   */
  async createSession(
    sessionId: string,
    sessionData: SessionData,
    expiresAt: Date
  ): Promise<void> {
    try {
      await this.query(
        `INSERT INTO sessions (session_id, session_key, session_type, client_id, principal, expires_at)
         VALUES ($1, $2, $3, $4, $5, $6)
         ON CONFLICT (session_id) DO UPDATE
         SET session_key = $2, session_type = $3, client_id = $4, principal = $5, expires_at = $6`,
        [
          sessionId,
          sessionData.key,
          sessionData.type,
          sessionData.clientId,
          sessionData.principal || null,
          expiresAt,
        ]
      );

      logger.debug('SessionRepository', 'Session created', undefined, { sessionId });
    } catch (error) {
      logger.error('SessionRepository', 'Failed to create session', error, undefined, undefined, undefined, {
        sessionId,
      });
      throw error;
    }
  }

  /**
   * Get session by ID from PostgreSQL
   * Returns session data with expiration timestamp for cache warming
   */
  async getSessionById(sessionId: string): Promise<SessionWithExpiry | null> {
    try {
      const result = await this.query<SessionRow>(
        'SELECT session_key, session_type, client_id, principal, expires_at FROM sessions WHERE session_id = $1',
        [sessionId]
      );

      if (result.rows.length === 0) {
        return null;
      }

      const row = result.rows[0];
      if (!row) {
        return null;
      }

      // Check if session has expired
      const now = new Date();
      if (row.expires_at && row.expires_at < now) {
        logger.debug('SessionRepository', 'Session expired', undefined, { sessionId });
        // Clean up expired session
        await this.deleteSession(sessionId);
        return null;
      }

      // Map row columns to SessionData and include expiration
      return {
        data: this.mapRowToEntity(row),
        expiresAt: row.expires_at,
      };
    } catch (error) {
      logger.error('SessionRepository', 'Failed to get session', error, undefined, undefined, undefined, {
        sessionId,
      });
      throw error;
    }
  }

  /**
   * Delete session from PostgreSQL
   */
  async deleteSession(sessionId: string): Promise<boolean> {
    try {
      const result = await this.query('DELETE FROM sessions WHERE session_id = $1', [
        sessionId,
      ]);

      const deleted = (result.rowCount ?? 0) > 0;
      if (deleted) {
        logger.debug('SessionRepository', 'Session deleted', undefined, { sessionId });
      }

      return deleted;
    } catch (error) {
      logger.error('SessionRepository', 'Failed to delete session', error, undefined, undefined, undefined, {
        sessionId,
      });
      throw error;
    }
  }

  /**
   * Map database row to entity (required by BaseRepositoryImpl)
   */
  protected mapRowToEntity(row: SessionRow): SessionData {
    const data: SessionData = {
      key: row.session_key,
      type: row.session_type,
      clientId: row.client_id,
    };

    if (row.principal) {
      data.principal = row.principal;
    }

    return data;
  }

  /**
   * Map entity to database row (required by BaseRepositoryImpl)
   */
  protected mapEntityToRow(entity: SessionData): Partial<SessionRow> {
    const row: Partial<SessionRow> = {
      session_key: entity.key,
      session_type: entity.type,
      client_id: entity.clientId,
    };

    if (entity.principal) {
      row.principal = entity.principal;
    }

    return row;
  }
}
