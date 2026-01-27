import { BaseRepository } from './base.repository';
import { SessionData, SessionWithExpiry } from '../../types/session.types';

/**
 * Repository interface for Session entity operations
 */
export interface SessionRepository extends BaseRepository {
  /**
   * Create a new session in PostgreSQL
   * @param sessionId Session identifier
   * @param sessionData Session data (key, type, clientId, principal)
   * @param expiresAt Session expiration date
   */
  createSession(sessionId: string, sessionData: SessionData, expiresAt: Date): Promise<void>;

  /**
   * Get session by ID from PostgreSQL
   * @param sessionId Session identifier
   * @returns Session data with expiration or null if not found
   */
  getSessionById(sessionId: string): Promise<SessionWithExpiry | null>;

  /**
   * Delete session from PostgreSQL
   * @param sessionId Session identifier
   * @returns true if session was deleted, false if not found
   */
  deleteSession(sessionId: string): Promise<boolean>;

  /**
   * Ensure sessions table exists (for initialization)
   */
  ensureSessionsTable(): Promise<void>;
}
