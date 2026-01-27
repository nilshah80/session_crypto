import { cacheService } from './cache.service';
import { sessionRepository, SessionRepository } from '../repositories';
import { SessionData } from '../types/session.types';
import { logger } from '../utils/logger';

/**
 * SessionStoreService - Coordinates between cache and repository
 * PostgreSQL as source of truth, Redis as cache
 *
 * Based on session-crypto/server/src/session-store.ts
 */

const SESSION_CACHE_PREFIX = 'sess:';

export class SessionStoreService {
  constructor(
    private readonly cache: typeof cacheService,
    private readonly repository: SessionRepository
  ) {}

  /**
   * Store session in both PostgreSQL and cache
   * @param sessionId Session identifier
   * @param sessionData Session data
   * @param ttlSec TTL in seconds
   */
  async storeSession(
    sessionId: string,
    sessionData: SessionData,
    ttlSec: number
  ): Promise<void> {
    const expiresAt = new Date(Date.now() + ttlSec * 1000);

    try {
      // 1. Write to PostgreSQL (Source of Truth)
      await this.repository.createSession(sessionId, sessionData, expiresAt);

      // 2. Write to Redis (Cache) - best effort
      try {
        const cacheKey = `${SESSION_CACHE_PREFIX}${sessionId}`;
        await this.cache.set(cacheKey, sessionData, ttlSec);
      } catch (cacheError) {
        logger.warn('SessionStoreService', 'Failed to cache session in Redis', undefined, undefined, undefined, undefined, {
          sessionId,
          error: (cacheError as Error).message,
        });
        // Don't throw - PostgreSQL write succeeded
      }
    } catch (error) {
      logger.error('SessionStoreService', 'Failed to store session', error, undefined, undefined, undefined, {
        sessionId,
      });
      throw error;
    }
  }

  /**
   * Get session from cache or PostgreSQL
   * @param sessionId Session identifier
   * @returns Session data or null if not found
   */
  async getSession(sessionId: string): Promise<SessionData | null> {
    const cacheKey = `${SESSION_CACHE_PREFIX}${sessionId}`;

    try {
      // 1. Try cache first (Redis → LRU fallback)
      const cachedSession = await this.cache.get<SessionData>(cacheKey);
      if (cachedSession) {
        logger.debug('SessionStoreService', 'Session found in cache', undefined, { sessionId });
        return cachedSession;
      }

      // 2. Fallback to PostgreSQL
      logger.debug('SessionStoreService', 'Session not in cache, checking PostgreSQL', undefined, {
        sessionId,
      });
      const sessionWithExpiry = await this.repository.getSessionById(sessionId);

      if (sessionWithExpiry) {
        // Warm up cache for next request (best effort)
        try {
          // Calculate remaining TTL
          const now = new Date();
          const remainingTtlSec = Math.max(
            1,
            Math.floor((sessionWithExpiry.expiresAt.getTime() - now.getTime()) / 1000)
          );

          await this.cache.set(cacheKey, sessionWithExpiry.data, remainingTtlSec);
        } catch (cacheError) {
          logger.warn('SessionStoreService', 'Failed to warm up cache', undefined, undefined, undefined, undefined, {
            sessionId,
            error: (cacheError as Error).message,
          });
        }

        return sessionWithExpiry.data;
      }

      return null;
    } catch (error) {
      logger.error('SessionStoreService', 'Failed to get session', error, undefined, undefined, undefined, {
        sessionId,
      });
      throw error;
    }
  }

  /**
   * Delete session from both cache and PostgreSQL
   * @param sessionId Session identifier
   * @returns true if session was deleted
   */
  async deleteSession(sessionId: string): Promise<boolean> {
    const cacheKey = `${SESSION_CACHE_PREFIX}${sessionId}`;

    try {
      // Delete from both cache and PostgreSQL
      const [deleted] = await Promise.all([
        this.repository.deleteSession(sessionId),
        this.cache.delete(cacheKey).catch(err => {
          logger.warn('SessionStoreService', 'Failed to delete from cache', undefined, undefined, undefined, undefined, {
            sessionId,
            error: (err as Error).message,
          });
        }),
      ]);

      return deleted;
    } catch (error) {
      logger.error('SessionStoreService', 'Failed to delete session', error, undefined, undefined, undefined, {
        sessionId,
      });
      throw error;
    }
  }
}

// Export singleton instance
export const sessionStoreService = new SessionStoreService(cacheService, sessionRepository);
