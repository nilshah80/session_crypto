import { sessionRepository } from '../repositories';
import { logger } from '../utils/logger';
import { config } from '../config';

/**
 * Session Cleanup Job
 *
 * Responsible for cleaning up expired sessions from PostgreSQL
 * to prevent database bloat and maintain performance.
 *
 * Based on identity-service/src/jobs/token-cleanup.job.ts
 *
 * **Cleanup Strategy:**
 * - Expired sessions: Deleted immediately (already past expiration)
 * - Batched deletes to avoid table locks
 *
 * **Execution:**
 * - Runs hourly (configurable via SESSION_CLEANUP_INTERVAL_MS)
 * - Non-blocking, graceful error handling
 * - Overlap prevention
 */
export class SessionCleanupJob {
  private intervalId?: NodeJS.Timeout | undefined;
  private isRunning = false;
  private currentExecution: Promise<void> | null = null;

  /**
   * Start the cleanup job with specified interval
   * @param intervalMs Interval in milliseconds (default: 1 hour)
   */
  start(intervalMs: number = config.SESSION_CLEANUP_INTERVAL_MS): void {
    if (this.intervalId) {
      logger.warn('SessionCleanupJob', 'Session cleanup job already running');
      return;
    }

    logger.debug('SessionCleanupJob', 'Starting session cleanup job', undefined, {
      intervalMs,
      intervalHours: intervalMs / 3600000,
    });

    // Run immediately on start
    void this.executeCleanup();

    // Then schedule periodic execution
    this.intervalId = setInterval(() => {
      void this.executeCleanup();
    }, intervalMs);
    this.intervalId.unref?.();
  }

  /**
   * Stop the cleanup job and wait for current execution to complete
   */
  async stop(): Promise<void> {
    if (this.intervalId) {
      clearInterval(this.intervalId);
      this.intervalId = undefined;
    }

    const execution = this.currentExecution;

    if (execution) {
      logger.debug('SessionCleanupJob', 'Waiting for current cleanup execution to finish...');
      try {
        await execution;
      } catch (_error) {
        // Error already logged in executeCleanup
      }
    }

    logger.debug('SessionCleanupJob', 'Session cleanup job stopped');
  }

  /**
   * Execute cleanup operations
   */
  private executeCleanup(): Promise<void> {
    if (this.isRunning) {
      logger.warn('SessionCleanupJob', 'Session cleanup already in progress, skipping');
      return this.currentExecution ?? Promise.resolve();
    }

    this.isRunning = true;

    const execution = (async () => {
      const startTime = Date.now();

      try {
        logger.debug('SessionCleanupJob', 'Starting session cleanup execution');

        const deletedSessions = await sessionRepository.cleanupExpired(
          config.SESSION_CLEANUP_BATCH_SIZE,
          config.SESSION_CLEANUP_BATCH_DELAY_MS
        );

        const duration = Date.now() - startTime;

        if (deletedSessions > 0) {
          logger.debug('SessionCleanupJob', 'Session cleanup completed', undefined, {
            deletedSessions,
            durationMs: duration,
          });
        } else {
          logger.debug('SessionCleanupJob', 'No expired sessions to clean up', undefined, {
            durationMs: duration,
          });
        }

        // Alert if cleanup took too long
        if (duration > config.SESSION_CLEANUP_WARNING_THRESHOLD_MS) {
          logger.warn('SessionCleanupJob', 'Session cleanup took longer than expected', undefined, undefined, undefined, undefined, {
            durationMs: duration,
            thresholdMs: config.SESSION_CLEANUP_WARNING_THRESHOLD_MS,
          });
        }
      } catch (error) {
        logger.error('SessionCleanupJob', 'Session cleanup failed', error as Error);
      } finally {
        this.isRunning = false;
        this.currentExecution = null;
      }
    })();

    this.currentExecution = execution;
    return execution;
  }

  /**
   * Get job status
   */
  getStatus() {
    return {
      isRunning: this.isRunning,
      isScheduled: !!this.intervalId,
    };
  }
}

// Export singleton instance
export const sessionCleanupJob = new SessionCleanupJob();
