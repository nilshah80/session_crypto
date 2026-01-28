import { createClient, RedisClientType } from 'redis';
import { config } from '../config';
import { logger } from '../utils/logger';
import { LRUCache } from '../utils/lru-cache';
import { CACHE } from '../constants';

export interface CacheService {
  get<T>(key: string): Promise<T | null>;
  set<T>(key: string, value: T, ttl: number): Promise<void>;
  setStrict<T>(key: string, value: T, ttl: number): Promise<void>;
  setIfNotExistsStrict<T>(key: string, value: T, ttl: number): Promise<boolean>;
  delete(key: string): Promise<void>;
  exists(key: string): Promise<boolean>;
  existsStrict(key: string): Promise<boolean>;
  healthCheck(): Promise<boolean>;
  close(): Promise<void>;
}

class RedisCacheService implements CacheService {
  private client: RedisClientType;
  private connected = false;
  private reconnectInProgress = false;
  private periodicReconnectInterval: NodeJS.Timeout | null = null;
  private readonly PERIODIC_RECONNECT_INTERVAL_MS =
    CACHE.REDIS_PERIODIC_RECONNECT_INTERVAL_MS;

  // In-memory LRU cache fallback when Redis is unavailable
  private readonly fallbackCache: LRUCache;
  private readonly FALLBACK_MAX_SIZE = CACHE.REDIS_FALLBACK_MAX_SIZE;

  constructor() {
    // Initialize in-memory fallback cache with max TTL from config
    this.fallbackCache = new LRUCache({
      maxSize: this.FALLBACK_MAX_SIZE,
      defaultTtlMs: config.CACHE_LRU_MAX_TTL_SECONDS * 1000,
    });

    const clientOptions: any = {
      url: config.REDIS_URL,
      socket: {
        connectTimeout: CACHE.REDIS_CONNECTION_TIMEOUT_MS,
        reconnectStrategy: (retries: number) => {
          if (retries > config.REDIS_MAX_RECONNECT_ATTEMPTS) {
            logger.error(
              'CacheService',
              `Redis reconnection failed after ${config.REDIS_MAX_RECONNECT_ATTEMPTS} attempts`
            );
            return false;
          }
          // Exponential backoff: baseDelay * 2^(retries-1), capped at maxDelay
          const delay = Math.min(
            config.REDIS_RECONNECT_BASE_DELAY_MS * Math.pow(2, retries - 1),
            config.REDIS_RECONNECT_MAX_DELAY_MS
          );
          return delay;
        },
      },
    };

    if (config.REDIS_PASSWORD) {
      clientOptions.password = config.REDIS_PASSWORD;
    }

    this.client = createClient(clientOptions);

    this.setupEventHandlers();
    this.startPeriodicReconnect();
    void this.connect().catch(err => {
      logger.error('CacheService', 'Redis initial connection failed', err as Error);
    });
  }

  /**
   * Start periodic reconnection attempts when disconnected
   */
  private startPeriodicReconnect(): void {
    this.periodicReconnectInterval = setInterval(() => {
      if (!this.connected && !this.reconnectInProgress) {
        this.attemptReconnect();
      }
    }, this.PERIODIC_RECONNECT_INTERVAL_MS);

    this.periodicReconnectInterval.unref?.();
  }

  /**
   * Attempt to reconnect
   */
  private async attemptReconnect(): Promise<void> {
    if (this.reconnectInProgress || this.connected) {
      return;
    }

    this.reconnectInProgress = true;

    try {
      if (this.client.isOpen) {
        this.connected = true;
        this.reconnectInProgress = false;
        return;
      }

      await this.client.connect();
    } catch (error) {
      logger.warn('CacheService', `Redis periodic reconnection failed: ${(error as Error).message}`);
    } finally {
      this.reconnectInProgress = false;
    }
  }

  private setupEventHandlers(): void {
    this.client.on('ready', () => {
      this.connected = true;
    });

    this.client.on('error', err => {
      logger.error('CacheService', 'Redis client error', err as Error);
      this.connected = false;
    });

    this.client.on('end', () => {
      this.connected = false;
    });

    this.client.on('reconnecting', () => {
      // Reconnecting silently
    });
  }

  private async connect(): Promise<void> {
    try {
      await this.client.connect();
    } catch (error) {
      logger.error('CacheService', 'Failed to connect to Redis', error as Error);
      throw error;
    }
  }

  /**
   * Attempt to reconnect to Redis in the background
   */
  private tryReconnectAsync(): void {
    if (this.reconnectInProgress || this.connected) {
      return;
    }

    this.reconnectInProgress = true;

    const resetTimer = setTimeout(() => {
      this.reconnectInProgress = false;
    }, CACHE.REDIS_CONNECTION_TIMEOUT_MS);

    resetTimer.unref?.();
  }

  /**
   * Get value from cache
   * Uses Redis when available, falls back to in-memory LRU cache when Redis is down
   */
  async get<T>(key: string): Promise<T | null> {
    if (!this.connected) {
      this.tryReconnectAsync();
      return this.fallbackCache.get(key) as T | null;
    }

    try {
      const value = await this.client.get(key);
      if (value === null) {
        return this.fallbackCache.get(key) as T | null;
      }
      const parsed = JSON.parse(value) as T;
      // Keep fallback cache in sync
      this.fallbackCache.set(key, parsed);
      return parsed;
    } catch (error) {
      this.connected = false;
      this.tryReconnectAsync();
      logger.warn('CacheService', `Cache get failed, using fallback: ${key}`, undefined, undefined, undefined, undefined, {
        error: (error as Error).message,
      });
      return this.fallbackCache.get(key) as T | null;
    }
  }

  /**
   * Calculate clipped TTL for fallback cache
   */
  private getClippedFallbackTtl(ttl: number): number {
    return Math.min(ttl, config.CACHE_LRU_MAX_TTL_SECONDS);
  }

  /**
   * Set value in cache
   * Uses Redis when available, falls back to in-memory LRU cache when Redis is down
   */
  async set<T>(key: string, value: T, ttl: number): Promise<void> {
    // Always write to fallback cache for resilience
    this.fallbackCache.set(key, value, this.getClippedFallbackTtl(ttl));

    if (!this.connected) {
      this.tryReconnectAsync();
      return;
    }

    try {
      const serialized = JSON.stringify(value);
      await this.client.setEx(key, ttl, serialized);
    } catch (error) {
      this.connected = false;
      this.tryReconnectAsync();
      logger.warn('CacheService', `Cache set failed, using fallback: ${key}`, undefined, undefined, undefined, undefined, {
        ttl,
        error: (error as Error).message,
      });
    }
  }

  /**
   * Set value in cache (STRICT mode)
   * CRITICAL for security operations - throws on failure
   */
  async setStrict<T>(key: string, value: T, ttl: number): Promise<void> {
    if (!this.connected) {
      this.tryReconnectAsync();
      throw new Error('Redis unavailable for security-critical set operation');
    }

    try {
      const serialized = JSON.stringify(value);
      await this.client.setEx(key, ttl, serialized);
    } catch (error) {
      this.connected = false;
      this.tryReconnectAsync();
      logger.error('CacheService', `Cache set failed (strict mode): ${key}`, error as Error, undefined, undefined, undefined, {
        key,
        ttl,
      });
      throw error;
    }
  }

  /**
   * Atomic set-if-not-exists operation (STRICT mode)
   * CRITICAL for replay protection - prevents race conditions
   * @param key Redis key
   * @param value Value to set
   * @param ttl TTL in seconds
   * @returns true if value was set, false if key already existed
   * @throws Error if Redis unavailable
   */
  async setIfNotExistsStrict<T>(key: string, value: T, ttl: number): Promise<boolean> {
    if (!this.connected) {
      this.tryReconnectAsync();
      throw new Error('Redis unavailable for security-critical operation');
    }

    try {
      const serialized = JSON.stringify(value);
      // SET key value EX ttl NX - atomic operation
      const result = await this.client.set(key, serialized, {
        EX: ttl,
        NX: true, // Only set if not exists
      });
      return result === 'OK';
    } catch (error) {
      this.connected = false;
      this.tryReconnectAsync();
      logger.error('CacheService', `Atomic set-if-not-exists failed: ${key}`, error as Error, undefined, undefined, undefined, {
        key,
        ttl,
      });
      throw error;
    }
  }

  /**
   * Delete key from cache
   */
  async delete(key: string): Promise<void> {
    this.fallbackCache.delete(key);

    if (!this.connected) {
      this.tryReconnectAsync();
      return;
    }

    try {
      await this.client.del(key);
    } catch (error) {
      this.connected = false;
      this.tryReconnectAsync();
      logger.warn('CacheService', `Cache delete failed, fallback already cleared: ${key}`, undefined, undefined, undefined, undefined, {
        error: (error as Error).message,
      });
    }
  }

  /**
   * Check if key exists in cache
   */
  async exists(key: string): Promise<boolean> {
    if (!this.connected) {
      this.tryReconnectAsync();
      return this.fallbackCache.has(key);
    }

    try {
      const result = await this.client.exists(key);
      if (result === 1) {
        return true;
      }
      return this.fallbackCache.has(key);
    } catch (error) {
      this.connected = false;
      this.tryReconnectAsync();
      logger.warn('CacheService', `Cache exists check failed, using fallback: ${key}`, undefined, undefined, undefined, undefined, {
        error: (error as Error).message,
      });
      return this.fallbackCache.has(key);
    }
  }

  /**
   * Check if key exists in cache (STRICT mode)
   * CRITICAL for security operations - throws if Redis unavailable
   */
  async existsStrict(key: string): Promise<boolean> {
    if (!this.connected) {
      this.tryReconnectAsync();
      throw new Error('Redis unavailable for security-critical exists check');
    }

    try {
      const result = await this.client.exists(key);
      return result === 1;
    } catch (error) {
      this.connected = false;
      this.tryReconnectAsync();
      logger.error('CacheService', `Cache exists check failed (strict mode): ${key}`, error as Error);
      throw error;
    }
  }

  /**
   * Health check for Redis connection
   */
  async healthCheck(): Promise<boolean> {
    if (!this.connected) {
      return false;
    }

    try {
      await this.client.ping();
      return true;
    } catch (error) {
      logger.error('CacheService', 'Health check failed', error as Error);
      return false;
    }
  }

  /**
   * Close Redis connection
   */
  async close(): Promise<void> {
    if (this.periodicReconnectInterval) {
      clearInterval(this.periodicReconnectInterval);
      this.periodicReconnectInterval = null;
    }

    this.fallbackCache.dispose();

    if (this.client.isOpen) {
      await this.client.quit();
    }
  }
}

// Export singleton instance
export const cacheService = new RedisCacheService();
