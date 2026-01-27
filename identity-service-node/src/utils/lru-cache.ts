import { CACHE } from '../constants';

/**
 * Simple LRU (Least Recently Used) Cache implementation
 * Used as a fallback when Redis is unavailable
 *
 * Features:
 * - O(1) get/set operations
 * - Automatic TTL expiration
 * - Memory-bounded with configurable max size
 * - Thread-safe for Node.js single-threaded event loop
 */

interface CacheEntry<T> {
  value: T;
  expiresAt: number;
}

export class LRUCache<T = any> {
  private cache: Map<string, CacheEntry<T>>;
  private readonly maxSize: number;
  private readonly defaultTtlMs: number;
  private cleanupInterval: NodeJS.Timeout | null = null;

  constructor(options: { maxSize?: number; defaultTtlMs?: number } = {}) {
    this.maxSize = options.maxSize || CACHE.LRU_DEFAULT_MAX_SIZE;
    this.defaultTtlMs = options.defaultTtlMs || CACHE.LRU_DEFAULT_TTL_MS;
    this.cache = new Map();

    // Periodic cleanup of expired entries
    this.cleanupInterval = setInterval(() => {
      this.removeExpired();
    }, CACHE.LRU_CLEANUP_INTERVAL_MS);

    this.cleanupInterval.unref?.();
  }

  /**
   * Get a value from cache
   * Returns null if not found or expired
   */
  get(key: string): T | null {
    const entry = this.cache.get(key);

    if (!entry) {
      return null;
    }

    // Check if expired
    if (Date.now() > entry.expiresAt) {
      this.cache.delete(key);
      return null;
    }

    // Move to end (most recently used) by re-inserting
    this.cache.delete(key);
    this.cache.set(key, entry);

    return entry.value;
  }

  /**
   * Set a value in cache with optional TTL
   * @param key Cache key
   * @param value Value to store
   * @param ttlSeconds TTL in seconds (uses default if not provided)
   */
  set(key: string, value: T, ttlSeconds?: number): void {
    // If at capacity, remove least recently used (first item in Map)
    if (this.cache.size >= this.maxSize && !this.cache.has(key)) {
      const firstKey = this.cache.keys().next().value;
      if (firstKey !== undefined) {
        this.cache.delete(firstKey);
      }
    }

    const ttlMs = ttlSeconds ? ttlSeconds * 1000 : this.defaultTtlMs;

    // Delete existing entry first to update position
    this.cache.delete(key);

    this.cache.set(key, {
      value,
      expiresAt: Date.now() + ttlMs,
    });
  }

  /**
   * Delete a key from cache
   */
  delete(key: string): boolean {
    return this.cache.delete(key);
  }

  /**
   * Check if key exists and is not expired
   */
  has(key: string): boolean {
    const entry = this.cache.get(key);
    if (!entry) {
      return false;
    }

    if (Date.now() > entry.expiresAt) {
      this.cache.delete(key);
      return false;
    }

    return true;
  }

  /**
   * Get current cache size
   */
  get size(): number {
    return this.cache.size;
  }

  /**
   * Clear all entries
   */
  clear(): void {
    this.cache.clear();
  }

  /**
   * Remove all expired entries
   */
  private removeExpired(): void {
    const now = Date.now();
    for (const [key, entry] of this.cache.entries()) {
      if (now > entry.expiresAt) {
        this.cache.delete(key);
      }
    }
  }

  /**
   * Get cache statistics
   */
  getStats(): { size: number; maxSize: number } {
    return {
      size: this.cache.size,
      maxSize: this.maxSize,
    };
  }

  /**
   * Dispose of cache resources
   */
  dispose(): void {
    if (this.cleanupInterval) {
      clearInterval(this.cleanupInterval);
      this.cleanupInterval = null;
    }
    this.cache.clear();
  }
}

// Export singleton instances for different cache types

/** Session cache - stores session data */
export const sessionCache = new LRUCache({
  maxSize: CACHE.SESSION_CACHE_MAX_SIZE,
  defaultTtlMs: CACHE.SESSION_CACHE_TTL_MS,
});

/** Nonce cache - stores used nonces for replay protection */
export const nonceCache = new LRUCache<boolean>({
  maxSize: CACHE.NONCE_CACHE_MAX_SIZE,
  defaultTtlMs: CACHE.NONCE_CACHE_TTL_MS,
});
