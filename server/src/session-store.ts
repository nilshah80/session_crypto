import { Redis } from "ioredis";
import pg from "pg";
import { b64, unb64 } from "./crypto-helpers.js";

const { Pool } = pg;

export interface SessionData {
  key: Buffer;
  type: "ANON" | "AUTH";
  expiresAt: number;
  principal?: string;
  clientId?: string;
}

// Redis key prefix for sessions
const SESSION_PREFIX = "sess:";

// Embedded migration SQL (no file dependency)
const MIGRATION_SQL = `
  CREATE TABLE IF NOT EXISTS sessions (
    session_id VARCHAR(255) PRIMARY KEY,
    data JSONB NOT NULL,
    expires_at BIGINT NOT NULL
  );
  CREATE INDEX IF NOT EXISTS idx_sessions_expires_at ON sessions(expires_at);
`;

// Configuration constants (with environment variable overrides)
const PG_POOL_MAX = parseInt(process.env.PG_POOL_MAX || "25", 10);
const PG_IDLE_TIMEOUT_MS = parseInt(process.env.PG_IDLE_TIMEOUT_MS || "60000", 10);
const PG_CONNECTION_TIMEOUT_MS = parseInt(process.env.PG_CONNECTION_TIMEOUT_MS || "5000", 10);

let redis: Redis | null = null;
let pool: pg.Pool | null = null;
let logger: any = null;

export async function initSessionStore(redisClient: Redis, loggerInstance?: any): Promise<void> {
  redis = redisClient;
  logger = loggerInstance;

  // Pool configuration for production
  pool = new Pool({
    user: process.env.POSTGRES_USER || "postgres",
    password: process.env.POSTGRES_PASSWORD || "postgres",
    host: process.env.POSTGRES_HOST || "localhost",
    database: process.env.POSTGRES_DB || "session_crypto",
    port: parseInt(process.env.POSTGRES_PORT || "5432"),
    // Connection pool settings
    max: PG_POOL_MAX,
    idleTimeoutMillis: PG_IDLE_TIMEOUT_MS,
    connectionTimeoutMillis: PG_CONNECTION_TIMEOUT_MS,
    // SSL configuration (set POSTGRES_SSL=true in production)
    ssl: process.env.POSTGRES_SSL === "true" ? { rejectUnauthorized: false } : undefined,
  });

  // IMPORTANT: For PgBouncer transaction pooling mode (Azure PostgreSQL):
  // - Application-level statement_timeout settings won't work
  // - Session-level SET commands are RESET after each transaction
  // - pool.on('connect') only fires for NEW physical connections, not pooled ones
  //
  // YOU MUST set statement_timeout at PostgreSQL database level:
  //
  //   For Azure PostgreSQL Flexible Server:
  //   ALTER DATABASE session_crypto SET statement_timeout = '5s';
  //
  //   Or globally (server parameter):
  //   Go to Azure Portal > PostgreSQL Server > Server parameters > statement_timeout
  //
  //   Or via SQL:
  //   ALTER SYSTEM SET statement_timeout = '5s';
  //   SELECT pg_reload_conf();

  // Ensure table exists using embedded SQL
  await pool.query(MIGRATION_SQL);
}

// Export pool for health checks and graceful shutdown
export function getPool(): pg.Pool | null {
  return pool;
}

export async function closeSessionStore(): Promise<void> {
  if (pool) {
    await pool.end();
    pool = null;
  }
}

export async function storeSession(
  sessionId: string,
  key: Buffer,
  type: "ANON" | "AUTH",
  ttlSec: number,
  principal?: string,
  clientId?: string
): Promise<void> {
  if (!pool) {
    throw new Error("Session store not initialized");
  }

  const expiresAt = Date.now() + ttlSec * 1000;

  // Create a copy of the key buffer for encoding to avoid modifying the original
  const keyCopy = Buffer.from(key);

  const sessionData = {
    key: b64(keyCopy),
    type,
    expiresAt,
    ...(principal && { principal }),
    ...(clientId && { clientId }),
  };
  const value = JSON.stringify(sessionData);

  // SECURITY: Zeroize the key copy after encoding
  keyCopy.fill(0);

  // 1. Write to PostgreSQL (Source of Truth)
  await pool.query(
    `INSERT INTO sessions (session_id, data, expires_at)
     VALUES ($1, $2, $3)
     ON CONFLICT (session_id) DO UPDATE
     SET data = $2, expires_at = $3`,
    [sessionId, value, expiresAt]
  );

  // 2. Write to Redis (Cache) - optional, skip if Redis is unavailable
  if (redis && redis.status === "ready") {
    try {
      await redis.set(`${SESSION_PREFIX}${sessionId}`, value, "EX", ttlSec);
    } catch (err) {
      if (logger) {
        logger.warn({ err, sessionId }, "Failed to cache session in Redis");
      }
    }
  }
}

export async function getSession(sessionId: string): Promise<SessionData | null> {
  if (!pool) {
    throw new Error("Session store not initialized");
  }

  // 1. Try Redis (if available)
  if (redis && redis.status === "ready") {
    try {
      const cachedValue = await redis.get(`${SESSION_PREFIX}${sessionId}`);
      if (cachedValue) {
        return parseSession(cachedValue, sessionId);
      }
    } catch (err) {
      if (logger) {
        logger.warn({ err, sessionId }, "Redis read failed, falling back to PostgreSQL");
      }
    }
  }

  // 2. Fallback to PostgreSQL
  const res = await pool.query(
    "SELECT data FROM sessions WHERE session_id = $1",
    [sessionId]
  );

  if (res.rows.length === 0) {
    return null;
  }

  // Handle JSONB: pg returns parsed object, not string
  const rawData = res.rows[0].data;
  const dbValue = typeof rawData === "string" ? rawData : JSON.stringify(rawData);
  const parsed = await parseSession(dbValue, sessionId);

  // Populate Redis if found, valid, and Redis is available
  if (parsed && redis && redis.status === "ready") {
    const ttl = Math.ceil((parsed.expiresAt - Date.now()) / 1000);
    if (ttl > 0) {
      try {
        await redis.set(`${SESSION_PREFIX}${sessionId}`, dbValue, "EX", ttl);
      } catch (err) {
        if (logger) {
          logger.warn({ err, sessionId }, "Failed to populate Redis cache");
        }
      }
    }
  }

  return parsed;
}

export async function deleteSession(sessionId: string): Promise<boolean> {
  if (!pool) {
    throw new Error("Session store not initialized");
  }

  const promises: Promise<any>[] = [];

  // Delete from Redis if available
  if (redis && redis.status === "ready") {
    promises.push(
      redis.del(`${SESSION_PREFIX}${sessionId}`).catch((err) => {
        if (logger) {
          logger.warn({ err, sessionId }, "Failed to delete session from Redis");
        }
        return 0;
      })
    );
  }

  // Delete from PostgreSQL
  promises.push(pool.query("DELETE FROM sessions WHERE session_id = $1", [sessionId]));

  const results = await Promise.all(promises);
  const pgRes = promises.length === 2 ? results[1] : results[0];

  return (pgRes.rowCount ?? 0) > 0;
}

async function parseSession(jsonStr: string, sessionId: string): Promise<SessionData | null> {
  try {
    const parsed = JSON.parse(jsonStr);

    // Check if expired
    if (Date.now() > parsed.expiresAt) {
      // Async cleanup with proper await and error handling
      cleanupExpiredSession(sessionId).catch((err) => {
        if (logger) {
          logger.error({ err, sessionId }, "Failed to cleanup expired session");
        }
      });
      return null;
    }

    return {
      key: unb64(parsed.key),
      type: parsed.type,
      expiresAt: parsed.expiresAt,
      principal: parsed.principal,
      clientId: parsed.clientId,
    };
  } catch {
    return null;
  }
}

async function cleanupExpiredSession(sessionId: string): Promise<void> {
  const promises: Promise<unknown>[] = [];

  if (redis) {
    promises.push(redis.del(`${SESSION_PREFIX}${sessionId}`));
  }
  if (pool) {
    promises.push(pool.query("DELETE FROM sessions WHERE session_id = $1", [sessionId]));
  }

  await Promise.all(promises);
}
