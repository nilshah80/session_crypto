import { Redis } from "ioredis";
import pg from "pg";
import fs from "fs/promises";
import path from "path";
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

let redis: Redis | null = null;
let pool: pg.Pool | null = null;

export async function initSessionStore(redisClient: Redis): Promise<void> {
  redis = redisClient;
  pool = new Pool({
    user: process.env.POSTGRES_USER || "postgres",
    password: process.env.POSTGRES_PASSWORD || "postgres",
    host: process.env.POSTGRES_HOST || "localhost",
    database: process.env.POSTGRES_DB || "session_crypto",
    port: parseInt(process.env.POSTGRES_PORT || "5432"),
  });

  const migrationPath = path.join(process.cwd(), "migrations", "scripts", "001_create_sessions_table.sql");
  const migrationSql = await fs.readFile(migrationPath, "utf-8");

  // Ensure table exists
  await pool.query(migrationSql);
}

export async function storeSession(
  sessionId: string,
  key: Buffer,
  type: "ANON" | "AUTH",
  ttlSec: number,
  principal?: string,
  clientId?: string
): Promise<void> {
  if (!redis || !pool) {
    throw new Error("Session store not initialized");
  }

  const expiresAt = Date.now() + ttlSec * 1000;
  const sessionData = {
    key: b64(key),
    type,
    expiresAt,
    ...(principal && { principal }),
    ...(clientId && { clientId }),
  };
  const value = JSON.stringify(sessionData);

  // 1. Write to PostgreSQL (Source of Truth)
  await pool.query(
    `INSERT INTO sessions (session_id, data, expires_at) 
     VALUES ($1, $2, $3) 
     ON CONFLICT (session_id) DO UPDATE 
     SET data = $2, expires_at = $3`,
    [sessionId, value, expiresAt]
  );

  // 2. Write to Redis (Cache)
  await redis.set(`${SESSION_PREFIX}${sessionId}`, value, "EX", ttlSec);
}

export async function getSession(sessionId: string): Promise<SessionData | null> {
  if (!redis || !pool) {
    throw new Error("Session store not initialized");
  }

  // 1. Try Redis
  const cachedValue = await redis.get(`${SESSION_PREFIX}${sessionId}`);
  if (cachedValue) {
    return parseSession(cachedValue, sessionId);
  }

  // 2. Fallback to PostgreSQL
  const res = await pool.query(
    "SELECT data FROM sessions WHERE session_id = $1",
    [sessionId]
  );

  if (res.rows.length === 0) {
    return null;
  }

  const dbValue = JSON.stringify(res.rows[0].data);
  const parsed = await parseSession(dbValue, sessionId);

  // Populate Redis if found and valid
  if (parsed) {
    const ttl = Math.ceil((parsed.expiresAt - Date.now()) / 1000);
    if (ttl > 0) {
      await redis.set(`${SESSION_PREFIX}${sessionId}`, dbValue, "EX", ttl);
    }
  }

  return parsed;
}

export async function deleteSession(sessionId: string): Promise<boolean> {
  if (!redis || !pool) {
    throw new Error("Session store not initialized");
  }

  // Delete from both
  const [redisRes, pgRes] = await Promise.all([
    redis.del(`${SESSION_PREFIX}${sessionId}`),
    pool.query("DELETE FROM sessions WHERE session_id = $1", [sessionId])
  ]);

  return redisRes > 0 || (pgRes.rowCount ?? 0) > 0;
}

async function parseSession(jsonStr: string, sessionId: string): Promise<SessionData | null> {
  try {
    const parsed = JSON.parse(jsonStr);

    // Check if expired
    if (Date.now() > parsed.expiresAt) {
      // Async cleanup
      if (redis) redis.del(`${SESSION_PREFIX}${sessionId}`);
      if (pool) pool.query("DELETE FROM sessions WHERE session_id = $1", [sessionId]);
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
