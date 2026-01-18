import { Redis } from "ioredis";
import { b64, unb64 } from "./crypto-helpers.js";

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

export function initSessionStore(redisClient: Redis): void {
  redis = redisClient;
}

export async function storeSession(
  sessionId: string,
  key: Buffer,
  type: "ANON" | "AUTH",
  ttlSec: number,
  principal?: string,
  clientId?: string
): Promise<void> {
  if (!redis) {
    throw new Error("Session store not initialized");
  }

  const expiresAt = Date.now() + ttlSec * 1000;
  const value = JSON.stringify({
    key: b64(key),
    type,
    expiresAt,
    ...(principal && { principal }),
    ...(clientId && { clientId }),
  });

  await redis.set(`${SESSION_PREFIX}${sessionId}`, value, "EX", ttlSec);
}

export async function getSession(sessionId: string): Promise<SessionData | null> {
  if (!redis) {
    throw new Error("Session store not initialized");
  }

  const value = await redis.get(`${SESSION_PREFIX}${sessionId}`);
  if (!value) return null;

  try {
    const parsed = JSON.parse(value);

    // Check if expired (Redis TTL should handle this, but double-check)
    if (Date.now() > parsed.expiresAt) {
      await redis.del(`${SESSION_PREFIX}${sessionId}`);
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

export async function deleteSession(sessionId: string): Promise<boolean> {
  if (!redis) {
    throw new Error("Session store not initialized");
  }

  const result = await redis.del(`${SESSION_PREFIX}${sessionId}`);
  return result > 0;
}
