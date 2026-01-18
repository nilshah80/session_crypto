// In-memory session store (use Redis in production)

export interface SessionData {
  key: Buffer;
  type: "ANON" | "AUTH";
  expiresAt: number;
  principal?: string;
  clientId?: string;
}

const sessions = new Map<string, SessionData>();

export function storeSession(
  sessionId: string,
  key: Buffer,
  type: "ANON" | "AUTH",
  ttlSec: number,
  principal?: string,
  clientId?: string
): void {
  const expiresAt = Date.now() + ttlSec * 1000;
  sessions.set(sessionId, { key, type, expiresAt, principal, clientId });

  // Auto-cleanup after TTL
  setTimeout(() => {
    sessions.delete(sessionId);
  }, ttlSec * 1000);
}

export function getSession(sessionId: string): SessionData | null {
  const session = sessions.get(sessionId);
  if (!session) return null;

  // Check if expired
  if (Date.now() > session.expiresAt) {
    sessions.delete(sessionId);
    return null;
  }

  return session;
}

export function deleteSession(sessionId: string): boolean {
  return sessions.delete(sessionId);
}
