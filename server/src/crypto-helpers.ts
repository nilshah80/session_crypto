import crypto from "crypto";
import { Redis } from "ioredis";

// Base64 encoding/decoding helpers
export const b64 = (buf: Buffer): string => buf.toString("base64");
export const unb64 = (s: string): Buffer => Buffer.from(s, "base64");

// AES-256-GCM constants
const IV_SIZE = 12;  // 96-bit IV for GCM mode
const TAG_SIZE = 16; // 128-bit authentication tag

// OPTIMIZATION: Buffer pool for IV reuse
// NOTE: This pool is NOT thread-safe. It's safe for single-threaded Node.js event loop,
// but would require synchronization (e.g., locks or per-thread pools) if crypto operations
// are moved to worker threads or if Node.js is run in cluster mode with shared state.
// For multi-threaded scenarios, consider: AsyncLocalStorage-based pools, per-request buffers,
// or thread-safe queue implementations.
const ivPool: Buffer[] = [];
const IV_POOL_MAX_SIZE = 100;

function getIVBuffer(): Buffer {
  return ivPool.pop() || Buffer.allocUnsafe(IV_SIZE);
}

function returnIVBuffer(buf: Buffer): void {
  if (ivPool.length < IV_POOL_MAX_SIZE) {
    // SECURITY: Clear IV before reusing
    buf.fill(0);
    ivPool.push(buf);
  }
}

// Create ECDH keypair using P-256 curve
export function createEcdhKeypair() {
  const ecdh = crypto.createECDH("prime256v1"); // P-256
  ecdh.generateKeys();
  return { ecdh, publicKey: ecdh.getPublicKey() };
}

// HKDF to derive 32-byte AES key
export function hkdf32(
  sharedSecret: Buffer,
  salt: Buffer,
  info: Buffer
): Buffer {
  return Buffer.from(crypto.hkdfSync("sha256", sharedSecret, salt, info, 32));
}

// AES-256-GCM encryption - returns IV || ciphertext || tag
// OPTIMIZED: Uses buffer pooling and optimized concatenation
export function aesGcmEncrypt(
  key32: Buffer,
  aad: Buffer,
  plaintext: Buffer
): Buffer {
  // Get IV from pool
  const iv = getIVBuffer();
  crypto.randomFillSync(iv);

  try {
    const cipher = crypto.createCipheriv("aes-256-gcm", key32, iv);
    cipher.setAAD(aad);

    // OPTIMIZATION: Pre-allocate result buffer to avoid multiple Buffer.concat()
    const result = Buffer.allocUnsafe(IV_SIZE + plaintext.length + TAG_SIZE);

    // Copy IV
    iv.copy(result, 0, 0, IV_SIZE);

    // Encrypt and copy ciphertext
    const updateResult = cipher.update(plaintext);
    updateResult.copy(result, IV_SIZE);
    const finalResult = cipher.final();
    finalResult.copy(result, IV_SIZE + updateResult.length);

    // Copy auth tag
    const tag = cipher.getAuthTag();
    tag.copy(result, result.length - TAG_SIZE);

    return result;
  } finally {
    returnIVBuffer(iv);
  }
}

// AES-256-GCM decryption - expects IV || ciphertext || tag
// OPTIMIZED: Avoids Buffer.concat()
export function aesGcmDecrypt(
  key32: Buffer,
  aad: Buffer,
  data: Buffer
): Buffer {
  const iv = data.subarray(0, IV_SIZE);
  const tag = data.subarray(-TAG_SIZE);
  const ciphertext = data.subarray(IV_SIZE, -TAG_SIZE);

  const decipher = crypto.createDecipheriv("aes-256-gcm", key32, iv);
  decipher.setAAD(aad);
  decipher.setAuthTag(tag);

  // OPTIMIZATION: Pre-allocate result buffer
  const updateResult = decipher.update(ciphertext);
  const finalResult = decipher.final();

  if (finalResult.length === 0) {
    return updateResult;
  }

  const result = Buffer.allocUnsafe(updateResult.length + finalResult.length);
  updateResult.copy(result, 0);
  finalResult.copy(result, updateResult.length);
  return result;
}

// Build AAD from request components
// Format: TIMESTAMP|NONCE|KID|CLIENTID
export function buildAad(
  ts: string,
  nonce: string,
  kid: string,
  clientId: string
): Buffer {
  return Buffer.from(`${ts}|${nonce}|${kid}|${clientId}`, "utf8");
}

// Validate P-256 public key is on curve
export function validateP256PublicKey(publicKeyBytes: Buffer): void {
  // P-256 uncompressed point: 0x04 || X (32 bytes) || Y (32 bytes) = 65 bytes
  if (publicKeyBytes.length !== 65) {
    throw new Error("INVALID_KEY_LENGTH");
  }

  if (publicKeyBytes[0] !== 0x04) {
    throw new Error("INVALID_KEY_FORMAT");
  }

  // Use Node.js crypto to validate point is on curve
  try {
    const keyObject = crypto.createPublicKey({
      key: Buffer.concat([
        // SPKI header for P-256 uncompressed point
        Buffer.from(
          "3059301306072a8648ce3d020106082a8648ce3d030107034200",
          "hex"
        ),
        publicKeyBytes,
      ]),
      format: "der",
      type: "spki",
    });

    if (keyObject.asymmetricKeyType !== "ec") {
      throw new Error("INVALID_KEY_TYPE");
    }
  } catch {
    throw new Error("POINT_NOT_ON_CURVE");
  }
}

/**
 * Parse integer environment variable with validation
 */
function parseIntEnv(name: string, defaultValue: number, min?: number, max?: number): number {
  const raw = process.env[name];
  if (!raw) return defaultValue;

  const parsed = parseInt(raw, 10);
  if (isNaN(parsed)) {
    throw new Error(`Invalid ${name}: "${raw}" is not a valid integer`);
  }
  if (min !== undefined && parsed < min) {
    throw new Error(`Invalid ${name}: ${parsed} is below minimum ${min}`);
  }
  if (max !== undefined && parsed > max) {
    throw new Error(`Invalid ${name}: ${parsed} exceeds maximum ${max}`);
  }
  return parsed;
}

// Replay protection constants (with environment variable overrides)
const TIMESTAMP_WINDOW_MS = parseIntEnv("TIMESTAMP_WINDOW_MS", 5 * 60 * 1000, 1000); // Default: ±5 minutes, min 1s
const NONCE_TTL_SEC = parseIntEnv("NONCE_TTL_SEC", 300, 1); // Default: 5 minutes, min 1s
const NONCE_PREFIX = "nonce:";
const MEMORY_CLEANUP_INTERVAL_MS = 5 * 60 * 1000; // Cleanup every 5 minutes

// Memory nonce store limits (with environment variable overrides)
// With sticky sessions, each pod handles a subset of clients, so limits can be conservative
const MEMORY_NONCE_MAX_SIZE = parseIntEnv("MEMORY_NONCE_MAX_SIZE", 100000, 1000); // Default: 100K, min 1K
const MEMORY_NONCE_CLEANUP_THRESHOLD = parseIntEnv("MEMORY_NONCE_CLEANUP_THRESHOLD", 80000, 100); // Default: 80K, min 100

// Validate threshold < max to ensure cleanup triggers before capacity is reached
if (MEMORY_NONCE_CLEANUP_THRESHOLD >= MEMORY_NONCE_MAX_SIZE) {
  throw new Error(
    `Invalid configuration: MEMORY_NONCE_CLEANUP_THRESHOLD (${MEMORY_NONCE_CLEANUP_THRESHOLD}) ` +
    `must be less than MEMORY_NONCE_MAX_SIZE (${MEMORY_NONCE_MAX_SIZE})`
  );
}

let redis: Redis | null = null;
let logger: any = null;

/**
 * In-memory nonce store as fallback when Redis is unavailable
 * Note: With sticky sessions, this provides full replay protection in multi-pod deployments
 * as each client's requests are routed to the same pod.
 *
 * Bounded to MEMORY_NONCE_MAX_SIZE entries with threshold-triggered cleanup.
 * Uses Map's insertion order for O(1) FIFO eviction instead of O(n log n) sorting.
 */
const memoryNonceStore = new Map<string, number>();
let cleanupInterval: NodeJS.Timeout | null = null;

/**
 * Cleanup expired nonces from in-memory fallback store
 * @returns number of entries cleaned
 */
function cleanupExpiredMemoryNonces(): number {
  const now = Date.now();
  const ttlMs = NONCE_TTL_SEC * 1000;
  let cleaned = 0;

  for (const [key, timestamp] of memoryNonceStore) {
    if (now - timestamp > ttlMs) {
      memoryNonceStore.delete(key);
      cleaned++;
    }
  }

  if (cleaned > 0 && logger) {
    logger.debug({ cleaned, remaining: memoryNonceStore.size }, "Cleaned expired memory nonces");
  }

  return cleaned;
}

/**
 * Check if memory nonce store needs cleanup and trigger if threshold reached.
 * Called BEFORE inserting new entries to ensure capacity.
 *
 * SECURITY: Fails closed - if at capacity after cleanup, rejects the request
 * rather than evicting valid nonces (which could allow replay attacks).
 *
 * @throws Error("CAPACITY_EXCEEDED") if at max capacity after cleanup
 */
function ensureMemoryCapacity(): void {
  if (memoryNonceStore.size >= MEMORY_NONCE_CLEANUP_THRESHOLD) {
    const cleaned = cleanupExpiredMemoryNonces();

    if (logger) {
      logger.info(
        {
          sizeBeforeCleanup: memoryNonceStore.size + cleaned,
          sizeAfterCleanup: memoryNonceStore.size,
          threshold: MEMORY_NONCE_CLEANUP_THRESHOLD,
          maxSize: MEMORY_NONCE_MAX_SIZE
        },
        "Triggered threshold-based nonce cleanup"
      );
    }

    // SECURITY: Fail closed - reject requests rather than evict valid nonces
    // Evicting valid nonces could allow replay attacks within TTL
    if (memoryNonceStore.size >= MEMORY_NONCE_MAX_SIZE) {
      if (logger) {
        logger.error(
          { size: memoryNonceStore.size, maxSize: MEMORY_NONCE_MAX_SIZE },
          "Memory nonce store at capacity - failing closed to prevent replay vulnerability"
        );
      }
      throw new Error("CAPACITY_EXCEEDED");
    }
  }
}

export function initReplayProtection(redisClient: Redis, loggerInstance?: any): void {
  redis = redisClient;
  logger = loggerInstance;

  // Start periodic cleanup of expired nonces from memory
  if (!cleanupInterval) {
    cleanupInterval = setInterval(() => {
      cleanupExpiredMemoryNonces();
    }, MEMORY_CLEANUP_INTERVAL_MS);

    // Don't keep the process alive for this timer
    cleanupInterval.unref?.();
  }
}

/**
 * Dispose replay protection resources (call during graceful shutdown)
 */
export function disposeReplayProtection(): void {
  if (cleanupInterval) {
    clearInterval(cleanupInterval);
    cleanupInterval = null;
  }
  memoryNonceStore.clear();
}

/**
 * In-memory nonce check fallback
 * Provides replay protection when Redis is unavailable
 * With sticky sessions: full protection across requests
 *
 * Includes bounded memory protection with threshold-triggered cleanup
 *
 * NOTE: This is atomic within the Node.js event loop - the check-and-set
 * happens synchronously without yielding. No two async operations can
 * interleave between the get() and set() calls.
 */
function checkAndStoreNonceInMemory(nonceKey: string): void {
  const now = Date.now();
  const ttlMs = NONCE_TTL_SEC * 1000;
  const existingTimestamp = memoryNonceStore.get(nonceKey);

  if (existingTimestamp !== undefined && now - existingTimestamp < ttlMs) {
    if (logger) {
      logger.warn({ nonceKey }, "Replay attack detected (in-memory store)");
    }
    throw new Error("REPLAY_DETECTED");
  }

  // Check capacity BEFORE inserting to prevent unbounded growth on CAPACITY_EXCEEDED
  // This ensures we don't insert entries that would exceed the limit
  ensureMemoryCapacity();

  // Store nonce after capacity check (atomic within event loop tick)
  // This ensures no concurrent request can pass the check before we write
  memoryNonceStore.set(nonceKey, now);
}

/**
 * Validate replay protection using Redis (primary) with in-memory fallback
 *
 * Two-factor replay protection:
 * 1. Timestamp window check (±5 minutes by default)
 * 2. Nonce uniqueness check
 *
 * Storage strategy:
 * - Primary: Redis (distributed, atomic operations)
 * - Fallback: In-memory Map (single-pod or sticky session deployments)
 */
export async function validateReplayProtection(
  nonce: string,
  timestamp: string
): Promise<void> {
  const ts = parseInt(timestamp, 10);
  const now = Date.now();

  // 1. Timestamp window check
  if (isNaN(ts) || Math.abs(now - ts) > TIMESTAMP_WINDOW_MS) {
    throw new Error("TIMESTAMP_INVALID");
  }

  // 2. Nonce uniqueness check
  const key = `${NONCE_PREFIX}${nonce}`;

  try {
    // Try Redis first (primary storage - distributed)
    if (!redis || redis.status !== "ready") {
      throw new Error("Redis not ready");
    }

    const wasSet = await redis.set(key, "1", "EX", NONCE_TTL_SEC, "NX");

    if (!wasSet) {
      if (logger) {
        logger.warn({ nonce }, "Replay attack detected (Redis)");
      }
      throw new Error("REPLAY_DETECTED");
    }
  } catch (error) {
    // CRITICAL: Re-throw REPLAY_DETECTED - don't allow fallback to bypass Redis detection
    if ((error as Error).message === "REPLAY_DETECTED") {
      throw error;
    }

    // Redis unavailable - fall back to in-memory nonce tracking
    if (logger) {
      logger.warn(
        { error: (error as Error).message },
        "Redis unavailable for nonce check - using in-memory fallback"
      );
    }

    checkAndStoreNonceInMemory(key);
  }
}

// Generate session ID with 128-bit entropy
export function generateSessionId(prefix: "S" | "A"): string {
  return `${prefix}-${crypto.randomBytes(16).toString("hex")}`;
}
