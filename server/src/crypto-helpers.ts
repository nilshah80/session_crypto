import crypto from "crypto";
import { Redis } from "ioredis";

// Base64 encoding/decoding helpers
export const b64 = (buf: Buffer): string => buf.toString("base64");
export const unb64 = (s: string): Buffer => Buffer.from(s, "base64");

// OPTIMIZATION: Buffer pool for IV reuse
// NOTE: This pool is NOT thread-safe. It's safe for single-threaded Node.js event loop,
// but would require synchronization (e.g., locks or per-thread pools) if crypto operations
// are moved to worker threads or if Node.js is run in cluster mode with shared state.
// For multi-threaded scenarios, consider: AsyncLocalStorage-based pools, per-request buffers,
// or thread-safe queue implementations.
const ivPool: Buffer[] = [];
const IV_POOL_MAX_SIZE = 100;

function getIVBuffer(): Buffer {
  return ivPool.pop() || Buffer.allocUnsafe(12);
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
    const result = Buffer.allocUnsafe(12 + plaintext.length + 16);

    // Copy IV
    iv.copy(result, 0, 0, 12);

    // Encrypt and copy ciphertext
    const updateResult = cipher.update(plaintext);
    updateResult.copy(result, 12);
    const finalResult = cipher.final();
    finalResult.copy(result, 12 + updateResult.length);

    // Copy auth tag
    const tag = cipher.getAuthTag();
    tag.copy(result, result.length - 16);

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
  const iv = data.subarray(0, 12);
  const tag = data.subarray(-16);
  const ciphertext = data.subarray(12, -16);

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

// Replay protection constants
const TIMESTAMP_WINDOW_MS = 5 * 60 * 1000; // ±5 minutes
const NONCE_TTL_SEC = 300; // 5 minutes
const NONCE_PREFIX = "nonce:";

let redis: Redis | null = null;

export function initReplayProtection(redisClient: Redis): void {
  redis = redisClient;
}

// Validate replay protection using Redis
export async function validateReplayProtection(
  nonce: string,
  timestamp: string
): Promise<void> {
  if (!redis) {
    throw new Error("Replay protection not initialized");
  }

  const ts = parseInt(timestamp, 10);
  const now = Date.now();

  // 1. Timestamp window check
  if (isNaN(ts) || Math.abs(now - ts) > TIMESTAMP_WINDOW_MS) {
    throw new Error("TIMESTAMP_INVALID");
  }

  // 2. Nonce uniqueness (atomic check-and-set using Redis SET NX EX)
  const key = `${NONCE_PREFIX}${nonce}`;
  const wasSet = await redis.set(key, "1", "EX", NONCE_TTL_SEC, "NX");

  if (!wasSet) {
    throw new Error("REPLAY_DETECTED");
  }
}

// Generate session ID with 128-bit entropy
export function generateSessionId(prefix: "S" | "A"): string {
  return `${prefix}-${crypto.randomBytes(16).toString("hex")}`;
}
