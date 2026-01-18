import crypto from "crypto";

// Base64 encoding/decoding helpers
export const b64 = (buf: Buffer): string => buf.toString("base64");
export const unb64 = (s: string): Buffer => Buffer.from(s, "base64");

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

// AES-256-GCM encryption
export function aesGcmEncrypt(
  key32: Buffer,
  iv12: Buffer,
  aad: Buffer,
  plaintext: Buffer
): { ciphertext: Buffer; tag: Buffer } {
  const cipher = crypto.createCipheriv("aes-256-gcm", key32, iv12);
  cipher.setAAD(aad);
  const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  const tag = cipher.getAuthTag();
  return { ciphertext, tag };
}

// AES-256-GCM decryption
export function aesGcmDecrypt(
  key32: Buffer,
  iv12: Buffer,
  aad: Buffer,
  ciphertext: Buffer,
  tag: Buffer
): Buffer {
  const decipher = crypto.createDecipheriv("aes-256-gcm", key32, iv12);
  decipher.setAAD(aad);
  decipher.setAuthTag(tag);
  return Buffer.concat([decipher.update(ciphertext), decipher.final()]);
}

// Build AAD from request components
export function buildAad(
  method: string,
  path: string,
  ts: string,
  nonce: string,
  kid: string
): Buffer {
  return Buffer.from(`${method}|${path}|${ts}|${nonce}|${kid}`, "utf8");
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
const NONCE_TTL_SEC = 300;

// Validate replay protection (for PoC using in-memory Map, use Redis in production)
const nonceStore = new Map<string, number>();

export function validateReplayProtection(
  nonce: string,
  timestamp: string
): void {
  const ts = parseInt(timestamp, 10);
  const now = Date.now();

  // 1. Timestamp window check
  if (isNaN(ts) || Math.abs(now - ts) > TIMESTAMP_WINDOW_MS) {
    throw new Error("TIMESTAMP_INVALID");
  }

  // 2. Nonce uniqueness check
  const key = `nonce:${nonce}`;
  if (nonceStore.has(key)) {
    throw new Error("REPLAY_DETECTED");
  }

  // Store nonce with expiry
  nonceStore.set(key, now);

  // Cleanup old nonces (simple implementation)
  setTimeout(() => {
    nonceStore.delete(key);
  }, NONCE_TTL_SEC * 1000);
}

// Generate random IV (12 bytes for AES-GCM)
export function generateIv(): Buffer {
  return crypto.randomBytes(12);
}

// Generate session ID with 128-bit entropy
export function generateSessionId(prefix: "S" | "A"): string {
  return `${prefix}-${crypto.randomBytes(16).toString("hex")}`;
}
