import crypto from "crypto";

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

    // OPTIMIZATION: Pre-allocate result buffer
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
