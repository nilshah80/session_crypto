import * as crypto from 'crypto';
import { CRYPTO } from '../constants';

/**
 * Crypto utility functions for ECDH key exchange, HKDF key derivation,
 * and AES-256-GCM encryption/decryption.
 *
 * Based on session-crypto/server/src/crypto-helpers.ts
 */

// Base64 encoding/decoding helpers
export const b64 = (buf: Buffer): string => buf.toString('base64');
export const unb64 = (s: string): Buffer => Buffer.from(s, 'base64');

// AES-256-GCM constants
const IV_SIZE = CRYPTO.AES_IV_LENGTH;
const TAG_SIZE = CRYPTO.AES_TAG_LENGTH;

// OPTIMIZATION: Buffer pool for IV reuse
// NOTE: This pool is NOT thread-safe. It's safe for single-threaded Node.js event loop,
// but would require synchronization if crypto operations are moved to worker threads.
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

/**
 * Create ECDH keypair using P-256 curve
 * @returns ECDH instance and public key
 */
export function createEcdhKeypair() {
  const ecdh = crypto.createECDH(CRYPTO.ECDH_CURVE); // P-256
  ecdh.generateKeys();
  return { ecdh, publicKey: ecdh.getPublicKey() };
}

/**
 * HKDF to derive 32-byte AES key from shared secret
 * @param sharedSecret ECDH shared secret
 * @param salt Salt for key derivation
 * @param info Context information for key derivation
 * @returns 32-byte AES key
 */
export function hkdf32(sharedSecret: Buffer, salt: Buffer, info: Buffer): Buffer {
  return Buffer.from(crypto.hkdfSync('sha256', sharedSecret, salt, info, CRYPTO.AES_KEY_LENGTH));
}

/**
 * AES-256-GCM encryption - returns IV || ciphertext || tag
 * OPTIMIZED: Uses buffer pooling and optimized concatenation
 * @param key32 32-byte AES key
 * @param aad Additional authenticated data
 * @param plaintext Data to encrypt
 * @returns IV || ciphertext || auth tag
 */
export function aesGcmEncrypt(key32: Buffer, aad: Buffer, plaintext: Buffer): Buffer {
  // Get IV from pool
  const iv = getIVBuffer();
  crypto.randomFillSync(iv);

  try {
    const cipher = crypto.createCipheriv(CRYPTO.AES_ALGORITHM, key32, iv);
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

/**
 * AES-256-GCM decryption - expects IV || ciphertext || tag
 * OPTIMIZED: Avoids Buffer.concat()
 * @param key32 32-byte AES key
 * @param aad Additional authenticated data
 * @param data IV || ciphertext || auth tag
 * @returns Decrypted plaintext
 */
export function aesGcmDecrypt(key32: Buffer, aad: Buffer, data: Buffer): Buffer {
  const iv = data.subarray(0, IV_SIZE);
  const tag = data.subarray(-TAG_SIZE);
  const ciphertext = data.subarray(IV_SIZE, -TAG_SIZE);

  const decipher = crypto.createDecipheriv(CRYPTO.AES_ALGORITHM, key32, iv);
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

/**
 * Build AAD (Additional Authenticated Data) from request components
 * Format: TIMESTAMP|NONCE|KID|CLIENTID
 * @param ts Timestamp string
 * @param nonce Nonce string
 * @param kid Key ID
 * @param clientId Client identifier
 * @returns AAD buffer
 */
export function buildAad(ts: string, nonce: string, kid: string, clientId: string): Buffer {
  return Buffer.from(`${ts}|${nonce}|${kid}|${clientId}`, 'utf8');
}

/**
 * Validate P-256 public key is on curve
 * @param publicKeyBytes Public key bytes (65 bytes: 0x04 || X || Y)
 * @throws Error if key is invalid or not on curve
 */
export function validateP256PublicKey(publicKeyBytes: Buffer): void {
  // P-256 uncompressed point: 0x04 || X (32 bytes) || Y (32 bytes) = 65 bytes
  if (publicKeyBytes.length !== 65) {
    throw new Error('INVALID_KEY_LENGTH');
  }

  if (publicKeyBytes[0] !== 0x04) {
    throw new Error('INVALID_KEY_FORMAT');
  }

  // Use Node.js crypto to validate point is on curve
  try {
    const keyObject = crypto.createPublicKey({
      key: Buffer.concat([
        // SPKI header for P-256 uncompressed point
        Buffer.from('3059301306072a8648ce3d020106082a8648ce3d030107034200', 'hex'),
        publicKeyBytes,
      ]),
      format: 'der',
      type: 'spki',
    });

    if (keyObject.asymmetricKeyType !== 'ec') {
      throw new Error('INVALID_KEY_TYPE');
    }
  } catch {
    throw new Error('POINT_NOT_ON_CURVE');
  }
}

/**
 * Generate session ID with 128-bit entropy
 * @param _prefix Session type prefix ('S' for session, 'A' for alternate) - reserved for future use
 * @returns Session ID with format: PREFIX-hexstring
 */
export function generateSessionId(_prefix: 'S' | 'A' = 'S'): string {
  return `${CRYPTO.SESSION_ID_PREFIX}${crypto.randomBytes(CRYPTO.SESSION_ID_LENGTH).toString('hex')}`;
}

/**
 * Zeroize sensitive buffer data
 * @param buffer Buffer to zeroize
 */
export function zeroizeBuffer(buffer: Buffer): void {
  buffer.fill(0);
}
