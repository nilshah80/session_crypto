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

// Generate random IV (12 bytes for AES-GCM)
export function generateIv(): Buffer {
  return crypto.randomBytes(12);
}
