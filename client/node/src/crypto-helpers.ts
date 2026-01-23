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

// AES-256-GCM encryption - returns IV || ciphertext || tag
export function aesGcmEncrypt(
  key32: Buffer,
  aad: Buffer,
  plaintext: Buffer
): Buffer {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv("aes-256-gcm", key32, iv);
  cipher.setAAD(aad);
  const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  const tag = cipher.getAuthTag();
  return Buffer.concat([iv, ciphertext, tag]); // IV (12) || ciphertext || tag (16)
}

// AES-256-GCM decryption - expects IV || ciphertext || tag
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
  return Buffer.concat([decipher.update(ciphertext), decipher.final()]);
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

