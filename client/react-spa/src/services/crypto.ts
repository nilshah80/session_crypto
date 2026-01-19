export interface KeyPair {
  privateKey: CryptoKey;
  publicKey: CryptoKey;
  publicKeyBytes: Uint8Array;
}

export interface EncryptedData {
  ciphertext: Uint8Array;
  iv: Uint8Array;
  tag: Uint8Array;
}

const cryptoSubtle = window.crypto.subtle;

// Generate ECDH P-256 keypair
export async function generateEcdhKeyPair(): Promise<KeyPair> {
  const keyPair = await cryptoSubtle.generateKey(
    { name: 'ECDH', namedCurve: 'P-256' },
    true,
    ['deriveBits']
  );

  const publicKeyBytes = new Uint8Array(
    await cryptoSubtle.exportKey('raw', keyPair.publicKey)
  );

  return {
    privateKey: keyPair.privateKey,
    publicKey: keyPair.publicKey,
    publicKeyBytes
  };
}

// Compute ECDH shared secret
export async function computeSharedSecret(
  privateKey: CryptoKey,
  peerPublicKeyBytes: Uint8Array
): Promise<Uint8Array> {
  const peerPublicKey = await cryptoSubtle.importKey(
    'raw',
    peerPublicKeyBytes,
    { name: 'ECDH', namedCurve: 'P-256' },
    false,
    []
  );

  const sharedBits = await cryptoSubtle.deriveBits(
    { name: 'ECDH', public: peerPublicKey },
    privateKey,
    256
  );

  return new Uint8Array(sharedBits);
}

// HKDF-SHA256 key derivation
export async function hkdf(
  sharedSecret: Uint8Array,
  salt: Uint8Array,
  info: Uint8Array,
  length: number = 32
): Promise<Uint8Array> {
  const keyMaterial = await cryptoSubtle.importKey(
    'raw',
    sharedSecret,
    'HKDF',
    false,
    ['deriveBits']
  );

  const derivedBits = await cryptoSubtle.deriveBits(
    {
      name: 'HKDF',
      hash: 'SHA-256',
      salt,
      info
    },
    keyMaterial,
    length * 8
  );

  return new Uint8Array(derivedBits);
}

// AES-256-GCM encryption
export async function aesGcmEncrypt(
  key: Uint8Array,
  plaintext: Uint8Array,
  aad: Uint8Array
): Promise<EncryptedData> {
  const iv = window.crypto.getRandomValues(new Uint8Array(12));

  const aesKey = await cryptoSubtle.importKey(
    'raw',
    key,
    'AES-GCM',
    false,
    ['encrypt']
  );

  const ciphertextWithTag = await cryptoSubtle.encrypt(
    {
      name: 'AES-GCM',
      iv,
      additionalData: aad,
      tagLength: 128
    },
    aesKey,
    plaintext
  );

  const result = new Uint8Array(ciphertextWithTag);
  const ciphertext = result.slice(0, -16);
  const tag = result.slice(-16);

  return { ciphertext, iv, tag };
}

// AES-256-GCM decryption
export async function aesGcmDecrypt(
  key: Uint8Array,
  iv: Uint8Array,
  aad: Uint8Array,
  ciphertext: Uint8Array,
  tag: Uint8Array
): Promise<Uint8Array> {
  const aesKey = await cryptoSubtle.importKey(
    'raw',
    key,
    'AES-GCM',
    false,
    ['decrypt']
  );

  const ciphertextWithTag = new Uint8Array(ciphertext.length + tag.length);
  ciphertextWithTag.set(ciphertext);
  ciphertextWithTag.set(tag, ciphertext.length);

  const plaintext = await cryptoSubtle.decrypt(
    {
      name: 'AES-GCM',
      iv,
      additionalData: aad,
      tagLength: 128
    },
    aesKey,
    ciphertextWithTag
  );

  return new Uint8Array(plaintext);
}

// Generate UUID v4 for nonce
export function generateNonce(): string {
  return crypto.randomUUID();
}

// Base64 encoding/decoding
export function toBase64(bytes: Uint8Array): string {
  return btoa(String.fromCharCode(...bytes));
}

export function fromBase64(base64: string): Uint8Array {
  const binary = atob(base64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}

// String to Uint8Array (UTF-8)
export function stringToBytes(str: string): Uint8Array {
  return new TextEncoder().encode(str);
}

// Uint8Array to string (UTF-8)
export function bytesToString(bytes: Uint8Array): string {
  return new TextDecoder().decode(bytes);
}

// Build AAD: TIMESTAMP|NONCE|KID|CLIENTID
export function buildAad(
  timestamp: string,
  nonce: string,
  kid: string,
  clientId: string
): Uint8Array {
  return stringToBytes(`${timestamp}|${nonce}|${kid}|${clientId}`);
}
