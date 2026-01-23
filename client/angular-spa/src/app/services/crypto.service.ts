import { Injectable } from '@angular/core';

export interface KeyPair {
  privateKey: CryptoKey;
  publicKey: CryptoKey;
  publicKeyBytes: Uint8Array;
}

export interface EncryptedData {
  // Body format: IV (12 bytes) || ciphertext || tag (16 bytes)
  encryptedBody: Uint8Array;
}

@Injectable({
  providedIn: 'root'
})
export class CryptoService {
  private crypto = window.crypto;
  private subtle = window.crypto.subtle;

  // Generate ECDH P-256 keypair
  async generateEcdhKeyPair(): Promise<KeyPair> {
    const keyPair = await this.subtle.generateKey(
      { name: 'ECDH', namedCurve: 'P-256' },
      true,
      ['deriveBits']
    );

    // Export public key to raw format (65 bytes uncompressed)
    const publicKeyBytes = new Uint8Array(
      await this.subtle.exportKey('raw', keyPair.publicKey)
    );

    return {
      privateKey: keyPair.privateKey,
      publicKey: keyPair.publicKey,
      publicKeyBytes
    };
  }

  // Compute ECDH shared secret
  async computeSharedSecret(
    privateKey: CryptoKey,
    peerPublicKeyBytes: Uint8Array
  ): Promise<Uint8Array> {
    // Import peer's public key
    const peerPublicKey = await this.subtle.importKey(
      'raw',
      peerPublicKeyBytes,
      { name: 'ECDH', namedCurve: 'P-256' },
      false,
      []
    );

    // Derive shared secret (32 bytes for P-256)
    const sharedBits = await this.subtle.deriveBits(
      { name: 'ECDH', public: peerPublicKey },
      privateKey,
      256
    );

    return new Uint8Array(sharedBits);
  }

  // HKDF-SHA256 key derivation
  async hkdf(
    sharedSecret: Uint8Array,
    salt: Uint8Array,
    info: Uint8Array,
    length: number = 32
  ): Promise<Uint8Array> {
    // Import shared secret as HKDF key material
    const keyMaterial = await this.subtle.importKey(
      'raw',
      sharedSecret,
      'HKDF',
      false,
      ['deriveBits']
    );

    // Derive key using HKDF
    const derivedBits = await this.subtle.deriveBits(
      {
        name: 'HKDF',
        hash: 'SHA-256',
        salt: salt,
        info: info
      },
      keyMaterial,
      length * 8
    );

    return new Uint8Array(derivedBits);
  }

  // AES-256-GCM encryption - returns IV || ciphertext || tag
  async aesGcmEncrypt(
    key: Uint8Array,
    plaintext: Uint8Array,
    aad: Uint8Array
  ): Promise<EncryptedData> {
    // Generate random 12-byte IV
    const iv = this.crypto.getRandomValues(new Uint8Array(12));

    // Import AES key
    const aesKey = await this.subtle.importKey(
      'raw',
      key,
      'AES-GCM',
      false,
      ['encrypt']
    );

    // Encrypt with AAD - Web Crypto returns ciphertext || tag
    const ciphertextWithTag = await this.subtle.encrypt(
      {
        name: 'AES-GCM',
        iv: iv,
        additionalData: aad,
        tagLength: 128
      },
      aesKey,
      plaintext
    );

    // Concatenate: IV (12 bytes) || ciphertext || tag (16 bytes)
    const result = new Uint8Array(12 + ciphertextWithTag.byteLength);
    result.set(iv, 0);
    result.set(new Uint8Array(ciphertextWithTag), 12);

    return { encryptedBody: result };
  }

  // AES-256-GCM decryption - expects IV || ciphertext || tag
  async aesGcmDecrypt(
    key: Uint8Array,
    aad: Uint8Array,
    encryptedBody: Uint8Array
  ): Promise<Uint8Array> {
    // Extract IV (first 12 bytes) and ciphertext+tag (rest)
    const iv = encryptedBody.slice(0, 12);
    const ciphertextWithTag = encryptedBody.slice(12);

    // Import AES key
    const aesKey = await this.subtle.importKey(
      'raw',
      key,
      'AES-GCM',
      false,
      ['decrypt']
    );

    // Decrypt
    const plaintext = await this.subtle.decrypt(
      {
        name: 'AES-GCM',
        iv: iv,
        additionalData: aad,
        tagLength: 128
      },
      aesKey,
      ciphertextWithTag
    );

    return new Uint8Array(plaintext);
  }

  // Generate UUID v4 for nonce
  generateNonce(): string {
    return crypto.randomUUID();
  }

  // Base64 encoding/decoding
  toBase64(bytes: Uint8Array): string {
    return btoa(String.fromCharCode(...bytes));
  }

  fromBase64(base64: string): Uint8Array {
    const binary = atob(base64);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
      bytes[i] = binary.charCodeAt(i);
    }
    return bytes;
  }

  // String to Uint8Array (UTF-8)
  stringToBytes(str: string): Uint8Array {
    return new TextEncoder().encode(str);
  }

  // Uint8Array to string (UTF-8)
  bytesToString(bytes: Uint8Array): string {
    return new TextDecoder().decode(bytes);
  }

  // Build AAD from request components
  // Format: TIMESTAMP|NONCE|KID|CLIENTID
  buildAad(timestamp: string, nonce: string, kid: string, clientId: string): Uint8Array {
    return this.stringToBytes(`${timestamp}|${nonce}|${kid}|${clientId}`);
  }
}
