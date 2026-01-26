import { Injectable, inject } from '@angular/core';
import { HttpClient, HttpHeaders, HttpResponse } from '@angular/common/http';
import { firstValueFrom, timeout } from 'rxjs';
import { CryptoService, KeyPair } from './crypto.service';

export interface SessionInitResponse {
  sessionId: string;
  serverPublicKey: string;
  encAlg: string;
  expiresInSec: number;
}

export interface SessionContext {
  sessionId: string;
  sessionKey: Uint8Array;
  kid: string;
  clientId: string;
}

export interface PurchaseRequest {
  schemeCode: string;
  amount: number;
}

export interface PurchaseResponse {
  status: string;
  transactionId: string;
  schemeCode: string;
  amount: number;
  message: string;
  timestamp: string;
}

export interface MetricsTiming {
  operation: string;
  durationMs: number;
}

export interface EndpointMetrics {
  endpoint: string;
  totalMs: number;
  httpMs: number;
  cryptoOps: MetricsTiming[];
  serverTiming: MetricsTiming[];
}

@Injectable({
  providedIn: 'root'
})
export class SessionService {
  private readonly SERVER_URL = 'http://localhost:3000';
  private readonly CLIENT_ID = 'ANGULAR_SPA_CLIENT';

  private http = inject(HttpClient);
  private crypto = inject(CryptoService);

  // Current session context
  private sessionContext: SessionContext | null = null;

  // Measure operation timing
  private async measure<T>(
    operation: string,
    timings: MetricsTiming[],
    fn: () => Promise<T>
  ): Promise<T> {
    const start = performance.now();
    const result = await fn();
    timings.push({
      operation,
      durationMs: performance.now() - start
    });
    return result;
  }

  // Parse Server-Timing header
  private parseServerTiming(header: string | null): MetricsTiming[] {
    if (!header) return [];

    return header.split(',').map(entry => {
      const parts = entry.trim().split(';');
      const name = parts[0];
      const durMatch = parts.find(p => p.includes('dur='));
      const duration = durMatch ? parseFloat(durMatch.split('=')[1]) : 0;
      return { operation: name, durationMs: duration };
    });
  }

  // Initialize session with server
  async initSession(verbose: boolean = false): Promise<{ session: SessionContext; metrics: EndpointMetrics }> {
    const cryptoOps: MetricsTiming[] = [];
    const startTime = performance.now();

    if (verbose) {
      console.log('\n📡 Step 1: Initializing session with server...');
    }

    // Generate client ECDH keypair
    const keyPair = await this.measure('ecdh-keygen', cryptoOps, () =>
      this.crypto.generateEcdhKeyPair()
    );

    if (verbose) {
      console.log('  ✅ Generated client ECDH keypair');
      console.log(`     Public key (first 32 chars): ${this.crypto.toBase64(keyPair.publicKeyBytes).slice(0, 32)}...`);
    }

    const nonce = this.crypto.generateNonce();
    const timestamp = Date.now().toString();
    const requestId = `${timestamp}.${nonce}`;

    const requestBody = {
      clientPublicKey: this.crypto.toBase64(keyPair.publicKeyBytes),
      ttlSec: 1800
    };

    if (verbose) {
      console.log('\n  📤 Sending POST /session/init');
      console.log(`     X-Idempotency-Key: ${requestId}`);
      console.log(`     X-ClientId: ${this.CLIENT_ID}`);
    }

    // Make HTTP request with 30-second timeout
    const httpStart = performance.now();
    const response = await firstValueFrom(
      this.http.post<SessionInitResponse>(
        `${this.SERVER_URL}/session/init`,
        requestBody,
        {
          headers: new HttpHeaders({
            'Content-Type': 'application/json',
            'X-Idempotency-Key': requestId,
            'X-ClientId': this.CLIENT_ID
          }),
          observe: 'response'
        }
      ).pipe(timeout(30000))
    );
    const httpMs = performance.now() - httpStart;

    const data = response.body!;
    const serverTiming = this.parseServerTiming(response.headers.get('Server-Timing'));

    if (verbose) {
      console.log('\n  📥 Received response:');
      console.log(`     Session ID: ${data.sessionId}`);
      console.log(`     Encryption: ${data.encAlg}`);
      console.log(`     Expires in: ${data.expiresInSec} seconds`);
      console.log(`     Server public key (first 32 chars): ${data.serverPublicKey.slice(0, 32)}...`);
    }

    // Compute shared secret
    const serverPubBytes = this.crypto.fromBase64(data.serverPublicKey);
    const sharedSecret = await this.measure('ecdh-compute', cryptoOps, () =>
      this.crypto.computeSharedSecret(keyPair.privateKey, serverPubBytes)
    );

    if (verbose) {
      console.log('\n  🔐 Computed ECDH shared secret');
    }

    // Derive session key using HKDF
    const salt = this.crypto.stringToBytes(data.sessionId);
    const info = this.crypto.stringToBytes(`SESSION|A256GCM|${this.CLIENT_ID}`);
    const sessionKey = await this.measure('hkdf', cryptoOps, () =>
      this.crypto.hkdf(sharedSecret, salt, info, 32)
    );

    // Zeroize shared secret immediately after key derivation
    this.crypto.zeroize(sharedSecret);

    if (verbose) {
      console.log('  🔑 Derived session key using HKDF-SHA256');
      console.log(`     Session key (first 16 chars): ${this.crypto.toBase64(sessionKey).slice(0, 16)}...`);
    }

    const kid = `session:${data.sessionId}`;
    this.sessionContext = {
      sessionId: data.sessionId,
      sessionKey,
      kid,
      clientId: this.CLIENT_ID
    };

    const metrics: EndpointMetrics = {
      endpoint: '/session/init',
      totalMs: performance.now() - startTime,
      httpMs,
      cryptoOps,
      serverTiming
    };

    return { session: this.sessionContext, metrics };
  }

  // Make encrypted purchase request
  async makePurchase(
    purchaseData: PurchaseRequest,
    verbose: boolean = false
  ): Promise<{ response: PurchaseResponse; metrics: EndpointMetrics }> {
    if (!this.sessionContext) {
      throw new Error('No active session. Call initSession() first.');
    }

    const cryptoOps: MetricsTiming[] = [];
    const startTime = performance.now();
    const session = this.sessionContext;

    if (verbose) {
      console.log('\n📡 Step 2: Making encrypted purchase request...');
      console.log('\n  📝 Request payload:');
      console.log(`     ${JSON.stringify(purchaseData)}`);
    }

    const nonce = this.crypto.generateNonce();
    const timestamp = Date.now().toString();
    const requestId = `${timestamp}.${nonce}`;

    // Build AAD: TIMESTAMP|NONCE|KID|CLIENTID
    const aad = this.crypto.buildAad(timestamp, nonce, session.kid, session.clientId);

    // Encrypt the payload - returns IV || ciphertext || tag
    const plaintext = this.crypto.stringToBytes(JSON.stringify(purchaseData));
    const encrypted = await this.measure('aes-gcm-encrypt', cryptoOps, () =>
      this.crypto.aesGcmEncrypt(session.sessionKey, plaintext, aad)
    );

    // Zeroize plaintext after encryption
    this.crypto.zeroize(plaintext);

    if (verbose) {
      console.log('\n  🔒 Encrypting request...');
      console.log(`     AAD: ${timestamp}|${nonce.slice(0, 8)}...|session:${session.sessionId.slice(0, 8)}...|${session.clientId}`);
      console.log(`     Encrypted body length: ${encrypted.encryptedBody.length} bytes (IV + ciphertext + tag)`);
    }

    // Build request headers (reduced from 9 to 3 custom headers)
    const headers = new HttpHeaders({
      'Content-Type': 'application/octet-stream',
      'X-Kid': session.kid,
      'X-Idempotency-Key': requestId,
      'X-ClientId': session.clientId
    });

    if (verbose) {
      console.log('\n  📤 Sending encrypted POST /transaction/purchase');
    }

    // Make HTTP request with binary body and 30-second timeout
    // Wrap Uint8Array in Blob to ensure Angular sends it as raw binary
    const blob = new Blob([encrypted.encryptedBody], { type: 'application/octet-stream' });
    const httpStart = performance.now();
    const response = await firstValueFrom(
      this.http.post(
        `${this.SERVER_URL}/transaction/purchase`,
        blob,
        {
          headers,
          observe: 'response',
          responseType: 'arraybuffer'
        }
      ).pipe(timeout(30000))
    );
    const httpMs = performance.now() - httpStart;

    const serverTiming = this.parseServerTiming(response.headers.get('Server-Timing'));

    // Extract response headers
    const respKid = response.headers.get('X-Kid');
    const respRequestId = response.headers.get('X-Idempotency-Key');

    if (verbose) {
      console.log(`\n  📥 Received encrypted response (status: ${response.status})`);
      console.log('     Response headers:');
      console.log(`       X-Kid: ${respKid}`);
      console.log(`       X-Idempotency-Key: ${respRequestId?.slice(0, 30)}...`);
    }

    if (!respKid || !respRequestId) {
      throw new Error('Missing required headers in response');
    }

    // Parse response request ID to get timestamp and nonce for AAD reconstruction
    const [respTimestamp, respNonce] = respRequestId.split('.');
    if (!respTimestamp || !respNonce) {
      throw new Error('Invalid X-Idempotency-Key format in response');
    }

    // Reconstruct AAD from response headers
    const responseAad = this.crypto.buildAad(respTimestamp, respNonce, respKid, session.clientId);

    // Get encrypted body (IV || ciphertext || tag)
    const responseEncryptedBody = new Uint8Array(response.body as ArrayBuffer);

    if (verbose) {
      console.log(`     Encrypted body length: ${responseEncryptedBody.length} bytes`);
      console.log('\n  🔓 Decrypting response...');
    }

    const decrypted = await this.measure('aes-gcm-decrypt', cryptoOps, () =>
      this.crypto.aesGcmDecrypt(
        session.sessionKey,
        responseAad,
        responseEncryptedBody
      )
    );

    const purchaseResponse: PurchaseResponse = JSON.parse(
      this.crypto.bytesToString(decrypted)
    );

    // Zeroize decrypted response after parsing
    this.crypto.zeroize(decrypted);

    if (verbose) {
      console.log('  ✅ Decryption successful!');
      console.log('\n  📋 Decrypted response:');
      console.log('  ─────────────────────────────────────────');
      console.log(JSON.stringify(purchaseResponse, null, 2));
      console.log('  ─────────────────────────────────────────');
    }

    const metrics: EndpointMetrics = {
      endpoint: '/transaction/purchase',
      totalMs: performance.now() - startTime,
      httpMs,
      cryptoOps,
      serverTiming
    };

    return { response: purchaseResponse, metrics };
  }

  // Get current session
  getSession(): SessionContext | null {
    return this.sessionContext;
  }

  // Clear session and zeroize sensitive data
  clearSession(): void {
    if (this.sessionContext) {
      // Zeroize session key before clearing context
      this.crypto.zeroize(this.sessionContext.sessionKey);
      this.sessionContext = null;
    }
  }

  // Get client ID
  getClientId(): string {
    return this.CLIENT_ID;
  }
}
