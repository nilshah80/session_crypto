import { Injectable, inject } from '@angular/core';
import { HttpClient, HttpHeaders, HttpResponse } from '@angular/common/http';
import { firstValueFrom } from 'rxjs';
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

    const requestBody = {
      clientPublicKey: this.crypto.toBase64(keyPair.publicKeyBytes),
      ttlSec: 1800
    };

    if (verbose) {
      console.log('\n  📤 Sending POST /session/init');
      console.log(`     X-Nonce: ${nonce}`);
      console.log(`     X-Timestamp: ${timestamp}`);
      console.log(`     X-ClientId: ${this.CLIENT_ID}`);
    }

    // Make HTTP request
    const httpStart = performance.now();
    const response = await firstValueFrom(
      this.http.post<SessionInitResponse>(
        `${this.SERVER_URL}/session/init`,
        requestBody,
        {
          headers: new HttpHeaders({
            'Content-Type': 'application/json',
            'X-Nonce': nonce,
            'X-Timestamp': timestamp,
            'X-ClientId': this.CLIENT_ID
          }),
          observe: 'response'
        }
      )
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

    // Build AAD: TIMESTAMP|NONCE|KID|CLIENTID
    const aad = this.crypto.buildAad(timestamp, nonce, session.kid, session.clientId);

    // Encrypt the payload (IV is generated inside aesGcmEncrypt)
    const plaintext = this.crypto.stringToBytes(JSON.stringify(purchaseData));
    const encrypted = await this.measure('aes-gcm-encrypt', cryptoOps, () =>
      this.crypto.aesGcmEncrypt(session.sessionKey, plaintext, aad)
    );

    if (verbose) {
      console.log('\n  🔒 Encrypting request...');
      console.log(`     IV (base64): ${this.crypto.toBase64(encrypted.iv)}`);
      console.log(`     AAD: ${timestamp}|${nonce.slice(0, 8)}...|session:${session.sessionId.slice(0, 8)}...|${session.clientId}`);
      console.log(`     Ciphertext length: ${encrypted.ciphertext.length} bytes`);
      console.log(`     Auth tag (base64): ${this.crypto.toBase64(encrypted.tag)}`);
    }

    // Build request headers - use IV from encryption result
    const headers = new HttpHeaders({
      'Content-Type': 'text/plain',
      'X-Kid': session.kid,
      'X-Enc-Alg': 'A256GCM',
      'X-IV': this.crypto.toBase64(encrypted.iv),
      'X-Tag': this.crypto.toBase64(encrypted.tag),
      'X-AAD': this.crypto.toBase64(aad),
      'X-Nonce': nonce,
      'X-Timestamp': timestamp,
      'X-ClientId': session.clientId
    });

    if (verbose) {
      console.log('\n  📤 Sending encrypted POST /transaction/purchase');
    }

    // Make HTTP request
    const httpStart = performance.now();
    const response = await firstValueFrom(
      this.http.post(
        `${this.SERVER_URL}/transaction/purchase`,
        this.crypto.toBase64(encrypted.ciphertext),
        {
          headers,
          observe: 'response',
          responseType: 'text'
        }
      )
    );
    const httpMs = performance.now() - httpStart;

    const serverTiming = this.parseServerTiming(response.headers.get('Server-Timing'));

    if (verbose) {
      console.log(`\n  📥 Received encrypted response (status: ${response.status})`);
      console.log('     Response headers:');
      console.log(`       X-Kid: ${response.headers.get('X-Kid')}`);
      console.log(`       X-Enc-Alg: ${response.headers.get('X-Enc-Alg')}`);
      console.log(`       X-IV: ${response.headers.get('X-IV')?.slice(0, 20)}...`);
      console.log(`       X-Tag: ${response.headers.get('X-Tag')?.slice(0, 20)}...`);
    }

    // Decrypt response
    const responseIv = this.crypto.fromBase64(response.headers.get('X-IV')!);
    const responseTag = this.crypto.fromBase64(response.headers.get('X-Tag')!);
    const responseAad = this.crypto.fromBase64(response.headers.get('X-AAD')!);
    const responseCiphertext = this.crypto.fromBase64(response.body!);

    if (verbose) {
      console.log('\n  🔓 Decrypting response...');
    }

    const decrypted = await this.measure('aes-gcm-decrypt', cryptoOps, () =>
      this.crypto.aesGcmDecrypt(
        session.sessionKey,
        responseIv,
        responseAad,
        responseCiphertext,
        responseTag
      )
    );

    const purchaseResponse: PurchaseResponse = JSON.parse(
      this.crypto.bytesToString(decrypted)
    );

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

  // Clear session
  clearSession(): void {
    this.sessionContext = null;
  }

  // Get client ID
  getClientId(): string {
    return this.CLIENT_ID;
  }
}
