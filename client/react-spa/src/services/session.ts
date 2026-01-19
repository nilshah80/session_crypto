import * as crypto from './crypto';

const SERVER_URL = 'http://localhost:3000';
const CLIENT_ID = 'REACT_SPA_CLIENT';

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

// Measure operation timing
async function measure<T>(
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
function parseServerTiming(header: string | null): MetricsTiming[] {
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
export async function initSession(
  verbose: boolean = false,
  log: (msg: string) => void = console.log
): Promise<{ session: SessionContext; metrics: EndpointMetrics }> {
  const cryptoOps: MetricsTiming[] = [];
  const startTime = performance.now();

  if (verbose) {
    log('\n📡 Step 1: Initializing session with server...');
  }

  // Generate client ECDH keypair
  const keyPair = await measure('ecdh-keygen', cryptoOps, () =>
    crypto.generateEcdhKeyPair()
  );

  if (verbose) {
    log('  ✅ Generated client ECDH keypair');
    log(`     Public key (first 32 chars): ${crypto.toBase64(keyPair.publicKeyBytes).slice(0, 32)}...`);
  }

  const nonce = crypto.generateNonce();
  const timestamp = Date.now().toString();

  const requestBody = {
    clientPublicKey: crypto.toBase64(keyPair.publicKeyBytes),
    ttlSec: 1800
  };

  if (verbose) {
    log('\n  📤 Sending POST /session/init');
    log(`     X-Nonce: ${nonce}`);
    log(`     X-Timestamp: ${timestamp}`);
    log(`     X-ClientId: ${CLIENT_ID}`);
  }

  // Make HTTP request
  const httpStart = performance.now();
  const response = await fetch(`${SERVER_URL}/session/init`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'X-Nonce': nonce,
      'X-Timestamp': timestamp,
      'X-ClientId': CLIENT_ID
    },
    body: JSON.stringify(requestBody)
  });
  const httpMs = performance.now() - httpStart;

  if (!response.ok) {
    throw new Error(`Session init failed: ${response.status}`);
  }

  const data: SessionInitResponse = await response.json();
  const serverTiming = parseServerTiming(response.headers.get('Server-Timing'));

  if (verbose) {
    log('\n  📥 Received response:');
    log(`     Session ID: ${data.sessionId}`);
    log(`     Encryption: ${data.encAlg}`);
    log(`     Expires in: ${data.expiresInSec} seconds`);
    log(`     Server public key (first 32 chars): ${data.serverPublicKey.slice(0, 32)}...`);
  }

  // Compute shared secret
  const serverPubBytes = crypto.fromBase64(data.serverPublicKey);
  const sharedSecret = await measure('ecdh-compute', cryptoOps, () =>
    crypto.computeSharedSecret(keyPair.privateKey, serverPubBytes)
  );

  if (verbose) {
    log('\n  🔐 Computed ECDH shared secret');
  }

  // Derive session key using HKDF
  const salt = crypto.stringToBytes(data.sessionId);
  const info = crypto.stringToBytes(`SESSION|A256GCM|${CLIENT_ID}`);
  const sessionKey = await measure('hkdf', cryptoOps, () =>
    crypto.hkdf(sharedSecret, salt, info, 32)
  );

  if (verbose) {
    log('  🔑 Derived session key using HKDF-SHA256');
    log(`     Session key (first 16 chars): ${crypto.toBase64(sessionKey).slice(0, 16)}...`);
  }

  const kid = `session:${data.sessionId}`;
  const session: SessionContext = {
    sessionId: data.sessionId,
    sessionKey,
    kid,
    clientId: CLIENT_ID
  };

  const metrics: EndpointMetrics = {
    endpoint: '/session/init',
    totalMs: performance.now() - startTime,
    httpMs,
    cryptoOps,
    serverTiming
  };

  return { session, metrics };
}

// Make encrypted purchase request
export async function makePurchase(
  session: SessionContext,
  purchaseData: PurchaseRequest,
  verbose: boolean = false,
  log: (msg: string) => void = console.log
): Promise<{ response: PurchaseResponse; metrics: EndpointMetrics }> {
  const cryptoOps: MetricsTiming[] = [];
  const startTime = performance.now();

  if (verbose) {
    log('\n📡 Step 2: Making encrypted purchase request...');
    log('\n  📝 Request payload:');
    log(`     ${JSON.stringify(purchaseData)}`);
  }

  const nonce = crypto.generateNonce();
  const timestamp = Date.now().toString();

  // Build AAD: TIMESTAMP|NONCE|KID|CLIENTID
  const aad = crypto.buildAad(timestamp, nonce, session.kid, session.clientId);

  // Encrypt the payload (IV is generated inside aesGcmEncrypt)
  const plaintext = crypto.stringToBytes(JSON.stringify(purchaseData));
  const encrypted = await measure('aes-gcm-encrypt', cryptoOps, () =>
    crypto.aesGcmEncrypt(session.sessionKey, plaintext, aad)
  );

  if (verbose) {
    log('\n  🔒 Encrypting request...');
    log(`     IV (base64): ${crypto.toBase64(encrypted.iv)}`);
    log(`     AAD: ${timestamp}|${nonce.slice(0, 8)}...|session:${session.sessionId.slice(0, 8)}...|${session.clientId}`);
    log(`     Ciphertext length: ${encrypted.ciphertext.length} bytes`);
    log(`     Auth tag (base64): ${crypto.toBase64(encrypted.tag)}`);
  }

  if (verbose) {
    log('\n  📤 Sending encrypted POST /transaction/purchase');
  }

  // Make HTTP request
  const httpStart = performance.now();
  const response = await fetch(`${SERVER_URL}/transaction/purchase`, {
    method: 'POST',
    headers: {
      'Content-Type': 'text/plain',
      'X-Kid': session.kid,
      'X-Enc-Alg': 'A256GCM',
      'X-IV': crypto.toBase64(encrypted.iv),
      'X-Tag': crypto.toBase64(encrypted.tag),
      'X-AAD': crypto.toBase64(aad),
      'X-Nonce': nonce,
      'X-Timestamp': timestamp,
      'X-ClientId': session.clientId
    },
    body: crypto.toBase64(encrypted.ciphertext)
  });
  const httpMs = performance.now() - httpStart;

  if (!response.ok) {
    throw new Error(`Purchase failed: ${response.status}`);
  }

  const serverTiming = parseServerTiming(response.headers.get('Server-Timing'));

  if (verbose) {
    log(`\n  📥 Received encrypted response (status: ${response.status})`);
    log('     Response headers:');
    log(`       X-Kid: ${response.headers.get('X-Kid')}`);
    log(`       X-Enc-Alg: ${response.headers.get('X-Enc-Alg')}`);
    log(`       X-IV: ${response.headers.get('X-IV')?.slice(0, 20)}...`);
    log(`       X-Tag: ${response.headers.get('X-Tag')?.slice(0, 20)}...`);
  }

  // Decrypt response
  const responseIv = crypto.fromBase64(response.headers.get('X-IV')!);
  const responseTag = crypto.fromBase64(response.headers.get('X-Tag')!);
  const responseAad = crypto.fromBase64(response.headers.get('X-AAD')!);
  const responseCiphertext = crypto.fromBase64(await response.text());

  if (verbose) {
    log('\n  🔓 Decrypting response...');
  }

  const decrypted = await measure('aes-gcm-decrypt', cryptoOps, () =>
    crypto.aesGcmDecrypt(
      session.sessionKey,
      responseIv,
      responseAad,
      responseCiphertext,
      responseTag
    )
  );

  const purchaseResponse: PurchaseResponse = JSON.parse(
    crypto.bytesToString(decrypted)
  );

  if (verbose) {
    log('  ✅ Decryption successful!');
    log('\n  📋 Decrypted response:');
    log('  ─────────────────────────────────────────');
    log(JSON.stringify(purchaseResponse, null, 2));
    log('  ─────────────────────────────────────────');
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

export function getClientId(): string {
  return CLIENT_ID;
}
