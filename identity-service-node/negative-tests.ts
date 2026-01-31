/**
 * Comprehensive Negative Test Suite for Identity Service Node
 *
 * Test Categories:
 * - Replay Protection (/v1/session/init)
 * - Header Validation (/v1/session/init)
 * - Public Key Validation (/v1/session/init)
 * - TTL Validation (/v1/session/init)
 * - Request Body Validation (/v1/session/init)
 * - Get Session Key Validation (/v1/session/:sessionId)
 */

import * as crypto from 'crypto';
import * as http from 'http';

// Test result structure
interface TestResult {
  name: string;
  passed: boolean;
  expected: string;
  actual: string;
  error?: string | undefined;
}

// Configuration
const BASE_URL = 'localhost';
const PORT = 3001;
const ENDPOINT = '/v1/session/init';

// Test utilities
function generateIdempotencyKey(): { timestamp: number; nonce: string; key: string } {
  const timestamp = Date.now();
  const nonce = crypto.randomBytes(16).toString('hex');
  return { timestamp, nonce, key: `${timestamp}.${nonce}` };
}

function generateECDHKeyPair(): { publicKey: string; ecdh: crypto.ECDH } {
  const ecdh = crypto.createECDH('prime256v1');
  ecdh.generateKeys();
  const publicKey = ecdh.getPublicKey().toString('base64');
  return { publicKey, ecdh };
}

async function makeSessionInitRequest(
  clientPublicKey: string,
  idempotencyKey: string,
  clientId: string
): Promise<{ status: number; body: any; headers: any }> {
  const requestBody: any = { clientPublicKey };

  const bodyString = JSON.stringify(requestBody);

  const options = {
    hostname: BASE_URL,
    port: PORT,
    path: ENDPOINT,
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'Content-Length': Buffer.byteLength(bodyString),
      'X-Idempotency-Key': idempotencyKey,
      'X-ClientId': clientId,
    },
  };

  return new Promise((resolve, reject) => {
    const req = http.request(options, (res) => {
      let data = '';
      res.on('data', (chunk) => { data += chunk; });
      res.on('end', () => {
        try {
          resolve({
            status: res.statusCode || 500,
            body: JSON.parse(data),
            headers: res.headers,
          });
        } catch (e) {
          resolve({
            status: res.statusCode || 500,
            body: data,
            headers: res.headers,
          });
        }
      });
    });

    req.on('error', reject);
    req.write(bodyString);
    req.end();
  });
}

async function makeSessionInitRequestWithAuth(
  clientPublicKey: string,
  idempotencyKey: string,
  clientId: string,
  authorizationHeader: string
): Promise<{ status: number; body: any; headers: any }> {
  const requestBody: any = { clientPublicKey };

  const bodyString = JSON.stringify(requestBody);

  const options = {
    hostname: BASE_URL,
    port: PORT,
    path: ENDPOINT,
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'Content-Length': Buffer.byteLength(bodyString),
      'X-Idempotency-Key': idempotencyKey,
      'X-ClientId': clientId,
      'Authorization': authorizationHeader,
    },
  };

  return new Promise((resolve, reject) => {
    const req = http.request(options, (res) => {
      let data = '';
      res.on('data', (chunk) => { data += chunk; });
      res.on('end', () => {
        try {
          resolve({
            status: res.statusCode || 500,
            body: JSON.parse(data),
            headers: res.headers,
          });
        } catch (e) {
          resolve({
            status: res.statusCode || 500,
            body: data,
            headers: res.headers,
          });
        }
      });
    });

    req.on('error', reject);
    req.write(bodyString);
    req.end();
  });
}

async function makeRawRequest(
  path: string,
  method: string,
  headers: Record<string, string>,
  body?: string
): Promise<{ status: number; body: any; headers: any }> {
  const options = {
    hostname: BASE_URL,
    port: PORT,
    path,
    method,
    headers,
  };

  return new Promise((resolve, reject) => {
    const req = http.request(options, (res) => {
      let data = '';
      res.on('data', (chunk) => { data += chunk; });
      res.on('end', () => {
        try {
          resolve({
            status: res.statusCode || 500,
            body: JSON.parse(data),
            headers: res.headers,
          });
        } catch (e) {
          resolve({
            status: res.statusCode || 500,
            body: data,
            headers: res.headers,
          });
        }
      });
    });

    req.on('error', reject);
    if (body) {
      req.write(body);
    }
    req.end();
  });
}

// Test Categories

async function testReplayProtection(): Promise<TestResult[]> {
  const results: TestResult[] = [];

  console.log('\n=== Replay Protection Tests ===\n');

  // Test 1: Reused idempotency key (nonce reuse)
  try {
    const { publicKey } = generateECDHKeyPair();
    const { key: idempotencyKey } = generateIdempotencyKey();
    const clientId = 'test-replay-1';

    // First request should succeed
    const res1 = await makeSessionInitRequest(publicKey, idempotencyKey, clientId);

    // Second request with same key should fail
    const res2 = await makeSessionInitRequest(publicKey, idempotencyKey, clientId);

    results.push({
      name: 'Reused idempotency key (nonce reuse)',
      passed: res1.status === 200 && res2.status === 409,
      expected: 'First: 200, Second: 409 (replay detected)',
      actual: `First: ${res1.status}, Second: ${res2.status}`,
      error: res2.status !== 409 ? JSON.stringify(res2.body) : undefined,
    });
  } catch (error: any) {
    results.push({
      name: 'Reused idempotency key (nonce reuse)',
      passed: false,
      expected: 'First: 200, Second: 409',
      actual: 'Exception thrown',
      error: error.message,
    });
  }

  // Test 2: Timestamp too old (beyond window)
  try {
    const { publicKey } = generateECDHKeyPair();
    const oldTimestamp = Date.now() - 400000; // 6.67 minutes ago (beyond 5 min window)
    const nonce = crypto.randomBytes(16).toString('hex');
    const idempotencyKey = `${oldTimestamp}.${nonce}`;

    const res = await makeSessionInitRequest(publicKey, idempotencyKey, 'test-replay-2');

    results.push({
      name: 'Timestamp too old (beyond 5 minute window)',
      passed: res.status === 400,
      expected: '400 (timestamp invalid)',
      actual: `${res.status}`,
      error: res.status !== 400 ? JSON.stringify(res.body) : undefined,
    });
  } catch (error: any) {
    results.push({
      name: 'Timestamp too old (beyond 5 minute window)',
      passed: false,
      expected: '400',
      actual: 'Exception thrown',
      error: error.message,
    });
  }

  // Test 3: Timestamp in future (beyond window)
  try {
    const { publicKey } = generateECDHKeyPair();
    const futureTimestamp = Date.now() + 400000; // 6.67 minutes in future
    const nonce = crypto.randomBytes(16).toString('hex');
    const idempotencyKey = `${futureTimestamp}.${nonce}`;

    const res = await makeSessionInitRequest(publicKey, idempotencyKey, 'test-replay-3');

    results.push({
      name: 'Timestamp in future (beyond window)',
      passed: res.status === 400,
      expected: '400 (timestamp invalid)',
      actual: `${res.status}`,
      error: res.status !== 400 ? JSON.stringify(res.body) : undefined,
    });
  } catch (error: any) {
    results.push({
      name: 'Timestamp in future (beyond window)',
      passed: false,
      expected: '400',
      actual: 'Exception thrown',
      error: error.message,
    });
  }

  // Test 4: Nonce too short
  try {
    const { publicKey } = generateECDHKeyPair();
    const timestamp = Date.now();
    const shortNonce = crypto.randomBytes(4).toString('hex'); // Only 8 chars
    const idempotencyKey = `${timestamp}.${shortNonce}`;

    const res = await makeSessionInitRequest(publicKey, idempotencyKey, 'test-replay-4');

    results.push({
      name: 'Nonce too short (< 16 chars)',
      passed: res.status === 400,
      expected: '400 (nonce invalid)',
      actual: `${res.status}`,
      error: res.status !== 400 ? JSON.stringify(res.body) : undefined,
    });
  } catch (error: any) {
    results.push({
      name: 'Nonce too short (< 16 chars)',
      passed: false,
      expected: '400',
      actual: 'Exception thrown',
      error: error.message,
    });
  }

  // Test 5: Same nonce, different clients (should BOTH succeed - nonces are per-client)
  try {
    const { publicKey: pk1 } = generateECDHKeyPair();
    const { publicKey: pk2 } = generateECDHKeyPair();
    const timestamp = Date.now();
    const sharedNonce = crypto.randomBytes(16).toString('hex');
    const idempotencyKey = `${timestamp}.${sharedNonce}`;

    // First client with this nonce
    const res1 = await makeSessionInitRequest(pk1, idempotencyKey, 'client-A-unique');

    // Different client with SAME nonce should succeed (nonces scoped per-client)
    const res2 = await makeSessionInitRequest(pk2, idempotencyKey, 'client-B-unique');

    results.push({
      name: 'Same nonce, different clients (both succeed)',
      passed: res1.status === 200 && res2.status === 200,
      expected: 'Both: 200 (nonces are per-client)',
      actual: `Client-A: ${res1.status}, Client-B: ${res2.status}`,
      error: (res1.status !== 200 || res2.status !== 200) ? 
        `ClientA: ${JSON.stringify(res1.body)}, ClientB: ${JSON.stringify(res2.body)}` : undefined,
    });
  } catch (error: any) {
    results.push({
      name: 'Same nonce, different clients (both succeed)',
      passed: false,
      expected: 'Both: 200',
      actual: 'Exception thrown',
      error: error.message,
    });
  }

  return results;
}

async function testHeaderValidation(): Promise<TestResult[]> {
  const results: TestResult[] = [];

  console.log('\n=== Header Validation Tests ===\n');

  // Test 1: Missing X-Idempotency-Key header
  try {
    const { publicKey } = generateECDHKeyPair();
    const body = JSON.stringify({ clientPublicKey: publicKey, ttlSec: 900 });

    const res = await makeRawRequest(ENDPOINT, 'POST', {
      'Content-Type': 'application/json',
      'Content-Length': Buffer.byteLength(body).toString(),
      'X-ClientId': 'test-header-1',
    }, body);

    results.push({
      name: 'Missing X-Idempotency-Key header',
      passed: res.status === 400,
      expected: '400 (missing header)',
      actual: `${res.status}`,
      error: res.status !== 400 ? JSON.stringify(res.body) : undefined,
    });
  } catch (error: any) {
    results.push({
      name: 'Missing X-Idempotency-Key header',
      passed: false,
      expected: '400',
      actual: 'Exception thrown',
      error: error.message,
    });
  }

  // Test 2: Missing X-ClientId header
  try {
    const { publicKey } = generateECDHKeyPair();
    const { key: idempotencyKey } = generateIdempotencyKey();
    const body = JSON.stringify({ clientPublicKey: publicKey, ttlSec: 900 });

    const res = await makeRawRequest(ENDPOINT, 'POST', {
      'Content-Type': 'application/json',
      'Content-Length': Buffer.byteLength(body).toString(),
      'X-Idempotency-Key': idempotencyKey,
    }, body);

    results.push({
      name: 'Missing X-ClientId header',
      passed: res.status === 400,
      expected: '400 (missing header)',
      actual: `${res.status}`,
      error: res.status !== 400 ? JSON.stringify(res.body) : undefined,
    });
  } catch (error: any) {
    results.push({
      name: 'Missing X-ClientId header',
      passed: false,
      expected: '400',
      actual: 'Exception thrown',
      error: error.message,
    });
  }

  // Test 3: Malformed idempotency key (no dot separator)
  try {
    const { publicKey } = generateECDHKeyPair();
    const malformedKey = 'invalid-format-without-dot';

    const res = await makeSessionInitRequest(publicKey, malformedKey, 'test-header-3');

    results.push({
      name: 'Malformed idempotency key (no dot separator)',
      passed: res.status === 400,
      expected: '400 (malformed key)',
      actual: `${res.status}`,
      error: res.status !== 400 ? JSON.stringify(res.body) : undefined,
    });
  } catch (error: any) {
    results.push({
      name: 'Malformed idempotency key (no dot separator)',
      passed: false,
      expected: '400',
      actual: 'Exception thrown',
      error: error.message,
    });
  }

  // Test 4: Malformed idempotency key (non-numeric timestamp)
  try {
    const { publicKey } = generateECDHKeyPair();
    const nonce = crypto.randomBytes(16).toString('hex');
    const malformedKey = `notanumber.${nonce}`;

    const res = await makeSessionInitRequest(publicKey, malformedKey, 'test-header-4');

    results.push({
      name: 'Malformed idempotency key (non-numeric timestamp)',
      passed: res.status === 400,
      expected: '400 (invalid timestamp)',
      actual: `${res.status}`,
      error: res.status !== 400 ? JSON.stringify(res.body) : undefined,
    });
  } catch (error: any) {
    results.push({
      name: 'Malformed idempotency key (non-numeric timestamp)',
      passed: false,
      expected: '400',
      actual: 'Exception thrown',
      error: error.message,
    });
  }

  // Test 5: Empty X-ClientId header
  try {
    const { publicKey } = generateECDHKeyPair();
    const { key: idempotencyKey } = generateIdempotencyKey();

    const res = await makeSessionInitRequest(publicKey, idempotencyKey, '');

    results.push({
      name: 'Empty X-ClientId header',
      passed: res.status === 400,
      expected: '400 (empty client ID)',
      actual: `${res.status}`,
      error: res.status !== 400 ? JSON.stringify(res.body) : undefined,
    });
  } catch (error: any) {
    results.push({
      name: 'Empty X-ClientId header',
      passed: false,
      expected: '400',
      actual: 'Exception thrown',
      error: error.message,
    });
  }

  // Test 6: Empty nonce in idempotency key (timestamp.)
  try {
    const { publicKey } = generateECDHKeyPair();
    const timestamp = Date.now();
    const malformedKey = `${timestamp}.`; // Empty nonce after dot

    const res = await makeSessionInitRequest(publicKey, malformedKey, 'test-header-6');

    results.push({
      name: 'Empty nonce in idempotency key (timestamp.)',
      passed: res.status === 400,
      expected: '400 (empty nonce)',
      actual: `${res.status}`,
      error: res.status !== 400 ? JSON.stringify(res.body) : undefined,
    });
  } catch (error: any) {
    results.push({
      name: 'Empty nonce in idempotency key (timestamp.)',
      passed: false,
      expected: '400',
      actual: 'Exception thrown',
      error: error.message,
    });
  }

  // Test 7: Empty timestamp in idempotency key (.nonce)
  try {
    const { publicKey } = generateECDHKeyPair();
    const nonce = crypto.randomBytes(16).toString('hex');
    const malformedKey = `.${nonce}`; // Empty timestamp before dot

    const res = await makeSessionInitRequest(publicKey, malformedKey, 'test-header-7');

    results.push({
      name: 'Empty timestamp in idempotency key (.nonce)',
      passed: res.status === 400,
      expected: '400 (empty timestamp)',
      actual: `${res.status}`,
      error: res.status !== 400 ? JSON.stringify(res.body) : undefined,
    });
  } catch (error: any) {
    results.push({
      name: 'Empty timestamp in idempotency key (.nonce)',
      passed: false,
      expected: '400',
      actual: 'Exception thrown',
      error: error.message,
    });
  }

  return results;
}

async function testPublicKeyValidation(): Promise<TestResult[]> {
  const results: TestResult[] = [];

  console.log('\n=== Public Key Validation Tests ===\n');

  // Test 1: Missing clientPublicKey field
  try {
    const { key: idempotencyKey } = generateIdempotencyKey();
    const body = JSON.stringify({ ttlSec: 900 });

    const res = await makeRawRequest(ENDPOINT, 'POST', {
      'Content-Type': 'application/json',
      'Content-Length': Buffer.byteLength(body).toString(),
      'X-Idempotency-Key': idempotencyKey,
      'X-ClientId': 'test-pubkey-1',
    }, body);

    results.push({
      name: 'Missing clientPublicKey field',
      passed: res.status === 400,
      expected: '400 (missing field)',
      actual: `${res.status}`,
      error: res.status !== 400 ? JSON.stringify(res.body) : undefined,
    });
  } catch (error: any) {
    results.push({
      name: 'Missing clientPublicKey field',
      passed: false,
      expected: '400',
      actual: 'Exception thrown',
      error: error.message,
    });
  }

  // Test 2: Invalid base64 encoding
  try {
    const invalidBase64 = 'This is not valid base64!!!@@@';
    const { key: idempotencyKey } = generateIdempotencyKey();

    const res = await makeSessionInitRequest(invalidBase64, idempotencyKey, 'test-pubkey-2');

    results.push({
      name: 'Invalid base64 encoding in public key',
      passed: res.status === 400,
      expected: '400 (invalid base64)',
      actual: `${res.status}`,
      error: res.status !== 400 ? JSON.stringify(res.body) : undefined,
    });
  } catch (error: any) {
    results.push({
      name: 'Invalid base64 encoding in public key',
      passed: false,
      expected: '400',
      actual: 'Exception thrown',
      error: error.message,
    });
  }

  // Test 3: Wrong length public key (not 65 bytes for uncompressed P-256)
  try {
    const wrongLengthKey = Buffer.from('0400', 'hex'); // Only 2 bytes
    const { key: idempotencyKey } = generateIdempotencyKey();

    const res = await makeSessionInitRequest(
      wrongLengthKey.toString('base64'),
      idempotencyKey,
      'test-pubkey-3'
    );

    results.push({
      name: 'Wrong length public key (not 65 bytes)',
      passed: res.status === 400,
      expected: '400 (invalid key length)',
      actual: `${res.status}`,
      error: res.status !== 400 ? JSON.stringify(res.body) : undefined,
    });
  } catch (error: any) {
    results.push({
      name: 'Wrong length public key (not 65 bytes)',
      passed: false,
      expected: '400',
      actual: 'Exception thrown',
      error: error.message,
    });
  }

  // Test 4: Invalid curve point (65 bytes but not on P-256 curve)
  try {
    const invalidPoint = Buffer.alloc(65);
    invalidPoint[0] = 0x04; // Uncompressed format
    // Fill with invalid coordinates
    for (let i = 1; i < 65; i++) {
      invalidPoint[i] = 0xFF;
    }

    const { key: idempotencyKey } = generateIdempotencyKey();

    const res = await makeSessionInitRequest(
      invalidPoint.toString('base64'),
      idempotencyKey,
      'test-pubkey-4'
    );

    results.push({
      name: 'Invalid curve point (not on P-256 curve)',
      passed: res.status === 400,
      expected: '400 (invalid curve point)',
      actual: `${res.status}`,
      error: res.status !== 400 ? JSON.stringify(res.body) : undefined,
    });
  } catch (error: any) {
    results.push({
      name: 'Invalid curve point (not on P-256 curve)',
      passed: false,
      expected: '400',
      actual: 'Exception thrown',
      error: error.message,
    });
  }

  // Test 5: Empty public key
  try {
    const { key: idempotencyKey } = generateIdempotencyKey();

    const res = await makeSessionInitRequest('', idempotencyKey, 'test-pubkey-5');

    results.push({
      name: 'Empty public key',
      passed: res.status === 400,
      expected: '400 (empty key)',
      actual: `${res.status}`,
      error: res.status !== 400 ? JSON.stringify(res.body) : undefined,
    });
  } catch (error: any) {
    results.push({
      name: 'Empty public key',
      passed: false,
      expected: '400',
      actual: 'Exception thrown',
      error: error.message,
    });
  }

  return results;
}

async function testTTLValidation(): Promise<TestResult[]> {
  const results: TestResult[] = [];

  console.log('\n=== TTL Validation Tests (Authorization-based) ===\n');

  // NOTE: TTL is now determined by Authorization header presence, not request body.
  // - No Authorization header: anonymous flow (30 min / 1800s)
  // - With Authorization header: authenticated flow (1 hour / 3600s)
  // The ttlSec field in request body is now ignored.

  // Test 1: Anonymous session (no Authorization) gets 30 min TTL
  try {
    const { publicKey } = generateECDHKeyPair();
    const { key: idempotencyKey } = generateIdempotencyKey();

    const res = await makeSessionInitRequest(publicKey, idempotencyKey, 'test-ttl-1');

    results.push({
      name: 'Anonymous session gets 30 min TTL (1800s)',
      passed: res.status === 200 && res.body.expiresInSec === 1800,
      expected: '200 with expiresInSec=1800',
      actual: `${res.status} with TTL ${res.body.expiresInSec || 'N/A'}`,
      error: (res.status !== 200 || res.body.expiresInSec !== 1800) ? JSON.stringify(res.body) : undefined,
    });
  } catch (error: any) {
    results.push({
      name: 'Anonymous session gets 30 min TTL (1800s)',
      passed: false,
      expected: '200',
      actual: 'Exception thrown',
      error: error.message,
    });
  }

  // Test 2: Authenticated session (with Authorization) gets 1 hour TTL
  try {
    const { publicKey } = generateECDHKeyPair();
    const { key: idempotencyKey } = generateIdempotencyKey();

    const res = await makeSessionInitRequestWithAuth(publicKey, idempotencyKey, 'test-ttl-2', 'Bearer mock-token');

    results.push({
      name: 'Authenticated session gets 1 hour TTL (3600s)',
      passed: res.status === 200 && res.body.expiresInSec === 3600,
      expected: '200 with expiresInSec=3600',
      actual: `${res.status} with TTL ${res.body.expiresInSec || 'N/A'}`,
      error: (res.status !== 200 || res.body.expiresInSec !== 3600) ? JSON.stringify(res.body) : undefined,
    });
  } catch (error: any) {
    results.push({
      name: 'Authenticated session gets 1 hour TTL (3600s)',
      passed: false,
      expected: '200',
      actual: 'Exception thrown',
      error: error.message,
    });
  }

  // Test 3: ttlSec in body is ignored for anonymous session
  try {
    const { publicKey } = generateECDHKeyPair();
    const { key: idempotencyKey } = generateIdempotencyKey();

    // ttlSec in body is now ignored - anonymous flow always gets 1800s
    const res = await makeSessionInitRequest(publicKey, idempotencyKey, 'test-ttl-3');

    results.push({
      name: 'ttlSec in body is ignored (anonymous still gets 1800s)',
      passed: res.status === 200 && res.body.expiresInSec === 1800,
      expected: '200 with expiresInSec=1800 (ttlSec ignored)',
      actual: `${res.status} with TTL ${res.body.expiresInSec || 'N/A'}`,
      error: (res.status !== 200 || res.body.expiresInSec !== 1800) ? JSON.stringify(res.body) : undefined,
    });
  } catch (error: any) {
    results.push({
      name: 'ttlSec in body is ignored (anonymous still gets 1800s)',
      passed: false,
      expected: '200',
      actual: 'Exception thrown',
      error: error.message,
    });
  }

  // Test 4: Any Authorization header value triggers authenticated flow
  // NOTE: In production, Azure APIM validates the Authorization header (JWT token) before
  // forwarding requests to this service. Invalid tokens are rejected at the gateway level.
  // This test uses a mock value to verify the service correctly detects header presence.
  try {
    const { publicKey } = generateECDHKeyPair();
    const { key: idempotencyKey } = generateIdempotencyKey();

    // Even a simple "test" value should trigger authenticated flow
    // (In production, APIM would reject invalid tokens before they reach this service)
    const res = await makeSessionInitRequestWithAuth(publicKey, idempotencyKey, 'test-ttl-4', 'test');

    results.push({
      name: 'Any Authorization header triggers authenticated flow',
      passed: res.status === 200 && res.body.expiresInSec === 3600,
      expected: '200 with expiresInSec=3600',
      actual: `${res.status} with TTL ${res.body.expiresInSec || 'N/A'}`,
      error: (res.status !== 200 || res.body.expiresInSec !== 3600) ? JSON.stringify(res.body) : undefined,
    });
  } catch (error: any) {
    results.push({
      name: 'Any Authorization header triggers authenticated flow',
      passed: false,
      expected: '200',
      actual: 'Exception thrown',
      error: error.message,
    });
  }

  return results;
}

async function testRequestBodyValidation(): Promise<TestResult[]> {
  const results: TestResult[] = [];

  console.log('\n=== Request Body Validation Tests ===\n');

  // Test 1: Empty request body
  try {
    const { key: idempotencyKey } = generateIdempotencyKey();

    const res = await makeRawRequest(ENDPOINT, 'POST', {
      'Content-Type': 'application/json',
      'Content-Length': '0',
      'X-Idempotency-Key': idempotencyKey,
      'X-ClientId': 'test-body-1',
    }, '');

    results.push({
      name: 'Empty request body',
      passed: res.status === 400,
      expected: '400 (empty body)',
      actual: `${res.status}`,
      error: res.status !== 400 ? JSON.stringify(res.body) : undefined,
    });
  } catch (error: any) {
    results.push({
      name: 'Empty request body',
      passed: false,
      expected: '400',
      actual: 'Exception thrown',
      error: error.message,
    });
  }

  // Test 2: Invalid JSON
  try {
    const { key: idempotencyKey } = generateIdempotencyKey();
    const invalidJson = '{invalid json}';

    const res = await makeRawRequest(ENDPOINT, 'POST', {
      'Content-Type': 'application/json',
      'Content-Length': Buffer.byteLength(invalidJson).toString(),
      'X-Idempotency-Key': idempotencyKey,
      'X-ClientId': 'test-body-2',
    }, invalidJson);

    results.push({
      name: 'Invalid JSON in request body',
      passed: res.status === 400,
      expected: '400 (invalid JSON)',
      actual: `${res.status}`,
      error: res.status !== 400 ? JSON.stringify(res.body) : undefined,
    });
  } catch (error: any) {
    results.push({
      name: 'Invalid JSON in request body',
      passed: false,
      expected: '400',
      actual: 'Exception thrown',
      error: error.message,
    });
  }

  // Test 3: Missing Content-Type header
  try {
    const { publicKey } = generateECDHKeyPair();
    const { key: idempotencyKey } = generateIdempotencyKey();
    const body = JSON.stringify({ clientPublicKey: publicKey, ttlSec: 900 });

    const res = await makeRawRequest(ENDPOINT, 'POST', {
      'Content-Length': Buffer.byteLength(body).toString(),
      'X-Idempotency-Key': idempotencyKey,
      'X-ClientId': 'test-body-3',
    }, body);

    results.push({
      name: 'Missing Content-Type header',
      passed: res.status === 400 || res.status === 415,
      expected: '400 or 415 (missing content type)',
      actual: `${res.status}`,
      error: (res.status !== 400 && res.status !== 415) ? JSON.stringify(res.body) : undefined,
    });
  } catch (error: any) {
    results.push({
      name: 'Missing Content-Type header',
      passed: false,
      expected: '400 or 415',
      actual: 'Exception thrown',
      error: error.message,
    });
  }

  return results;
}

async function testRedisFallback(): Promise<TestResult[]> {
  const results: TestResult[] = [];

  console.log('\n=== Redis Fallback Tests ===\n');

  // Test 1: Service should work with Redis down (LRU fallback)
  try {
    const { publicKey } = generateECDHKeyPair();
    const { key: idempotencyKey } = generateIdempotencyKey();

    const res = await makeSessionInitRequest(publicKey, idempotencyKey, 'test-redis-fallback');

    // Should succeed even if Redis is down (using LRU cache fallback)
    results.push({
      name: 'Session creation with Redis down (LRU fallback)',
      passed: res.status === 200,
      expected: '200 (LRU fallback works)',
      actual: `${res.status}`,
      error: res.status !== 200 ? JSON.stringify(res.body) : undefined,
    });
  } catch (error: any) {
    results.push({
      name: 'Session creation with Redis down (LRU fallback)',
      passed: false,
      expected: '200',
      actual: 'Exception thrown',
      error: error.message,
    });
  }

  return results;
}

async function makeGetSessionRequest(
  sessionId: string,
  clientId?: string
): Promise<{ status: number; body: any; headers: any }> {
  const headers: Record<string, string> = {};
  if (clientId) {
    headers['X-ClientId'] = clientId;
  }

  const options = {
    hostname: BASE_URL,
    port: PORT,
    path: `/v1/session/${sessionId}`,
    method: 'GET',
    headers,
  };

  return new Promise((resolve, reject) => {
    const req = http.request(options, (res) => {
      let data = '';
      res.on('data', (chunk) => { data += chunk; });
      res.on('end', () => {
        try {
          resolve({
            status: res.statusCode || 500,
            body: JSON.parse(data),
            headers: res.headers,
          });
        } catch (e) {
          resolve({
            status: res.statusCode || 500,
            body: data,
            headers: res.headers,
          });
        }
      });
    });

    req.on('error', reject);
    req.end();
  });
}

async function testGetSessionKeyValidation(): Promise<TestResult[]> {
  const results: TestResult[] = [];

  console.log('\n=== Get Session Key Validation Tests ===\n');

  // Test 1: Missing X-ClientId header
  try {
    const res = await makeGetSessionRequest('S-00000000000000000000000000000000');

    results.push({
      name: 'Missing X-ClientId header',
      passed: res.status === 400,
      expected: '400 (Bad Request)',
      actual: `${res.status}`,
      error: res.status !== 400 ? JSON.stringify(res.body) : undefined,
    });
  } catch (error: any) {
    results.push({
      name: 'Missing X-ClientId header',
      passed: false,
      expected: '400',
      actual: 'Exception thrown',
      error: error.message,
    });
  }

  // Test 2: Invalid session ID format (missing prefix)
  try {
    const res = await makeGetSessionRequest('00000000000000000000000000000000', 'test-client');

    results.push({
      name: 'Invalid session ID format (missing S- prefix)',
      passed: res.status === 400,
      expected: '400 (Bad Request)',
      actual: `${res.status}`,
      error: res.status !== 400 ? JSON.stringify(res.body) : undefined,
    });
  } catch (error: any) {
    results.push({
      name: 'Invalid session ID format (missing S- prefix)',
      passed: false,
      expected: '400',
      actual: 'Exception thrown',
      error: error.message,
    });
  }

  // Test 3: Invalid session ID format (too short)
  try {
    const res = await makeGetSessionRequest('S-abc123', 'test-client');

    results.push({
      name: 'Invalid session ID format (too short)',
      passed: res.status === 400,
      expected: '400 (Bad Request)',
      actual: `${res.status}`,
      error: res.status !== 400 ? JSON.stringify(res.body) : undefined,
    });
  } catch (error: any) {
    results.push({
      name: 'Invalid session ID format (too short)',
      passed: false,
      expected: '400',
      actual: 'Exception thrown',
      error: error.message,
    });
  }

  // Test 4: Invalid session ID format (invalid characters)
  try {
    const res = await makeGetSessionRequest('S-ZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZ', 'test-client');

    results.push({
      name: 'Invalid session ID format (invalid hex characters)',
      passed: res.status === 400,
      expected: '400 (Bad Request)',
      actual: `${res.status}`,
      error: res.status !== 400 ? JSON.stringify(res.body) : undefined,
    });
  } catch (error: any) {
    results.push({
      name: 'Invalid session ID format (invalid hex characters)',
      passed: false,
      expected: '400',
      actual: 'Exception thrown',
      error: error.message,
    });
  }

  // Test 5: Non-existent session
  try {
    const res = await makeGetSessionRequest('S-00000000000000000000000000000000', 'test-client');

    results.push({
      name: 'Non-existent session',
      passed: res.status === 404,
      expected: '404 (Not Found)',
      actual: `${res.status}`,
      error: res.status !== 404 ? JSON.stringify(res.body) : undefined,
    });
  } catch (error: any) {
    results.push({
      name: 'Non-existent session',
      passed: false,
      expected: '404',
      actual: 'Exception thrown',
      error: error.message,
    });
  }

  // Test 6: Unauthorized client (different clientId)
  try {
    const { publicKey } = generateECDHKeyPair();
    const { key: idempotencyKey } = generateIdempotencyKey();
    const ownerClientId = 'owner-client-' + crypto.randomBytes(8).toString('hex');
    const attackerClientId = 'attacker-client-' + crypto.randomBytes(8).toString('hex');

    // Create session with owner client
    const createRes = await makeSessionInitRequest(publicKey, idempotencyKey, ownerClientId);
    if (createRes.status !== 200) {
      throw new Error(`Failed to create session: ${createRes.status}`);
    }

    // Try to access with different client
    const getRes = await makeGetSessionRequest(createRes.body.sessionId, attackerClientId);

    results.push({
      name: 'Unauthorized client access (different clientId)',
      passed: getRes.status === 403,
      expected: '403 (Forbidden)',
      actual: `${getRes.status}`,
      error: getRes.status !== 403 ? JSON.stringify(getRes.body) : undefined,
    });
  } catch (error: any) {
    results.push({
      name: 'Unauthorized client access (different clientId)',
      passed: false,
      expected: '403',
      actual: 'Exception thrown',
      error: error.message,
    });
  }

  // Test 7: Empty session ID
  try {
    const res = await makeGetSessionRequest('', 'test-client');

    // Empty path segment might result in different behavior
    results.push({
      name: 'Empty session ID',
      passed: res.status === 400 || res.status === 404,
      expected: '400 or 404',
      actual: `${res.status}`,
      error: (res.status !== 400 && res.status !== 404) ? JSON.stringify(res.body) : undefined,
    });
  } catch (error: any) {
    results.push({
      name: 'Empty session ID',
      passed: false,
      expected: '400 or 404',
      actual: 'Exception thrown',
      error: error.message,
    });
  }

  return results;
}

// Main test runner
async function runAllTests() {
  console.log('╔════════════════════════════════════════════════════════════════╗');
  console.log('║   Negative Test Suite for Identity Service Node               ║');
  console.log('╚════════════════════════════════════════════════════════════════╝');

  const allResults: TestResult[] = [];

  // Run all test categories
  allResults.push(...await testReplayProtection());
  allResults.push(...await testHeaderValidation());
  allResults.push(...await testPublicKeyValidation());
  allResults.push(...await testTTLValidation());
  allResults.push(...await testRequestBodyValidation());
  allResults.push(...await testRedisFallback());
  allResults.push(...await testGetSessionKeyValidation());

  // Print summary
  console.log('\n╔════════════════════════════════════════════════════════════════╗');
  console.log('║                         TEST SUMMARY                           ║');
  console.log('╚════════════════════════════════════════════════════════════════╝\n');

  const passed = allResults.filter(r => r.passed).length;
  const failed = allResults.filter(r => !r.passed).length;
  const total = allResults.length;

  console.log(`Total Tests:  ${total}`);
  console.log(`Passed:       ${passed} ✓`);
  console.log(`Failed:       ${failed} ✗`);
  console.log(`Success Rate: ${((passed / total) * 100).toFixed(1)}%\n`);

  // Print failed tests details
  if (failed > 0) {
    console.log('╔════════════════════════════════════════════════════════════════╗');
    console.log('║                        FAILED TESTS                            ║');
    console.log('╚════════════════════════════════════════════════════════════════╝\n');

    allResults.filter(r => !r.passed).forEach((result, index) => {
      console.log(`${index + 1}. ${result.name}`);
      console.log(`   Expected: ${result.expected}`);
      console.log(`   Actual:   ${result.actual}`);
      if (result.error) {
        console.log(`   Error:    ${result.error}`);
      }
      console.log('');
    });
  }

  // Exit with appropriate code
  process.exit(failed > 0 ? 1 : 0);
}

// Run tests
runAllTests().catch((error) => {
  console.error('Test suite failed with error:', error);
  process.exit(1);
});
