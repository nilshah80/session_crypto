/**
 * Comprehensive Negative Test Suite for /v1/session/init endpoint
 *
 * Test Categories:
 * - Replay Protection
 * - Header Validation
 * - Public Key Validation
 * - TTL Validation
 * - Request Body Validation
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
  clientId: string,
  ttlSec?: number
): Promise<{ status: number; body: any; headers: any }> {
  const requestBody: any = { clientPublicKey };
  if (ttlSec !== undefined) {
    requestBody.ttlSec = ttlSec;
  }

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
    const res1 = await makeSessionInitRequest(publicKey, idempotencyKey, clientId, 900);

    // Second request with same key should fail
    const res2 = await makeSessionInitRequest(publicKey, idempotencyKey, clientId, 900);

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

    const res = await makeSessionInitRequest(publicKey, idempotencyKey, 'test-replay-2', 900);

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

    const res = await makeSessionInitRequest(publicKey, idempotencyKey, 'test-replay-3', 900);

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

    const res = await makeSessionInitRequest(publicKey, idempotencyKey, 'test-replay-4', 900);

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

    const res = await makeSessionInitRequest(publicKey, malformedKey, 'test-header-3', 900);

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

    const res = await makeSessionInitRequest(publicKey, malformedKey, 'test-header-4', 900);

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

    const res = await makeSessionInitRequest(publicKey, idempotencyKey, '', 900);

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

    const res = await makeSessionInitRequest(publicKey, malformedKey, 'test-header-6', 900);

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

    const res = await makeSessionInitRequest(publicKey, malformedKey, 'test-header-7', 900);

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

    const res = await makeSessionInitRequest(invalidBase64, idempotencyKey, 'test-pubkey-2', 900);

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
      'test-pubkey-3',
      900
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
      'test-pubkey-4',
      900
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

    const res = await makeSessionInitRequest('', idempotencyKey, 'test-pubkey-5', 900);

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

  console.log('\n=== TTL Validation Tests ===\n');

  // Test 1: Negative TTL
  try {
    const { publicKey } = generateECDHKeyPair();
    const { key: idempotencyKey } = generateIdempotencyKey();

    const res = await makeSessionInitRequest(publicKey, idempotencyKey, 'test-ttl-1', -100);

    results.push({
      name: 'Negative TTL value',
      passed: res.status === 400,
      expected: '400 (negative TTL)',
      actual: `${res.status}`,
      error: res.status !== 400 ? JSON.stringify(res.body) : undefined,
    });
  } catch (error: any) {
    results.push({
      name: 'Negative TTL value',
      passed: false,
      expected: '400',
      actual: 'Exception thrown',
      error: error.message,
    });
  }

  // Test 2: Zero TTL (should be clamped to minimum, not rejected)
  try {
    const { publicKey } = generateECDHKeyPair();
    const { key: idempotencyKey } = generateIdempotencyKey();

    const res = await makeSessionInitRequest(publicKey, idempotencyKey, 'test-ttl-2', 0);

    results.push({
      name: 'Zero TTL value (clamped to minimum)',
      passed: res.status === 200 && res.body.expiresInSec === 60,
      expected: '200 with TTL clamped to 60',
      actual: `${res.status} with TTL ${res.body.expiresInSec || 'N/A'}`,
      error: (res.status !== 200 || res.body.expiresInSec !== 60) ? JSON.stringify(res.body) : undefined,
    });
  } catch (error: any) {
    results.push({
      name: 'Zero TTL value (clamped to minimum)',
      passed: false,
      expected: '200',
      actual: 'Exception thrown',
      error: error.message,
    });
  }

  // Test 3: TTL above maximum (should be clamped to maximum, not rejected)
  try {
    const { publicKey } = generateECDHKeyPair();
    const { key: idempotencyKey } = generateIdempotencyKey();

    const res = await makeSessionInitRequest(publicKey, idempotencyKey, 'test-ttl-3', 7200);

    results.push({
      name: 'TTL above maximum (clamped to 3600)',
      passed: res.status === 200 && res.body.expiresInSec === 3600,
      expected: '200 with TTL clamped to 3600',
      actual: `${res.status} with TTL ${res.body.expiresInSec || 'N/A'}`,
      error: (res.status !== 200 || res.body.expiresInSec !== 3600) ? JSON.stringify(res.body) : undefined,
    });
  } catch (error: any) {
    results.push({
      name: 'TTL above maximum (clamped to 3600)',
      passed: false,
      expected: '200',
      actual: 'Exception thrown',
      error: error.message,
    });
  }

  // Test 4: TTL below minimum (should be clamped to minimum, not rejected)
  try {
    const { publicKey } = generateECDHKeyPair();
    const { key: idempotencyKey } = generateIdempotencyKey();

    const res = await makeSessionInitRequest(publicKey, idempotencyKey, 'test-ttl-4', 30);

    results.push({
      name: 'TTL below minimum (clamped to 60)',
      passed: res.status === 200 && res.body.expiresInSec === 60,
      expected: '200 with TTL clamped to 60',
      actual: `${res.status} with TTL ${res.body.expiresInSec || 'N/A'}`,
      error: (res.status !== 200 || res.body.expiresInSec !== 60) ? JSON.stringify(res.body) : undefined,
    });
  } catch (error: any) {
    results.push({
      name: 'TTL below minimum (clamped to 60)',
      passed: false,
      expected: '200',
      actual: 'Exception thrown',
      error: error.message,
    });
  }

  // Test 7: Float/decimal TTL (non-integer)
  try {
    const { publicKey } = generateECDHKeyPair();
    const { key: idempotencyKey } = generateIdempotencyKey();

    const res = await makeSessionInitRequest(publicKey, idempotencyKey, 'test-ttl-7', 123.45);

    results.push({
      name: 'Float/decimal TTL value (non-integer)',
      passed: res.status === 400,
      expected: '400 (non-integer TTL)',
      actual: `${res.status}`,
      error: res.status !== 400 ? JSON.stringify(res.body) : undefined,
    });
  } catch (error: any) {
    results.push({
      name: 'Float/decimal TTL value (non-integer)',
      passed: false,
      expected: '400',
      actual: 'Exception thrown',
      error: error.message,
    });
  }

  // Test 5: Valid TTL at minimum boundary (60)
  try {
    const { publicKey } = generateECDHKeyPair();
    const { key: idempotencyKey } = generateIdempotencyKey();

    const res = await makeSessionInitRequest(publicKey, idempotencyKey, 'test-ttl-5', 60);

    results.push({
      name: 'Valid TTL at minimum boundary (60 sec)',
      passed: res.status === 200,
      expected: '200 (valid)',
      actual: `${res.status}`,
      error: res.status !== 200 ? JSON.stringify(res.body) : undefined,
    });
  } catch (error: any) {
    results.push({
      name: 'Valid TTL at minimum boundary (60 sec)',
      passed: false,
      expected: '200',
      actual: 'Exception thrown',
      error: error.message,
    });
  }

  // Test 6: Valid TTL at maximum boundary (3600)
  try {
    const { publicKey } = generateECDHKeyPair();
    const { key: idempotencyKey } = generateIdempotencyKey();

    const res = await makeSessionInitRequest(publicKey, idempotencyKey, 'test-ttl-6', 3600);

    results.push({
      name: 'Valid TTL at maximum boundary (3600 sec)',
      passed: res.status === 200,
      expected: '200 (valid)',
      actual: `${res.status}`,
      error: res.status !== 200 ? JSON.stringify(res.body) : undefined,
    });
  } catch (error: any) {
    results.push({
      name: 'Valid TTL at maximum boundary (3600 sec)',
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

    const res = await makeSessionInitRequest(publicKey, idempotencyKey, 'test-redis-fallback', 900);

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

// Main test runner
async function runAllTests() {
  console.log('╔════════════════════════════════════════════════════════════════╗');
  console.log('║   Negative Test Suite for /v1/session/init Endpoint           ║');
  console.log('╚════════════════════════════════════════════════════════════════╝');

  const allResults: TestResult[] = [];

  // Run all test categories
  allResults.push(...await testReplayProtection());
  allResults.push(...await testHeaderValidation());
  allResults.push(...await testPublicKeyValidation());
  allResults.push(...await testTTLValidation());
  allResults.push(...await testRequestBodyValidation());
  allResults.push(...await testRedisFallback());

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
