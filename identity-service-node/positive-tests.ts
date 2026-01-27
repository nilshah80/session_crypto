/**
 * Positive Test Suite for /v1/session/init endpoint
 *
 * Test Categories:
 * - Valid session creation
 * - TTL variations
 * - Response validation
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

// Test runner
const results: TestResult[] = [];

function printResults() {
  console.log('\n╔════════════════════════════════════════════════════════════════╗');
  console.log('║   Positive Test Suite for /v1/session/init Endpoint           ║');
  console.log('╚════════════════════════════════════════════════════════════════╝\n');

  console.log('=== Valid Session Creation Tests ===\n');

  results.forEach((result) => {
    const status = result.passed ? '✓' : '✗';
    const color = result.passed ? '\x1b[32m' : '\x1b[31m';
    const reset = '\x1b[0m';
    console.log(`${color}${status}${reset} ${result.name}`);
    if (!result.passed) {
      console.log(`  Expected: ${result.expected}`);
      console.log(`  Actual: ${result.actual}`);
      if (result.error) {
        console.log(`  Error: ${result.error}`);
      }
    }
  });

  console.log('\n╔════════════════════════════════════════════════════════════════╗');
  console.log('║                         TEST SUMMARY                           ║');
  console.log('╚════════════════════════════════════════════════════════════════╝\n');

  const passed = results.filter(r => r.passed).length;
  const failed = results.filter(r => !r.passed).length;
  const total = results.length;
  const successRate = ((passed / total) * 100).toFixed(1);

  console.log(`Total Tests:  ${total}`);
  console.log(`Passed:       ${passed} ✓`);
  console.log(`Failed:       ${failed} ✗`);
  console.log(`Success Rate: ${successRate}%\n`);

  process.exit(failed > 0 ? 1 : 0);
}

// Tests
async function runTests() {
  // Test 1: Valid session creation with default TTL
  try {
    const { publicKey } = generateECDHKeyPair();
    const { key } = generateIdempotencyKey();
    const response = await makeSessionInitRequest(publicKey, key, 'test-client-1');

    const passed = response.status === 200 &&
                   response.body.sessionId &&
                   response.body.serverPublicKey &&
                   response.body.encAlg === 'aes-256-gcm' &&
                   response.body.expiresInSec > 0 &&
                   response.headers['x-kid'];

    results.push({
      name: 'Valid session with default TTL',
      passed,
      expected: '200 with sessionId, serverPublicKey, encAlg, expiresInSec, X-Kid header',
      actual: `${response.status} with ${JSON.stringify(response.body)}`,
      error: passed ? undefined : 'Missing required fields in response',
    });
  } catch (error) {
    results.push({
      name: 'Valid session with default TTL',
      passed: false,
      expected: '200 OK',
      actual: 'Request failed',
      error: (error as Error).message,
    });
  }

  // Test 2: Valid session with minimum TTL
  try {
    const { publicKey } = generateECDHKeyPair();
    const { key } = generateIdempotencyKey();
    const response = await makeSessionInitRequest(publicKey, key, 'test-client-2', 300);

    const passed = response.status === 200 &&
                   response.body.sessionId &&
                   response.body.expiresInSec === 300;

    results.push({
      name: 'Valid session with minimum TTL (300s)',
      passed,
      expected: '200 with expiresInSec=300',
      actual: `${response.status} with expiresInSec=${response.body.expiresInSec}`,
    });
  } catch (error) {
    results.push({
      name: 'Valid session with minimum TTL (300s)',
      passed: false,
      expected: '200 OK',
      actual: 'Request failed',
      error: (error as Error).message,
    });
  }

  // Test 3: Valid session with maximum TTL
  try {
    const { publicKey } = generateECDHKeyPair();
    const { key } = generateIdempotencyKey();
    const response = await makeSessionInitRequest(publicKey, key, 'test-client-3', 3600);

    const passed = response.status === 200 &&
                   response.body.sessionId &&
                   response.body.expiresInSec === 3600;

    results.push({
      name: 'Valid session with maximum TTL (3600s)',
      passed,
      expected: '200 with expiresInSec=3600',
      actual: `${response.status} with expiresInSec=${response.body.expiresInSec}`,
    });
  } catch (error) {
    results.push({
      name: 'Valid session with maximum TTL (3600s)',
      passed: false,
      expected: '200 OK',
      actual: 'Request failed',
      error: (error as Error).message,
    });
  }

  // Test 4: Valid session with custom TTL
  try {
    const { publicKey } = generateECDHKeyPair();
    const { key } = generateIdempotencyKey();
    const response = await makeSessionInitRequest(publicKey, key, 'test-client-4', 1800);

    const passed = response.status === 200 &&
                   response.body.sessionId &&
                   response.body.expiresInSec === 1800;

    results.push({
      name: 'Valid session with custom TTL (1800s)',
      passed,
      expected: '200 with expiresInSec=1800',
      actual: `${response.status} with expiresInSec=${response.body.expiresInSec}`,
    });
  } catch (error) {
    results.push({
      name: 'Valid session with custom TTL (1800s)',
      passed: false,
      expected: '200 OK',
      actual: 'Request failed',
      error: (error as Error).message,
    });
  }

  // Test 5: Verify session ID format
  try {
    const { publicKey } = generateECDHKeyPair();
    const { key } = generateIdempotencyKey();
    const response = await makeSessionInitRequest(publicKey, key, 'test-client-5');

    const sessionIdPattern = /^S-[0-9a-f]{32}$/;
    const passed = response.status === 200 &&
                   sessionIdPattern.test(response.body.sessionId);

    results.push({
      name: 'Session ID format validation (S-{32-hex})',
      passed,
      expected: 'Session ID matching S-[0-9a-f]{32}',
      actual: `${response.body.sessionId}`,
    });
  } catch (error) {
    results.push({
      name: 'Session ID format validation (S-{32-hex})',
      passed: false,
      expected: 'Valid session ID format',
      actual: 'Request failed',
      error: (error as Error).message,
    });
  }

  // Test 6: Verify server public key format
  try {
    const { publicKey } = generateECDHKeyPair();
    const { key } = generateIdempotencyKey();
    const response = await makeSessionInitRequest(publicKey, key, 'test-client-6');

    let isValidKey = false;
    try {
      const keyBuffer = Buffer.from(response.body.serverPublicKey, 'base64');
      isValidKey = keyBuffer.length === 65; // Uncompressed P-256 key
    } catch (e) {
      isValidKey = false;
    }

    const passed = response.status === 200 && isValidKey;

    results.push({
      name: 'Server public key format validation',
      passed,
      expected: 'Valid base64-encoded P-256 public key (65 bytes)',
      actual: passed ? 'Valid key format' : 'Invalid key format',
    });
  } catch (error) {
    results.push({
      name: 'Server public key format validation',
      passed: false,
      expected: 'Valid public key',
      actual: 'Request failed',
      error: (error as Error).message,
    });
  }

  // Test 7: Verify X-Kid header matches session ID
  try {
    const { publicKey } = generateECDHKeyPair();
    const { key } = generateIdempotencyKey();
    const response = await makeSessionInitRequest(publicKey, key, 'test-client-7');

    const passed = response.status === 200 &&
                   response.headers['x-kid'] === response.body.sessionId;

    results.push({
      name: 'X-Kid header matches session ID',
      passed,
      expected: 'X-Kid header equals sessionId',
      actual: `X-Kid=${response.headers['x-kid']}, sessionId=${response.body.sessionId}`,
    });
  } catch (error) {
    results.push({
      name: 'X-Kid header matches session ID',
      passed: false,
      expected: 'Matching X-Kid and sessionId',
      actual: 'Request failed',
      error: (error as Error).message,
    });
  }

  // Test 8: Multiple sessions with different clients
  try {
    const { publicKey: pk1 } = generateECDHKeyPair();
    const { key: key1 } = generateIdempotencyKey();
    const response1 = await makeSessionInitRequest(pk1, key1, 'test-client-8a');

    await new Promise(resolve => setTimeout(resolve, 10)); // Small delay

    const { publicKey: pk2 } = generateECDHKeyPair();
    const { key: key2 } = generateIdempotencyKey();
    const response2 = await makeSessionInitRequest(pk2, key2, 'test-client-8b');

    const passed = response1.status === 200 &&
                   response2.status === 200 &&
                   response1.body.sessionId !== response2.body.sessionId;

    results.push({
      name: 'Multiple concurrent sessions with different clients',
      passed,
      expected: 'Both sessions created with unique session IDs',
      actual: `Session1=${response1.body.sessionId}, Session2=${response2.body.sessionId}`,
    });
  } catch (error) {
    results.push({
      name: 'Multiple concurrent sessions with different clients',
      passed: false,
      expected: 'Unique session IDs',
      actual: 'Request failed',
      error: (error as Error).message,
    });
  }

  printResults();
}

// Run all tests
runTests().catch((error) => {
  console.error('Test suite failed:', error);
  process.exit(1);
});
