/**
 * Positive Test Suite for Identity Service Node
 *
 * Test Categories:
 * - Valid session creation (/v1/session/init)
 * - TTL variations
 * - Response validation
 * - Get session key (/v1/session/:sessionId)
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
  authorizationHeader?: string
): Promise<{ status: number; body: any; headers: any }> {
  const requestBody: any = { clientPublicKey };

  const bodyString = JSON.stringify(requestBody);

  const headers: Record<string, string | number> = {
    'Content-Type': 'application/json',
    'Content-Length': Buffer.byteLength(bodyString),
    'X-Idempotency-Key': idempotencyKey,
    'X-ClientId': clientId,
  };

  if (authorizationHeader) {
    headers['Authorization'] = authorizationHeader;
  }

  const options = {
    hostname: BASE_URL,
    port: PORT,
    path: ENDPOINT,
    method: 'POST',
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
    req.write(bodyString);
    req.end();
  });
}

async function makeGetSessionRequest(
  sessionId: string,
  clientId: string
): Promise<{ status: number; body: any; headers: any }> {
  const options = {
    hostname: BASE_URL,
    port: PORT,
    path: `/v1/session/${sessionId}`,
    method: 'GET',
    headers: {
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
    req.end();
  });
}

// Test runner
function printResults(sessionInitResults: TestResult[], getSessionResults: TestResult[]) {
  console.log('\n╔════════════════════════════════════════════════════════════════╗');
  console.log('║   Positive Test Suite for Identity Service Node               ║');
  console.log('╚════════════════════════════════════════════════════════════════╝\n');

  console.log('=== Valid Session Creation Tests ===\n');

  sessionInitResults.forEach((result) => {
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

  console.log('\n=== Get Session Key Tests ===\n');

  getSessionResults.forEach((result) => {
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

  const allResults = [...sessionInitResults, ...getSessionResults];
  const passed = allResults.filter(r => r.passed).length;
  const failed = allResults.filter(r => !r.passed).length;
  const total = allResults.length;
  const successRate = ((passed / total) * 100).toFixed(1);

  console.log(`Total Tests:  ${total}`);
  console.log(`Passed:       ${passed} ✓`);
  console.log(`Failed:       ${failed} ✗`);
  console.log(`Success Rate: ${successRate}%\n`);

  process.exit(failed > 0 ? 1 : 0);
}

// Session Init Tests
async function runSessionInitTests(): Promise<TestResult[]> {
  const results: TestResult[] = [];
  // Test 1: Anonymous session (no Authorization header) - 30 min TTL
  try {
    const { publicKey } = generateECDHKeyPair();
    const { key } = generateIdempotencyKey();
    const response = await makeSessionInitRequest(publicKey, key, 'test-client-1');

    const passed = response.status === 200 &&
                   response.body.sessionId &&
                   response.body.serverPublicKey &&
                   response.body.encAlg === 'aes-256-gcm' &&
                   response.body.expiresInSec === 1800 &&
                   response.headers['x-kid'];

    results.push({
      name: 'Anonymous session (no Authorization) - 30 min TTL',
      passed,
      expected: '200 with expiresInSec=1800 (30 min)',
      actual: `${response.status} with expiresInSec=${response.body.expiresInSec}`,
      error: passed ? undefined : 'Missing required fields or wrong TTL',
    });
  } catch (error) {
    results.push({
      name: 'Anonymous session (no Authorization) - 30 min TTL',
      passed: false,
      expected: '200 OK',
      actual: 'Request failed',
      error: (error as Error).message,
    });
  }

  // Test 2: Authenticated session (with Authorization header) - 1 hour TTL
  try {
    const { publicKey } = generateECDHKeyPair();
    const { key } = generateIdempotencyKey();
    const response = await makeSessionInitRequest(publicKey, key, 'test-client-2', 'Bearer mock-token');

    const passed = response.status === 200 &&
                   response.body.sessionId &&
                   response.body.expiresInSec === 3600;

    results.push({
      name: 'Authenticated session (with Authorization) - 1 hour TTL',
      passed,
      expected: '200 with expiresInSec=3600 (1 hour)',
      actual: `${response.status} with expiresInSec=${response.body.expiresInSec}`,
    });
  } catch (error) {
    results.push({
      name: 'Authenticated session (with Authorization) - 1 hour TTL',
      passed: false,
      expected: '200 OK',
      actual: 'Request failed',
      error: (error as Error).message,
    });
  }

  // Test 3: Anonymous session response contains all required fields
  try {
    const { publicKey } = generateECDHKeyPair();
    const { key } = generateIdempotencyKey();
    const response = await makeSessionInitRequest(publicKey, key, 'test-client-3');

    const passed = response.status === 200 &&
                   response.body.sessionId &&
                   response.body.serverPublicKey &&
                   response.body.encAlg === 'aes-256-gcm' &&
                   response.body.expiresInSec > 0;

    results.push({
      name: 'Anonymous session response contains all required fields',
      passed,
      expected: '200 with sessionId, serverPublicKey, encAlg, expiresInSec',
      actual: `${response.status} with ${JSON.stringify(response.body)}`,
    });
  } catch (error) {
    results.push({
      name: 'Anonymous session response contains all required fields',
      passed: false,
      expected: '200 OK',
      actual: 'Request failed',
      error: (error as Error).message,
    });
  }

  // Test 4: Authenticated session response contains all required fields
  try {
    const { publicKey } = generateECDHKeyPair();
    const { key } = generateIdempotencyKey();
    const response = await makeSessionInitRequest(publicKey, key, 'test-client-4', 'Bearer mock-token');

    const passed = response.status === 200 &&
                   response.body.sessionId &&
                   response.body.serverPublicKey &&
                   response.body.encAlg === 'aes-256-gcm' &&
                   response.body.expiresInSec === 3600;

    results.push({
      name: 'Authenticated session response contains all required fields',
      passed,
      expected: '200 with sessionId, serverPublicKey, encAlg, expiresInSec=3600',
      actual: `${response.status} with expiresInSec=${response.body.expiresInSec}`,
    });
  } catch (error) {
    results.push({
      name: 'Authenticated session response contains all required fields',
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

  return results;
}

// Get Session Key Tests
async function runGetSessionTests(): Promise<TestResult[]> {
  const results: TestResult[] = [];

  // Test 1: Get session key after creating session
  try {
    const { publicKey } = generateECDHKeyPair();
    const { key } = generateIdempotencyKey();
    const clientId = 'test-get-session-1';

    // Create session first
    const createRes = await makeSessionInitRequest(publicKey, key, clientId);
    if (createRes.status !== 200) {
      throw new Error(`Failed to create session: ${createRes.status}`);
    }

    // Get session key
    const getRes = await makeGetSessionRequest(createRes.body.sessionId, clientId);

    const passed = getRes.status === 200 &&
                   getRes.body.sessionId === createRes.body.sessionId &&
                   getRes.body.sessionKey &&
                   getRes.body.expiresAt > Date.now();

    results.push({
      name: 'Get session key after creating session',
      passed,
      expected: '200 with sessionId, sessionKey, expiresAt',
      actual: `${getRes.status} with ${JSON.stringify(getRes.body)}`,
    });
  } catch (error) {
    results.push({
      name: 'Get session key after creating session',
      passed: false,
      expected: '200 OK',
      actual: 'Request failed',
      error: (error as Error).message,
    });
  }

  // Test 2: Verify session key is valid base64
  try {
    const { publicKey } = generateECDHKeyPair();
    const { key } = generateIdempotencyKey();
    const clientId = 'test-get-session-2';

    const createRes = await makeSessionInitRequest(publicKey, key, clientId);
    const getRes = await makeGetSessionRequest(createRes.body.sessionId, clientId);

    let isValidBase64 = false;
    try {
      const keyBuffer = Buffer.from(getRes.body.sessionKey, 'base64');
      isValidBase64 = keyBuffer.length === 32; // AES-256 key
    } catch (e) {
      isValidBase64 = false;
    }

    results.push({
      name: 'Session key is valid base64 (32 bytes for AES-256)',
      passed: getRes.status === 200 && isValidBase64,
      expected: 'Valid base64-encoded 32-byte key',
      actual: isValidBase64 ? 'Valid 32-byte key' : 'Invalid key format',
    });
  } catch (error) {
    results.push({
      name: 'Session key is valid base64 (32 bytes for AES-256)',
      passed: false,
      expected: 'Valid key',
      actual: 'Request failed',
      error: (error as Error).message,
    });
  }

  // Test 3: Verify expiresAt is in the future (anonymous session - 30 min)
  try {
    const { publicKey } = generateECDHKeyPair();
    const { key } = generateIdempotencyKey();
    const clientId = 'test-get-session-3';

    const createRes = await makeSessionInitRequest(publicKey, key, clientId);
    const getRes = await makeGetSessionRequest(createRes.body.sessionId, clientId);

    const now = Date.now();
    const expiresAt = getRes.body.expiresAt;
    const ttlRemaining = Math.floor((expiresAt - now) / 1000);

    // Should have roughly 1800 seconds remaining (allowing some tolerance)
    const passed = getRes.status === 200 &&
                   expiresAt > now &&
                   ttlRemaining > 1790 && ttlRemaining <= 1800;

    results.push({
      name: 'ExpiresAt is in the future (anonymous - 30 min TTL)',
      passed,
      expected: 'expiresAt ~1800 seconds from now',
      actual: `TTL remaining: ${ttlRemaining}s`,
    });
  } catch (error) {
    results.push({
      name: 'ExpiresAt is in the future (anonymous - 30 min TTL)',
      passed: false,
      expected: 'Valid expiresAt',
      actual: 'Request failed',
      error: (error as Error).message,
    });
  }

  // Test 4: Same client can retrieve session multiple times
  try {
    const { publicKey } = generateECDHKeyPair();
    const { key } = generateIdempotencyKey();
    const clientId = 'test-get-session-4';

    const createRes = await makeSessionInitRequest(publicKey, key, clientId);
    const sessionId = createRes.body.sessionId;

    // Get session multiple times
    const getRes1 = await makeGetSessionRequest(sessionId, clientId);
    const getRes2 = await makeGetSessionRequest(sessionId, clientId);

    const passed = getRes1.status === 200 &&
                   getRes2.status === 200 &&
                   getRes1.body.sessionKey === getRes2.body.sessionKey;

    results.push({
      name: 'Same client can retrieve session multiple times',
      passed,
      expected: 'Both requests return 200 with same sessionKey',
      actual: `First: ${getRes1.status}, Second: ${getRes2.status}, Keys match: ${getRes1.body.sessionKey === getRes2.body.sessionKey}`,
    });
  } catch (error) {
    results.push({
      name: 'Same client can retrieve session multiple times',
      passed: false,
      expected: 'Both 200 OK',
      actual: 'Request failed',
      error: (error as Error).message,
    });
  }

  return results;
}

// Main test runner
async function runTests() {
  const sessionInitResults = await runSessionInitTests();
  const getSessionResults = await runGetSessionTests();
  printResults(sessionInitResults, getSessionResults);
}

// Run all tests
runTests().catch((error) => {
  console.error('Test suite failed:', error);
  process.exit(1);
});
