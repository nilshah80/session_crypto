/**
 * Negative Tests for Session Crypto PoC
 *
 * Tests error paths and security controls:
 * - Replay protection (nonce reuse, timestamp validation)
 * - Encryption/decryption failures (tampering, wrong keys)
 * - Session validation (expired, invalid, non-existent)
 * - Header validation (missing, malformed)
 * - Public key validation (invalid format, not on curve)
 */

import crypto from "crypto";
import {
  b64,
  unb64,
  createEcdhKeypair,
  hkdf32,
  aesGcmEncrypt,
  buildAad,
} from "./crypto-helpers.js";

const SERVER_URL = process.env.SERVER_URL || "http://localhost:3000";
const CLIENT_ID = "NEGATIVE_TEST_CLIENT";
const EXPECT_REDIS_DOWN = process.env.EXPECT_REDIS_DOWN === "1";
const EXPECT_CAPACITY_EXCEEDED = process.env.EXPECT_CAPACITY_EXCEEDED === "1";
const RUN_CAPACITY_ONLY = process.env.RUN_CAPACITY_ONLY === "1";
const CAPACITY_TEST_ATTEMPTS = parseInt(process.env.CAPACITY_TEST_ATTEMPTS || "1100", 10);

interface TestResult {
  name: string;
  passed: boolean;
  expected: string;
  actual: string;
  error?: string;
}

interface SessionContext {
  sessionId: string;
  sessionKey: Buffer;
  kid: string;
}

// ============================================
// Test Utilities
// ============================================

function generateIdempotencyKey(): { key: string; timestamp: string; nonce: string } {
  const timestamp = Date.now().toString();
  const nonce = crypto.randomUUID();
  return { key: `${timestamp}.${nonce}`, timestamp, nonce };
}

async function initValidSession(): Promise<SessionContext> {
  const { ecdh, publicKey } = createEcdhKeypair();
  const { key: idempotencyKey } = generateIdempotencyKey();

  const response = await fetch(`${SERVER_URL}/session/init`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "X-Idempotency-Key": idempotencyKey,
      "X-ClientId": CLIENT_ID,
    },
    body: JSON.stringify({ clientPublicKey: b64(publicKey) }),
  });

  if (!response.ok) {
    throw new Error(`Failed to init session: ${response.status}`);
  }

  const data = await response.json();
  const serverPub = unb64(data.serverPublicKey);
  const sharedSecret = ecdh.computeSecret(serverPub);
  const salt = Buffer.from(data.sessionId, "utf8");
  const info = Buffer.from(`SESSION|A256GCM|${CLIENT_ID}`, "utf8");
  const sessionKey = hkdf32(sharedSecret, salt, info);

  return {
    sessionId: data.sessionId,
    sessionKey,
    kid: `session:${data.sessionId}`,
  };
}

async function makePurchaseRequest(
  session: SessionContext,
  options: {
    timestamp?: string;
    nonce?: string;
    kid?: string;
    clientId?: string;
    body?: Buffer;
    omitHeaders?: string[];
  } = {}
): Promise<Response> {
  const timestamp = options.timestamp ?? Date.now().toString();
  const nonce = options.nonce ?? crypto.randomUUID();
  const kid = options.kid ?? session.kid;
  const clientId = options.clientId ?? CLIENT_ID;

  const aad = buildAad(timestamp, nonce, kid, clientId);
  const plaintext = Buffer.from(JSON.stringify({ schemeCode: "TEST", amount: 100 }), "utf8");
  const encryptedBody = options.body ?? aesGcmEncrypt(session.sessionKey, aad, plaintext);

  const headers: Record<string, string> = {
    "Content-Type": "application/octet-stream",
    "X-Kid": kid,
    "X-Idempotency-Key": `${timestamp}.${nonce}`,
    "X-ClientId": clientId,
  };

  // Remove specified headers
  for (const header of options.omitHeaders ?? []) {
    delete headers[header];
  }

  return fetch(`${SERVER_URL}/transaction/purchase`, {
    method: "POST",
    headers,
    body: new Uint8Array(encryptedBody),
  });
}

async function fetchHealth(): Promise<Response> {
  return fetch(`${SERVER_URL}/health`, { method: "GET" });
}

// ============================================
// Test Cases
// ============================================

const tests: Array<() => Promise<TestResult>> = [];

// --------------------------------------------
// 1. Replay Protection Tests
// --------------------------------------------

if (!RUN_CAPACITY_ONLY) {
tests.push(async () => {
  const name = "Replay: Same nonce reused within TTL";
  try {
    const session = await initValidSession();
    const nonce = crypto.randomUUID();
    const timestamp = Date.now().toString();

    // First request should succeed
    const resp1 = await makePurchaseRequest(session, { nonce, timestamp });
    if (!resp1.ok) {
      return { name, passed: false, expected: "First request succeeds", actual: `Status ${resp1.status}` };
    }

    // Second request with same nonce should fail
    const resp2 = await makePurchaseRequest(session, { nonce, timestamp: Date.now().toString() });
    const body = await resp2.json();

    return {
      name,
      passed: resp2.status === 400 && body.error === "CRYPTO_ERROR",
      expected: "400 CRYPTO_ERROR",
      actual: `${resp2.status} ${body.error}`,
    };
  } catch (e) {
    return { name, passed: false, expected: "400 CRYPTO_ERROR", actual: "Exception", error: String(e) };
  }
});

tests.push(async () => {
  const name = "Replay: Timestamp outside window (future)";
  try {
    const session = await initValidSession();
    const futureTimestamp = (Date.now() + 10 * 60 * 1000).toString(); // 10 min in future

    const resp = await makePurchaseRequest(session, { timestamp: futureTimestamp });
    const body = await resp.json();

    return {
      name,
      passed: resp.status === 400 && body.error === "CRYPTO_ERROR",
      expected: "400 CRYPTO_ERROR",
      actual: `${resp.status} ${body.error}`,
    };
  } catch (e) {
    return { name, passed: false, expected: "400 CRYPTO_ERROR", actual: "Exception", error: String(e) };
  }
});

tests.push(async () => {
  const name = "Replay: Timestamp outside window (past)";
  try {
    const session = await initValidSession();
    const pastTimestamp = (Date.now() - 10 * 60 * 1000).toString(); // 10 min in past

    const resp = await makePurchaseRequest(session, { timestamp: pastTimestamp });
    const body = await resp.json();

    return {
      name,
      passed: resp.status === 400 && body.error === "CRYPTO_ERROR",
      expected: "400 CRYPTO_ERROR",
      actual: `${resp.status} ${body.error}`,
    };
  } catch (e) {
    return { name, passed: false, expected: "400 CRYPTO_ERROR", actual: "Exception", error: String(e) };
  }
});

tests.push(async () => {
  const name = "Replay: Invalid timestamp format (NaN)";
  try {
    const session = await initValidSession();

    const resp = await makePurchaseRequest(session, { timestamp: "not-a-number" });
    const body = await resp.json();

    return {
      name,
      passed: resp.status === 400 && body.error === "CRYPTO_ERROR",
      expected: "400 CRYPTO_ERROR",
      actual: `${resp.status} ${body.error}`,
    };
  } catch (e) {
    return { name, passed: false, expected: "400 CRYPTO_ERROR", actual: "Exception", error: String(e) };
  }
});

// --------------------------------------------
// 2. Encryption/Decryption Failure Tests
// --------------------------------------------

tests.push(async () => {
  const name = "Crypto: Tampered ciphertext";
  try {
    const session = await initValidSession();
    const timestamp = Date.now().toString();
    const nonce = crypto.randomUUID();

    const aad = buildAad(timestamp, nonce, session.kid, CLIENT_ID);
    const plaintext = Buffer.from(JSON.stringify({ schemeCode: "TEST", amount: 100 }), "utf8");
    const encrypted = aesGcmEncrypt(session.sessionKey, aad, plaintext);

    // Tamper with ciphertext (byte 15 is in ciphertext region)
    encrypted[15] ^= 0xff;

    const resp = await makePurchaseRequest(session, { timestamp, nonce, body: encrypted });
    const body = await resp.json();

    return {
      name,
      passed: resp.status === 400 && body.error === "CRYPTO_ERROR",
      expected: "400 CRYPTO_ERROR",
      actual: `${resp.status} ${body.error}`,
    };
  } catch (e) {
    return { name, passed: false, expected: "400 CRYPTO_ERROR", actual: "Exception", error: String(e) };
  }
});

tests.push(async () => {
  const name = "Crypto: Tampered auth tag";
  try {
    const session = await initValidSession();
    const timestamp = Date.now().toString();
    const nonce = crypto.randomUUID();

    const aad = buildAad(timestamp, nonce, session.kid, CLIENT_ID);
    const plaintext = Buffer.from(JSON.stringify({ schemeCode: "TEST", amount: 100 }), "utf8");
    const encrypted = aesGcmEncrypt(session.sessionKey, aad, plaintext);

    // Tamper with auth tag (last 16 bytes)
    encrypted[encrypted.length - 1] ^= 0xff;

    const resp = await makePurchaseRequest(session, { timestamp, nonce, body: encrypted });
    const body = await resp.json();

    return {
      name,
      passed: resp.status === 400 && body.error === "CRYPTO_ERROR",
      expected: "400 CRYPTO_ERROR",
      actual: `${resp.status} ${body.error}`,
    };
  } catch (e) {
    return { name, passed: false, expected: "400 CRYPTO_ERROR", actual: "Exception", error: String(e) };
  }
});

tests.push(async () => {
  const name = "Crypto: Tampered AAD (modified clientId header)";
  try {
    const session = await initValidSession();
    const timestamp = Date.now().toString();
    const nonce = crypto.randomUUID();

    // Encrypt with correct AAD
    const aad = buildAad(timestamp, nonce, session.kid, CLIENT_ID);
    const plaintext = Buffer.from(JSON.stringify({ schemeCode: "TEST", amount: 100 }), "utf8");
    const encrypted = aesGcmEncrypt(session.sessionKey, aad, plaintext);

    // Send with different clientId (AAD mismatch)
    const resp = await makePurchaseRequest(session, {
      timestamp,
      nonce,
      clientId: "DIFFERENT_CLIENT",
      body: encrypted,
    });
    const body = await resp.json();

    return {
      name,
      passed: resp.status === 400 && body.error === "CRYPTO_ERROR",
      expected: "400 CRYPTO_ERROR",
      actual: `${resp.status} ${body.error}`,
    };
  } catch (e) {
    return { name, passed: false, expected: "400 CRYPTO_ERROR", actual: "Exception", error: String(e) };
  }
});

tests.push(async () => {
  const name = "Crypto: Wrong session key";
  try {
    const session = await initValidSession();
    const timestamp = Date.now().toString();
    const nonce = crypto.randomUUID();

    // Use a random wrong key
    const wrongKey = crypto.randomBytes(32);
    const aad = buildAad(timestamp, nonce, session.kid, CLIENT_ID);
    const plaintext = Buffer.from(JSON.stringify({ schemeCode: "TEST", amount: 100 }), "utf8");
    const encrypted = aesGcmEncrypt(wrongKey, aad, plaintext);

    const resp = await makePurchaseRequest(session, { timestamp, nonce, body: encrypted });
    const body = await resp.json();

    return {
      name,
      passed: resp.status === 400 && body.error === "CRYPTO_ERROR",
      expected: "400 CRYPTO_ERROR",
      actual: `${resp.status} ${body.error}`,
    };
  } catch (e) {
    return { name, passed: false, expected: "400 CRYPTO_ERROR", actual: "Exception", error: String(e) };
  }
});

tests.push(async () => {
  const name = "Crypto: Truncated body (< 28 bytes)";
  try {
    const session = await initValidSession();

    // Body too short (less than IV + tag)
    const resp = await makePurchaseRequest(session, { body: Buffer.alloc(20) });
    const body = await resp.json();

    return {
      name,
      passed: resp.status === 400 && body.error === "CRYPTO_ERROR",
      expected: "400 CRYPTO_ERROR",
      actual: `${resp.status} ${body.error}`,
    };
  } catch (e) {
    return { name, passed: false, expected: "400 CRYPTO_ERROR", actual: "Exception", error: String(e) };
  }
});

tests.push(async () => {
  const name = "Crypto: Empty body (0 bytes)";
  try {
    const session = await initValidSession();

    const resp = await makePurchaseRequest(session, { body: Buffer.alloc(0) });
    const body = await resp.json();

    return {
      name,
      passed: resp.status === 400 && body.error === "CRYPTO_ERROR",
      expected: "400 CRYPTO_ERROR",
      actual: `${resp.status} ${body.error}`,
    };
  } catch (e) {
    return { name, passed: false, expected: "400 CRYPTO_ERROR", actual: "Exception", error: String(e) };
  }
});

tests.push(async () => {
  const name = "Crypto: Tampered IV";
  try {
    const session = await initValidSession();
    const timestamp = Date.now().toString();
    const nonce = crypto.randomUUID();

    const aad = buildAad(timestamp, nonce, session.kid, CLIENT_ID);
    const plaintext = Buffer.from(JSON.stringify({ schemeCode: "TEST", amount: 100 }), "utf8");
    const encrypted = aesGcmEncrypt(session.sessionKey, aad, plaintext);

    // Tamper with IV (first 12 bytes)
    encrypted[0] ^= 0xff;

    const resp = await makePurchaseRequest(session, { timestamp, nonce, body: encrypted });
    const body = await resp.json();

    return {
      name,
      passed: resp.status === 400 && body.error === "CRYPTO_ERROR",
      expected: "400 CRYPTO_ERROR",
      actual: `${resp.status} ${body.error}`,
    };
  } catch (e) {
    return { name, passed: false, expected: "400 CRYPTO_ERROR", actual: "Exception", error: String(e) };
  }
});

tests.push(async () => {
  const name = "Crypto: Valid decrypt but invalid JSON payload";
  try {
    const session = await initValidSession();
    const timestamp = Date.now().toString();
    const nonce = crypto.randomUUID();

    const aad = buildAad(timestamp, nonce, session.kid, CLIENT_ID);
    const encrypted = aesGcmEncrypt(session.sessionKey, aad, Buffer.from("not-json", "utf8"));

    const resp = await makePurchaseRequest(session, { timestamp, nonce, body: encrypted });
    const body = await resp.json();

    return {
      name,
      passed: resp.status === 400 && body.error === "CRYPTO_ERROR",
      expected: "400 CRYPTO_ERROR",
      actual: `${resp.status} ${body.error}`,
    };
  } catch (e) {
    return { name, passed: false, expected: "400 CRYPTO_ERROR", actual: "Exception", error: String(e) };
  }
});

// --------------------------------------------
// 3. Session Validation Tests
// --------------------------------------------

tests.push(async () => {
  const name = "Session: Non-existent session ID";
  try {
    const session = await initValidSession();

    // Use a valid-format but non-existent session ID
    const fakeSessionId = `S-${"a".repeat(32)}`;
    const resp = await makePurchaseRequest(session, { kid: `session:${fakeSessionId}` });
    const body = await resp.json();

    return {
      name,
      passed: resp.status === 401 && body.error === "SESSION_EXPIRED",
      expected: "401 SESSION_EXPIRED",
      actual: `${resp.status} ${body.error}`,
    };
  } catch (e) {
    return { name, passed: false, expected: "401 SESSION_EXPIRED", actual: "Exception", error: String(e) };
  }
});

tests.push(async () => {
  const name = "Session: Invalid session ID format";
  try {
    const session = await initValidSession();

    // Invalid format (not matching S-[hex]{32})
    const resp = await makePurchaseRequest(session, { kid: "session:invalid-format" });
    const body = await resp.json();

    return {
      name,
      passed: resp.status === 401 && body.error === "SESSION_EXPIRED",
      expected: "401 SESSION_EXPIRED",
      actual: `${resp.status} ${body.error}`,
    };
  } catch (e) {
    return { name, passed: false, expected: "401 SESSION_EXPIRED", actual: "Exception", error: String(e) };
  }
});

tests.push(async () => {
  const name = "Session: Malformed kid (no session: prefix)";
  try {
    const session = await initValidSession();

    const resp = await makePurchaseRequest(session, { kid: session.sessionId }); // Missing "session:" prefix
    const body = await resp.json();

    return {
      name,
      passed: resp.status === 400 && body.error === "CRYPTO_ERROR",
      expected: "400 CRYPTO_ERROR",
      actual: `${resp.status} ${body.error}`,
    };
  } catch (e) {
    return { name, passed: false, expected: "400 CRYPTO_ERROR", actual: "Exception", error: String(e) };
  }
});

// --------------------------------------------
// 4. Header Validation Tests
// --------------------------------------------

tests.push(async () => {
  const name = "Headers: Missing X-Kid";
  try {
    const session = await initValidSession();

    const resp = await makePurchaseRequest(session, { omitHeaders: ["X-Kid"] });
    const body = await resp.json();

    return {
      name,
      passed: resp.status === 400 && body.error === "CRYPTO_ERROR",
      expected: "400 CRYPTO_ERROR",
      actual: `${resp.status} ${body.error}`,
    };
  } catch (e) {
    return { name, passed: false, expected: "400 CRYPTO_ERROR", actual: "Exception", error: String(e) };
  }
});

tests.push(async () => {
  const name = "Headers: Missing X-Idempotency-Key";
  try {
    const session = await initValidSession();

    const resp = await makePurchaseRequest(session, { omitHeaders: ["X-Idempotency-Key"] });
    const body = await resp.json();

    return {
      name,
      passed: resp.status === 400 && body.error === "CRYPTO_ERROR",
      expected: "400 CRYPTO_ERROR",
      actual: `${resp.status} ${body.error}`,
    };
  } catch (e) {
    return { name, passed: false, expected: "400 CRYPTO_ERROR", actual: "Exception", error: String(e) };
  }
});

tests.push(async () => {
  const name = "Headers: Missing X-ClientId";
  try {
    const session = await initValidSession();

    const resp = await makePurchaseRequest(session, { omitHeaders: ["X-ClientId"] });
    const body = await resp.json();

    return {
      name,
      passed: resp.status === 400 && body.error === "CRYPTO_ERROR",
      expected: "400 CRYPTO_ERROR",
      actual: `${resp.status} ${body.error}`,
    };
  } catch (e) {
    return { name, passed: false, expected: "400 CRYPTO_ERROR", actual: "Exception", error: String(e) };
  }
});

tests.push(async () => {
  const name = "Headers: Missing X-ClientId (Session Init)";
  try {
    const { publicKey } = createEcdhKeypair();
    const { key: idempotencyKey } = generateIdempotencyKey();

    const resp = await fetch(`${SERVER_URL}/session/init`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-Idempotency-Key": idempotencyKey,
      },
      body: JSON.stringify({ clientPublicKey: b64(publicKey) }),
    });
    const body = await resp.json();

    return {
      name,
      passed: resp.status === 400 && body.error === "CRYPTO_ERROR",
      expected: "400 CRYPTO_ERROR",
      actual: `${resp.status} ${body.error}`,
    };
  } catch (e) {
    return { name, passed: false, expected: "400 CRYPTO_ERROR", actual: "Exception", error: String(e) };
  }
});

tests.push(async () => {
  const name = "Headers: Missing X-Idempotency-Key (Session Init)";
  try {
    const { publicKey } = createEcdhKeypair();

    const resp = await fetch(`${SERVER_URL}/session/init`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-ClientId": CLIENT_ID,
      },
      body: JSON.stringify({ clientPublicKey: b64(publicKey) }),
    });
    const body = await resp.json();

    return {
      name,
      passed: resp.status === 400 && body.error === "CRYPTO_ERROR",
      expected: "400 CRYPTO_ERROR",
      actual: `${resp.status} ${body.error}`,
    };
  } catch (e) {
    return { name, passed: false, expected: "400 CRYPTO_ERROR", actual: "Exception", error: String(e) };
  }
});

tests.push(async () => {
  const name = "Headers: Malformed idempotency key (no dot)";
  try {
    const session = await initValidSession();
    const timestamp = Date.now().toString();
    const nonce = crypto.randomUUID();

    const aad = buildAad(timestamp, nonce, session.kid, CLIENT_ID);
    const plaintext = Buffer.from(JSON.stringify({ schemeCode: "TEST", amount: 100 }), "utf8");
    const encrypted = aesGcmEncrypt(session.sessionKey, aad, plaintext);

    // Send malformed idempotency key (no dot separator)
    const resp = await fetch(`${SERVER_URL}/transaction/purchase`, {
      method: "POST",
      headers: {
        "Content-Type": "application/octet-stream",
        "X-Kid": session.kid,
        "X-Idempotency-Key": "nodot",
        "X-ClientId": CLIENT_ID,
      },
      body: new Uint8Array(encrypted),
    });
    const body = await resp.json();

    return {
      name,
      passed: resp.status === 400 && body.error === "CRYPTO_ERROR",
      expected: "400 CRYPTO_ERROR",
      actual: `${resp.status} ${body.error}`,
    };
  } catch (e) {
    return { name, passed: false, expected: "400 CRYPTO_ERROR", actual: "Exception", error: String(e) };
  }
});

tests.push(async () => {
  const name = "Headers: Empty nonce in idempotency key (timestamp.)";
  try {
    const session = await initValidSession();
    const timestamp = Date.now().toString();

    const aad = buildAad(timestamp, "", session.kid, CLIENT_ID);
    const plaintext = Buffer.from(JSON.stringify({ schemeCode: "TEST", amount: 100 }), "utf8");
    const encrypted = aesGcmEncrypt(session.sessionKey, aad, plaintext);

    // Send idempotency key with empty nonce
    const resp = await fetch(`${SERVER_URL}/transaction/purchase`, {
      method: "POST",
      headers: {
        "Content-Type": "application/octet-stream",
        "X-Kid": session.kid,
        "X-Idempotency-Key": `${timestamp}.`,
        "X-ClientId": CLIENT_ID,
      },
      body: new Uint8Array(encrypted),
    });
    const body = await resp.json();

    return {
      name,
      passed: resp.status === 400 && body.error === "CRYPTO_ERROR",
      expected: "400 CRYPTO_ERROR",
      actual: `${resp.status} ${body.error}`,
    };
  } catch (e) {
    return { name, passed: false, expected: "400 CRYPTO_ERROR", actual: "Exception", error: String(e) };
  }
});

tests.push(async () => {
  const name = "Headers: Empty timestamp in idempotency key (.nonce)";
  try {
    const session = await initValidSession();
    const nonce = crypto.randomUUID();

    const aad = buildAad("", nonce, session.kid, CLIENT_ID);
    const plaintext = Buffer.from(JSON.stringify({ schemeCode: "TEST", amount: 100 }), "utf8");
    const encrypted = aesGcmEncrypt(session.sessionKey, aad, plaintext);

    // Send idempotency key with empty timestamp
    const resp = await fetch(`${SERVER_URL}/transaction/purchase`, {
      method: "POST",
      headers: {
        "Content-Type": "application/octet-stream",
        "X-Kid": session.kid,
        "X-Idempotency-Key": `.${nonce}`,
        "X-ClientId": CLIENT_ID,
      },
      body: new Uint8Array(encrypted),
    });
    const body = await resp.json();

    return {
      name,
      passed: resp.status === 400 && body.error === "CRYPTO_ERROR",
      expected: "400 CRYPTO_ERROR",
      actual: `${resp.status} ${body.error}`,
    };
  } catch (e) {
    return { name, passed: false, expected: "400 CRYPTO_ERROR", actual: "Exception", error: String(e) };
  }
});

// --------------------------------------------
// 5. Public Key Validation Tests (Session Init)
// --------------------------------------------

tests.push(async () => {
  const name = "PubKey: Invalid key length (too short)";
  try {
    const { key: idempotencyKey } = generateIdempotencyKey();
    const shortKey = crypto.randomBytes(32); // Should be 65 bytes

    const resp = await fetch(`${SERVER_URL}/session/init`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-Idempotency-Key": idempotencyKey,
        "X-ClientId": CLIENT_ID,
      },
      body: JSON.stringify({ clientPublicKey: b64(shortKey) }),
    });
    const body = await resp.json();

    return {
      name,
      passed: resp.status === 400 && body.error === "CRYPTO_ERROR",
      expected: "400 CRYPTO_ERROR",
      actual: `${resp.status} ${body.error}`,
    };
  } catch (e) {
    return { name, passed: false, expected: "400 CRYPTO_ERROR", actual: "Exception", error: String(e) };
  }
});

tests.push(async () => {
  const name = "PubKey: Invalid prefix (not 0x04)";
  try {
    const { key: idempotencyKey } = generateIdempotencyKey();
    const invalidKey = crypto.randomBytes(65);
    invalidKey[0] = 0x02; // Should be 0x04 for uncompressed

    const resp = await fetch(`${SERVER_URL}/session/init`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-Idempotency-Key": idempotencyKey,
        "X-ClientId": CLIENT_ID,
      },
      body: JSON.stringify({ clientPublicKey: b64(invalidKey) }),
    });
    const body = await resp.json();

    return {
      name,
      passed: resp.status === 400 && body.error === "CRYPTO_ERROR",
      expected: "400 CRYPTO_ERROR",
      actual: `${resp.status} ${body.error}`,
    };
  } catch (e) {
    return { name, passed: false, expected: "400 CRYPTO_ERROR", actual: "Exception", error: String(e) };
  }
});

tests.push(async () => {
  const name = "PubKey: Point not on curve";
  try {
    const { key: idempotencyKey } = generateIdempotencyKey();
    // Valid format but random bytes won't be on curve
    const notOnCurve = Buffer.alloc(65);
    notOnCurve[0] = 0x04;
    crypto.randomBytes(64).copy(notOnCurve, 1);

    const resp = await fetch(`${SERVER_URL}/session/init`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-Idempotency-Key": idempotencyKey,
        "X-ClientId": CLIENT_ID,
      },
      body: JSON.stringify({ clientPublicKey: b64(notOnCurve) }),
    });
    const body = await resp.json();

    return {
      name,
      passed: resp.status === 400 && body.error === "CRYPTO_ERROR",
      expected: "400 CRYPTO_ERROR",
      actual: `${resp.status} ${body.error}`,
    };
  } catch (e) {
    return { name, passed: false, expected: "400 CRYPTO_ERROR", actual: "Exception", error: String(e) };
  }
});

tests.push(async () => {
  const name = "PubKey: Invalid base64 input";
  try {
    const { key: idempotencyKey } = generateIdempotencyKey();

    const resp = await fetch(`${SERVER_URL}/session/init`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-Idempotency-Key": idempotencyKey,
        "X-ClientId": CLIENT_ID,
      },
      body: JSON.stringify({ clientPublicKey: "!!!not-base64!!!" }),
    });
    const body = await resp.json();

    return {
      name,
      passed: resp.status === 400 && body.error === "CRYPTO_ERROR",
      expected: "400 CRYPTO_ERROR",
      actual: `${resp.status} ${body.error}`,
    };
  } catch (e) {
    return { name, passed: false, expected: "400 CRYPTO_ERROR", actual: "Exception", error: String(e) };
  }
});

tests.push(async () => {
  const name = "SessionInit: Missing clientPublicKey";
  try {
    const { key: idempotencyKey } = generateIdempotencyKey();

    const resp = await fetch(`${SERVER_URL}/session/init`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-Idempotency-Key": idempotencyKey,
        "X-ClientId": CLIENT_ID,
      },
      body: JSON.stringify({}),
    });
    const body = await resp.json();

    return {
      name,
      passed: resp.status === 400 && body.error === "CRYPTO_ERROR",
      expected: "400 CRYPTO_ERROR",
      actual: `${resp.status} ${body.error}`,
    };
  } catch (e) {
    return { name, passed: false, expected: "400 CRYPTO_ERROR", actual: "Exception", error: String(e) };
  }
});

tests.push(async () => {
  const name = "SessionInit: Malformed idempotency key (no dot)";
  try {
    const { publicKey } = createEcdhKeypair();

    const resp = await fetch(`${SERVER_URL}/session/init`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-Idempotency-Key": "nodot",
        "X-ClientId": CLIENT_ID,
      },
      body: JSON.stringify({ clientPublicKey: b64(publicKey) }),
    });
    const body = await resp.json();

    return {
      name,
      passed: resp.status === 400 && body.error === "CRYPTO_ERROR",
      expected: "400 CRYPTO_ERROR",
      actual: `${resp.status} ${body.error}`,
    };
  } catch (e) {
    return { name, passed: false, expected: "400 CRYPTO_ERROR", actual: "Exception", error: String(e) };
  }
});

tests.push(async () => {
  const name = "SessionInit: Replay idempotency key (same nonce)";
  try {
    const { publicKey } = createEcdhKeypair();
    const { key: idempotencyKey } = generateIdempotencyKey();

    const resp1 = await fetch(`${SERVER_URL}/session/init`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-Idempotency-Key": idempotencyKey,
        "X-ClientId": CLIENT_ID,
      },
      body: JSON.stringify({ clientPublicKey: b64(publicKey) }),
    });

    if (!resp1.ok) {
      return { name, passed: false, expected: "First request succeeds", actual: `Status ${resp1.status}` };
    }

    // Reuse same idempotency key should be rejected
    const resp2 = await fetch(`${SERVER_URL}/session/init`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-Idempotency-Key": idempotencyKey,
        "X-ClientId": CLIENT_ID,
      },
      body: JSON.stringify({ clientPublicKey: b64(publicKey) }),
    });
    const body = await resp2.json();

    return {
      name,
      passed: resp2.status === 400 && body.error === "CRYPTO_ERROR",
      expected: "400 CRYPTO_ERROR",
      actual: `${resp2.status} ${body.error}`,
    };
  } catch (e) {
    return { name, passed: false, expected: "400 CRYPTO_ERROR", actual: "Exception", error: String(e) };
  }
});

tests.push(async () => {
  const name = "SessionInit: Invalid TTL (negative)";
  try {
    const { publicKey } = createEcdhKeypair();
    const { key: idempotencyKey } = generateIdempotencyKey();

    const resp = await fetch(`${SERVER_URL}/session/init`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-Idempotency-Key": idempotencyKey,
        "X-ClientId": CLIENT_ID,
      },
      body: JSON.stringify({ clientPublicKey: b64(publicKey), ttlSec: -100 }),
    });
    const body = await resp.json();

    return {
      name,
      passed: resp.status === 400 && body.error === "CRYPTO_ERROR",
      expected: "400 CRYPTO_ERROR",
      actual: `${resp.status} ${body.error}`,
    };
  } catch (e) {
    return { name, passed: false, expected: "400 CRYPTO_ERROR", actual: "Exception", error: String(e) };
  }
});

tests.push(async () => {
  const name = "SessionInit: Invalid TTL (float)";
  try {
    const { publicKey } = createEcdhKeypair();
    const { key: idempotencyKey } = generateIdempotencyKey();

    const resp = await fetch(`${SERVER_URL}/session/init`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-Idempotency-Key": idempotencyKey,
        "X-ClientId": CLIENT_ID,
      },
      body: JSON.stringify({ clientPublicKey: b64(publicKey), ttlSec: 1.5 }),
    });
    const body = await resp.json();

    return {
      name,
      passed: resp.status === 400 && body.error === "CRYPTO_ERROR",
      expected: "400 CRYPTO_ERROR",
      actual: `${resp.status} ${body.error}`,
    };
  } catch (e) {
    return { name, passed: false, expected: "400 CRYPTO_ERROR", actual: "Exception", error: String(e) };
  }
});

tests.push(async () => {
  const name = "SessionInit: TTL above max is capped (not rejected)";
  try {
    const { publicKey } = createEcdhKeypair();
    const { key: idempotencyKey } = generateIdempotencyKey();

    // Request TTL of 1 week (way above max of 1 hour)
    const resp = await fetch(`${SERVER_URL}/session/init`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-Idempotency-Key": idempotencyKey,
        "X-ClientId": CLIENT_ID,
      },
      body: JSON.stringify({ clientPublicKey: b64(publicKey), ttlSec: 604800 }),
    });
    const body = await resp.json();

    // Should succeed but TTL capped to max (3600 by default)
    const ttlCapped = resp.ok && body.expiresInSec <= 3600;

    return {
      name,
      passed: ttlCapped,
      expected: "200 with expiresInSec <= 3600",
      actual: `${resp.status} expiresInSec=${body.expiresInSec}`,
    };
  } catch (e) {
    return { name, passed: false, expected: "200 with capped TTL", actual: "Exception", error: String(e) };
  }
});

tests.push(async () => {
  const name = "SessionInit: TTL below min is raised (not rejected)";
  try {
    const { publicKey } = createEcdhKeypair();
    const { key: idempotencyKey } = generateIdempotencyKey();

    // Request TTL of 1 second (below min of 300)
    const resp = await fetch(`${SERVER_URL}/session/init`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-Idempotency-Key": idempotencyKey,
        "X-ClientId": CLIENT_ID,
      },
      body: JSON.stringify({ clientPublicKey: b64(publicKey), ttlSec: 1 }),
    });
    const body = await resp.json();

    // Should succeed but TTL raised to min (300 by default)
    const ttlRaised = resp.ok && body.expiresInSec >= 300;

    return {
      name,
      passed: ttlRaised,
      expected: "200 with expiresInSec >= 300",
      actual: `${resp.status} expiresInSec=${body.expiresInSec}`,
    };
  } catch (e) {
    return { name, passed: false, expected: "200 with raised TTL", actual: "Exception", error: String(e) };
  }
});

// --------------------------------------------
// 6. Redis Down Fallback (optional)
// --------------------------------------------

tests.push(async () => {
  const name = "Health: Redis disconnected when EXPECT_REDIS_DOWN=1";
  if (!EXPECT_REDIS_DOWN) {
    return { name, passed: true, expected: "SKIPPED", actual: "SKIPPED" };
  }

  try {
    const resp = await fetchHealth();
    const body = await resp.json();

    return {
      name,
      passed: resp.status === 200 && body.redis === "disconnected",
      expected: "200 redis=disconnected",
      actual: `${resp.status} redis=${body.redis}`,
    };
  } catch (e) {
    return { name, passed: false, expected: "200 redis=disconnected", actual: "Exception", error: String(e) };
  }
});
}

// --------------------------------------------
// 7. Memory Nonce Capacity (optional)
// --------------------------------------------

tests.push(async () => {
  const name = "Replay: Memory nonce capacity exceeded when EXPECT_CAPACITY_EXCEEDED=1";
  if (!EXPECT_CAPACITY_EXCEEDED) {
    return { name, passed: true, expected: "SKIPPED", actual: "SKIPPED" };
  }

  try {
    const session = await initValidSession();
    let okCount = 0;
    let failCount = 0;

    // Run enough requests to exceed memory nonce capacity
    for (let i = 0; i < CAPACITY_TEST_ATTEMPTS; i++) {
      const resp = await makePurchaseRequest(session);
      if (resp.ok) {
        okCount++;
        continue;
      }

      let body: { error?: string } = {};
      try {
        body = await resp.json();
      } catch {
        body = {};
      }

      if (resp.status === 400 && body.error === "CRYPTO_ERROR") {
        failCount++;
        break;
      }

      return {
        name,
        passed: false,
        expected: "400 CRYPTO_ERROR after capacity exceeded",
        actual: `${resp.status} ${body.error ?? ""}`.trim(),
      };
    }

    return {
      name,
      passed: failCount >= 1,
      expected: "400 CRYPTO_ERROR after capacity exceeded",
      actual: `ok=${okCount} failed=${failCount}`,
    };
  } catch (e) {
    return { name, passed: false, expected: "400 CRYPTO_ERROR", actual: "Exception", error: String(e) };
  }
});

// ============================================
// Test Runner
// ============================================

async function runTests(): Promise<void> {
  console.log("=".repeat(60));
  console.log("Session Crypto - Negative Tests");
  console.log("=".repeat(60));
  console.log();

  let passed = 0;
  let failed = 0;

  for (const test of tests) {
    const result = await test();

    if (result.passed) {
      console.log(`✅ ${result.name}`);
      passed++;
    } else {
      console.log(`❌ ${result.name}`);
      console.log(`   Expected: ${result.expected}`);
      console.log(`   Actual:   ${result.actual}`);
      if (result.error) {
        console.log(`   Error:    ${result.error}`);
      }
      failed++;
    }
  }

  console.log();
  console.log("=".repeat(60));
  console.log(`Results: ${passed} passed, ${failed} failed, ${tests.length} total`);
  console.log("=".repeat(60));

  if (failed > 0) {
    process.exit(1);
  }
}

// Run if executed directly
runTests().catch((err) => {
  console.error("Test runner failed:", err);
  process.exit(1);
});
