import crypto from "crypto";
import {
  b64,
  unb64,
  createEcdhKeypair,
  hkdf32,
  aesGcmEncrypt,
  buildAad,
} from "./crypto-helpers.js";

const SERVER_URL = "http://localhost:3000";
const CLIENT_ID = "NODE_CLIENT";

interface SessionContext {
  sessionId: string;
  sessionKey: Buffer;
  kid: string;
  clientId: string;
}

interface SessionInitResponse {
  sessionId: string;
  serverPublicKey: string;
  encAlg: string;
  expiresInSec: number;
}

// Helper to initialize a valid session
async function initSession(): Promise<SessionContext> {
  const { ecdh: clientECDH, publicKey: clientPub } = createEcdhKeypair();

  const nonce = crypto.randomUUID();
  const timestamp = Date.now().toString();
  const requestId = `${timestamp}.${nonce}`;

  const response = await fetch(`${SERVER_URL}/session/init`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "X-Request-Id": requestId,
      "X-ClientId": CLIENT_ID,
    },
    body: JSON.stringify({
      clientPublicKey: b64(clientPub),
      ttlSec: 1800,
    }),
  });

  if (!response.ok) {
    throw new Error(`Session init failed: ${response.status}`);
  }

  const data: SessionInitResponse = await response.json();
  const serverPub = unb64(data.serverPublicKey);
  const sharedSecret = clientECDH.computeSecret(serverPub);

  const salt = Buffer.from(data.sessionId, "utf8");
  const info = Buffer.from(`SESSION|A256GCM|${CLIENT_ID}`, "utf8");
  const sessionKey = hkdf32(sharedSecret, salt, info);

  return {
    sessionId: data.sessionId,
    sessionKey,
    kid: `session:${data.sessionId}`,
    clientId: CLIENT_ID,
  };
}

// Helper to make a purchase request
async function makePurchaseRequest(
  session: SessionContext,
  options: {
    customKid?: string;
    customRequestId?: string;
    customClientId?: string;
    customBody?: Buffer;
    tamperAAD?: boolean;
  } = {}
): Promise<{ status: number; body: string }> {
  const nonce = crypto.randomUUID();
  const timestamp = Date.now().toString();
  const requestId = options.customRequestId ?? `${timestamp}.${nonce}`;
  const kid = options.customKid ?? session.kid;
  const clientId = options.customClientId ?? session.clientId;

  // Build AAD (optionally tampered)
  const aadTimestamp = options.tamperAAD ? "9999999999999" : timestamp;
  const aad = buildAad(
    aadTimestamp,
    nonce,
    kid,
    clientId
  );

  // Encrypt body
  const plaintext = Buffer.from(JSON.stringify({ schemeCode: "AEF", amount: 1000 }), "utf8");
  const encryptedBody = options.customBody ?? aesGcmEncrypt(session.sessionKey, aad, plaintext);

  const response = await fetch(`${SERVER_URL}/transaction/purchase`, {
    method: "POST",
    headers: {
      "Content-Type": "application/octet-stream",
      "X-Kid": kid,
      "X-Request-Id": requestId,
      "X-ClientId": clientId,
    },
    body: new Uint8Array(encryptedBody),
  });

  const body = await response.text();
  return { status: response.status, body };
}

// Test functions
async function testReplayProtection(): Promise<boolean> {
  console.log("\n🔄 Test: Replay Protection (duplicate nonce)");
  console.log("   Sending same request twice with identical X-Request-Id...");

  const session = await initSession();

  const nonce = crypto.randomUUID();
  const timestamp = Date.now().toString();
  const requestId = `${timestamp}.${nonce}`;

  // Build AAD
  const aad = buildAad(timestamp, nonce, session.kid, session.clientId);
  const plaintext = Buffer.from(JSON.stringify({ schemeCode: "AEF", amount: 1000 }), "utf8");
  const encryptedBody = aesGcmEncrypt(session.sessionKey, aad, plaintext);

  // First request should succeed
  const response1 = await fetch(`${SERVER_URL}/transaction/purchase`, {
    method: "POST",
    headers: {
      "Content-Type": "application/octet-stream",
      "X-Kid": session.kid,
      "X-Request-Id": requestId,
      "X-ClientId": session.clientId,
    },
    body: new Uint8Array(encryptedBody),
  });

  if (response1.status !== 200) {
    console.log(`   ❌ First request failed unexpectedly: ${response1.status}`);
    return false;
  }
  console.log(`   ✓ First request succeeded (status: ${response1.status})`);

  // Second request with same nonce should fail
  const response2 = await fetch(`${SERVER_URL}/transaction/purchase`, {
    method: "POST",
    headers: {
      "Content-Type": "application/octet-stream",
      "X-Kid": session.kid,
      "X-Request-Id": requestId,
      "X-ClientId": session.clientId,
    },
    body: new Uint8Array(encryptedBody),
  });

  const body2 = await response2.text();
  if (response2.status === 400 && body2.includes("CRYPTO_ERROR")) {
    console.log(`   ✓ Second (replay) request rejected (status: ${response2.status})`);
    console.log("   ✅ PASS: Replay protection is working");
    return true;
  } else {
    console.log(`   ❌ FAIL: Replay attack succeeded! Status: ${response2.status}, Body: ${body2}`);
    return false;
  }
}

async function testExpiredTimestamp(): Promise<boolean> {
  console.log("\n⏰ Test: Expired Timestamp (old request)");
  console.log("   Sending request with timestamp from 10 minutes ago...");

  const session = await initSession();

  const nonce = crypto.randomUUID();
  // 10 minutes in the past
  const oldTimestamp = (Date.now() - 10 * 60 * 1000).toString();
  const requestId = `${oldTimestamp}.${nonce}`;

  const result = await makePurchaseRequest(session, { customRequestId: requestId });

  if (result.status === 400 && result.body.includes("CRYPTO_ERROR")) {
    console.log(`   ✓ Request rejected (status: ${result.status})`);
    console.log("   ✅ PASS: Expired timestamp rejected");
    return true;
  } else {
    console.log(`   ❌ FAIL: Old timestamp accepted! Status: ${result.status}, Body: ${result.body}`);
    return false;
  }
}

async function testInvalidSessionId(): Promise<boolean> {
  console.log("\n🔑 Test: Invalid Session ID");
  console.log("   Sending request with non-existent session ID...");

  const session = await initSession();

  const result = await makePurchaseRequest(session, {
    customKid: "session:S-INVALID12345678901234",
  });

  if (result.status === 401 && result.body.includes("SESSION_EXPIRED")) {
    console.log(`   ✓ Request rejected (status: ${result.status})`);
    console.log("   ✅ PASS: Invalid session rejected");
    return true;
  } else {
    console.log(`   ❌ FAIL: Invalid session accepted! Status: ${result.status}, Body: ${result.body}`);
    return false;
  }
}

async function testMissingHeaders(): Promise<boolean> {
  console.log("\n📋 Test: Missing Required Headers");
  console.log("   Sending request without X-Kid header...");

  const session = await initSession();

  const nonce = crypto.randomUUID();
  const timestamp = Date.now().toString();
  const requestId = `${timestamp}.${nonce}`;

  const aad = buildAad(timestamp, nonce, session.kid, session.clientId);
  const plaintext = Buffer.from(JSON.stringify({ schemeCode: "AEF", amount: 1000 }), "utf8");
  const encryptedBody = aesGcmEncrypt(session.sessionKey, aad, plaintext);

  // Request without X-Kid
  const response = await fetch(`${SERVER_URL}/transaction/purchase`, {
    method: "POST",
    headers: {
      "Content-Type": "application/octet-stream",
      "X-Request-Id": requestId,
      "X-ClientId": session.clientId,
      // Missing X-Kid
    },
    body: new Uint8Array(encryptedBody),
  });

  const body = await response.text();
  if (response.status === 400 && body.includes("CRYPTO_ERROR")) {
    console.log(`   ✓ Request rejected (status: ${response.status})`);
    console.log("   ✅ PASS: Missing header rejected");
    return true;
  } else {
    console.log(`   ❌ FAIL: Missing header accepted! Status: ${response.status}, Body: ${body}`);
    return false;
  }
}

async function testTamperedCiphertext(): Promise<boolean> {
  console.log("\n🔨 Test: Tampered Ciphertext");
  console.log("   Sending request with modified encrypted body...");

  const session = await initSession();

  const nonce = crypto.randomUUID();
  const timestamp = Date.now().toString();

  const aad = buildAad(timestamp, nonce, session.kid, session.clientId);
  const plaintext = Buffer.from(JSON.stringify({ schemeCode: "AEF", amount: 1000 }), "utf8");
  const encryptedBody = aesGcmEncrypt(session.sessionKey, aad, plaintext);

  // Tamper with the ciphertext (flip some bits in the middle)
  const tamperedBody = Buffer.from(encryptedBody);
  tamperedBody[20] ^= 0xFF;  // Flip bits in ciphertext portion

  const result = await makePurchaseRequest(session, {
    customRequestId: `${timestamp}.${nonce}`,
    customBody: tamperedBody,
  });

  if (result.status === 400 && result.body.includes("CRYPTO_ERROR")) {
    console.log(`   ✓ Request rejected (status: ${result.status})`);
    console.log("   ✅ PASS: Tampered ciphertext rejected");
    return true;
  } else {
    console.log(`   ❌ FAIL: Tampered ciphertext accepted! Status: ${result.status}, Body: ${result.body}`);
    return false;
  }
}

async function testAADMismatch(): Promise<boolean> {
  console.log("\n🏷️  Test: AAD Mismatch (ClientId tampering)");
  console.log("   Encrypting with one ClientId, sending header with another...");

  const session = await initSession();

  const nonce = crypto.randomUUID();
  const timestamp = Date.now().toString();
  const requestId = `${timestamp}.${nonce}`;

  // Encrypt with original clientId
  const aad = buildAad(timestamp, nonce, session.kid, session.clientId);
  const plaintext = Buffer.from(JSON.stringify({ schemeCode: "AEF", amount: 1000 }), "utf8");
  const encryptedBody = aesGcmEncrypt(session.sessionKey, aad, plaintext);

  // Send with different clientId in header
  const response = await fetch(`${SERVER_URL}/transaction/purchase`, {
    method: "POST",
    headers: {
      "Content-Type": "application/octet-stream",
      "X-Kid": session.kid,
      "X-Request-Id": requestId,
      "X-ClientId": "TAMPERED_CLIENT",  // Different from what was used in AAD
    },
    body: new Uint8Array(encryptedBody),
  });

  const body = await response.text();
  if (response.status === 400 && body.includes("CRYPTO_ERROR")) {
    console.log(`   ✓ Request rejected (status: ${response.status})`);
    console.log("   ✅ PASS: AAD mismatch rejected");
    return true;
  } else {
    console.log(`   ❌ FAIL: AAD mismatch accepted! Status: ${response.status}, Body: ${body}`);
    return false;
  }
}

async function testInvalidRequestIdFormat(): Promise<boolean> {
  console.log("\n📝 Test: Invalid X-Request-Id Format");
  console.log("   Sending request with malformed X-Request-Id...");

  const session = await initSession();

  const result = await makePurchaseRequest(session, {
    customRequestId: "invalid-no-dot-separator",
  });

  if (result.status === 400 && result.body.includes("CRYPTO_ERROR")) {
    console.log(`   ✓ Request rejected (status: ${result.status})`);
    console.log("   ✅ PASS: Invalid format rejected");
    return true;
  } else {
    console.log(`   ❌ FAIL: Invalid format accepted! Status: ${result.status}, Body: ${result.body}`);
    return false;
  }
}

async function testEmptyBody(): Promise<boolean> {
  console.log("\n📭 Test: Empty/Short Body");
  console.log("   Sending request with body shorter than IV+Tag minimum...");

  const session = await initSession();

  const nonce = crypto.randomUUID();
  const timestamp = Date.now().toString();
  const requestId = `${timestamp}.${nonce}`;

  // Body too short (less than 28 bytes: 12 IV + 16 tag minimum)
  const shortBody = Buffer.alloc(20);

  const response = await fetch(`${SERVER_URL}/transaction/purchase`, {
    method: "POST",
    headers: {
      "Content-Type": "application/octet-stream",
      "X-Kid": session.kid,
      "X-Request-Id": requestId,
      "X-ClientId": session.clientId,
    },
    body: new Uint8Array(shortBody),
  });

  const body = await response.text();
  if (response.status === 400 && body.includes("CRYPTO_ERROR")) {
    console.log(`   ✓ Request rejected (status: ${response.status})`);
    console.log("   ✅ PASS: Short body rejected");
    return true;
  } else {
    console.log(`   ❌ FAIL: Short body accepted! Status: ${response.status}, Body: ${body}`);
    return false;
  }
}

async function testSessionInitReplayProtection(): Promise<boolean> {
  console.log("\n🔄 Test: Session Init Replay Protection");
  console.log("   Sending session init request twice with same X-Request-Id...");

  const { ecdh: clientECDH, publicKey: clientPub } = createEcdhKeypair();

  const nonce = crypto.randomUUID();
  const timestamp = Date.now().toString();
  const requestId = `${timestamp}.${nonce}`;

  const requestBody = JSON.stringify({
    clientPublicKey: b64(clientPub),
    ttlSec: 1800,
  });

  // First request should succeed
  const response1 = await fetch(`${SERVER_URL}/session/init`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "X-Request-Id": requestId,
      "X-ClientId": CLIENT_ID,
    },
    body: requestBody,
  });

  if (response1.status !== 200) {
    console.log(`   ❌ First request failed unexpectedly: ${response1.status}`);
    return false;
  }
  console.log(`   ✓ First request succeeded (status: ${response1.status})`);

  // Second request with same nonce should fail
  const response2 = await fetch(`${SERVER_URL}/session/init`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "X-Request-Id": requestId,
      "X-ClientId": CLIENT_ID,
    },
    body: requestBody,
  });

  const body2 = await response2.text();
  if (response2.status === 400 && body2.includes("CRYPTO_ERROR")) {
    console.log(`   ✓ Second (replay) request rejected (status: ${response2.status})`);
    console.log("   ✅ PASS: Session init replay protection is working");
    return true;
  } else {
    console.log(`   ❌ FAIL: Session init replay attack succeeded! Status: ${response2.status}, Body: ${body2}`);
    return false;
  }
}

// Main test runner
async function main() {
  console.log("═══════════════════════════════════════════════════════════════");
  console.log("  Negative Tests & Security Validation");
  console.log("═══════════════════════════════════════════════════════════════");
  console.log(`  Server: ${SERVER_URL}`);

  const tests = [
    { name: "Replay Protection", fn: testReplayProtection },
    { name: "Session Init Replay", fn: testSessionInitReplayProtection },
    { name: "Expired Timestamp", fn: testExpiredTimestamp },
    { name: "Invalid Session ID", fn: testInvalidSessionId },
    { name: "Missing Headers", fn: testMissingHeaders },
    { name: "Tampered Ciphertext", fn: testTamperedCiphertext },
    { name: "AAD Mismatch", fn: testAADMismatch },
    { name: "Invalid Request-Id Format", fn: testInvalidRequestIdFormat },
    { name: "Empty/Short Body", fn: testEmptyBody },
  ];

  const results: { name: string; passed: boolean }[] = [];

  for (const test of tests) {
    try {
      const passed = await test.fn();
      results.push({ name: test.name, passed });
    } catch (error) {
      console.log(`   ❌ ERROR: ${error}`);
      results.push({ name: test.name, passed: false });
    }
  }

  // Summary
  console.log("\n═══════════════════════════════════════════════════════════════");
  console.log("  Test Results Summary");
  console.log("═══════════════════════════════════════════════════════════════\n");

  const passed = results.filter((r) => r.passed).length;
  const failed = results.filter((r) => !r.passed).length;

  for (const result of results) {
    const icon = result.passed ? "✅" : "❌";
    console.log(`  ${icon} ${result.name}`);
  }

  console.log("\n───────────────────────────────────────────────────────────────");
  console.log(`  Total: ${results.length} | Passed: ${passed} | Failed: ${failed}`);
  console.log("═══════════════════════════════════════════════════════════════\n");

  if (failed > 0) {
    process.exit(1);
  }
}

main().catch((error) => {
  console.error("Fatal error:", error);
  process.exit(1);
});
