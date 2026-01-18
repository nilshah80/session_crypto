import crypto from "crypto";
import {
  b64,
  unb64,
  createEcdhKeypair,
  hkdf32,
  aesGcmEncrypt,
  aesGcmDecrypt,
  buildAad,
  generateIv,
} from "./crypto-helpers.js";

const SERVER_URL = "http://localhost:3000";

interface SessionInitResponse {
  sessionId: string;
  serverPublicKey: string;
  encAlg: string;
  expiresInSec: number;
}

interface SessionContext {
  sessionId: string;
  sessionKey: Buffer;
  kid: string;
}

// Step 1: Initialize session with server
async function initSession(): Promise<SessionContext> {
  console.log("\n📡 Step 1: Initializing session with server...\n");

  // Generate client ECDH keypair
  const { ecdh: clientECDH, publicKey: clientPub } = createEcdhKeypair();
  console.log("  ✅ Generated client ECDH keypair");
  console.log(`     Public key (first 32 chars): ${b64(clientPub).slice(0, 32)}...`);

  // Prepare request
  const nonce = crypto.randomUUID();
  const timestamp = Date.now().toString();

  const requestBody = {
    keyAgreement: "ECDH_P256",
    clientPublicKey: b64(clientPub),
    ttlSec: 1800,
  };

  console.log("\n  📤 Sending POST /session/init");
  console.log(`     X-Nonce: ${nonce}`);
  console.log(`     X-Timestamp: ${timestamp}`);

  // Call /session/init
  // Note: Authorization handled by APIM in production
  const response = await fetch(`${SERVER_URL}/session/init`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "X-Nonce": nonce,
      "X-Timestamp": timestamp,
    },
    body: JSON.stringify(requestBody),
  });

  if (!response.ok) {
    const error = await response.text();
    throw new Error(`Session init failed: ${response.status} - ${error}`);
  }

  const data: SessionInitResponse = await response.json();
  console.log("\n  📥 Received response:");
  console.log(`     Session ID: ${data.sessionId}`);
  console.log(`     Encryption: ${data.encAlg}`);
  console.log(`     Expires in: ${data.expiresInSec} seconds`);

  // Decode server public key
  const serverPub = unb64(data.serverPublicKey);
  console.log(`     Server public key (first 32 chars): ${data.serverPublicKey.slice(0, 32)}...`);

  // Compute shared secret using ECDH
  const sharedSecret = clientECDH.computeSecret(serverPub);
  console.log("\n  🔐 Computed ECDH shared secret");

  // Derive session key using HKDF (must match server's derivation)
  const salt = Buffer.from(data.sessionId, "utf8");
  const info = Buffer.from("SESSION|A256GCM|AUTH", "utf8");
  const sessionKey = hkdf32(sharedSecret, salt, info);
  console.log("  🔑 Derived session key using HKDF-SHA256");
  console.log(`     Session key (first 16 chars): ${b64(sessionKey).slice(0, 16)}...`);

  const kid = `session:${data.sessionId}`;

  return {
    sessionId: data.sessionId,
    sessionKey,
    kid,
  };
}

// Step 2: Make encrypted API call
async function makePurchase(
  session: SessionContext,
  purchaseData: { schemeCode: string; amount: number }
): Promise<void> {
  console.log("\n📡 Step 2: Making encrypted purchase request...\n");

  // Prepare plaintext
  const plaintext = Buffer.from(JSON.stringify(purchaseData), "utf8");
  console.log("  📝 Request payload:");
  console.log(`     ${JSON.stringify(purchaseData)}`);

  // Generate IV for this request
  const iv = generateIv();
  const nonce = crypto.randomUUID();
  const timestamp = Date.now().toString();

  // Build AAD
  const aad = buildAad("POST", "/transaction/purchase", timestamp, nonce, session.kid);
  console.log("\n  🔒 Encrypting request...");
  console.log(`     IV (base64): ${b64(iv)}`);
  console.log(`     AAD: POST|/transaction/purchase|${timestamp}|${nonce.slice(0, 8)}...|session:${session.sessionId.slice(0, 8)}...`);

  // Encrypt
  const { ciphertext, tag } = aesGcmEncrypt(session.sessionKey, iv, aad, plaintext);
  console.log(`     Ciphertext length: ${ciphertext.length} bytes`);
  console.log(`     Auth tag (base64): ${b64(tag)}`);

  // Send encrypted request
  // Note: Authorization handled by APIM in production
  console.log("\n  📤 Sending encrypted POST /transaction/purchase");

  const response = await fetch(`${SERVER_URL}/transaction/purchase`, {
    method: "POST",
    headers: {
      "Content-Type": "application/octet-stream",
      "X-Kid": session.kid,
      "X-Enc-Alg": "A256GCM",
      "X-IV": b64(iv),
      "X-Tag": b64(tag),
      "X-AAD": b64(aad),
      "X-Nonce": nonce,
      "X-Timestamp": timestamp,
    },
    body: b64(ciphertext),
  });

  if (!response.ok) {
    const error = await response.text();
    throw new Error(`Purchase failed: ${response.status} - ${error}`);
  }

  console.log(`\n  📥 Received encrypted response (status: ${response.status})`);

  // Extract response headers
  const respKid = response.headers.get("X-Kid");
  const respEncAlg = response.headers.get("X-Enc-Alg");
  const respIvB64 = response.headers.get("X-IV");
  const respTagB64 = response.headers.get("X-Tag");
  const respAadB64 = response.headers.get("X-AAD");

  console.log("     Response headers:");
  console.log(`       X-Kid: ${respKid}`);
  console.log(`       X-Enc-Alg: ${respEncAlg}`);
  console.log(`       X-IV: ${respIvB64?.slice(0, 20)}...`);
  console.log(`       X-Tag: ${respTagB64?.slice(0, 20)}...`);

  if (!respIvB64 || !respTagB64 || !respAadB64) {
    throw new Error("Missing encryption headers in response");
  }

  // Decode response crypto components
  const respIv = unb64(respIvB64);
  const respTag = unb64(respTagB64);
  const respAad = unb64(respAadB64);
  const respCiphertext = unb64(await response.text());

  console.log("\n  🔓 Decrypting response...");

  // Decrypt response
  const respPlaintext = aesGcmDecrypt(
    session.sessionKey,
    respIv,
    respAad,
    respCiphertext,
    respTag
  );

  // Parse decrypted JSON
  const responseData = JSON.parse(respPlaintext.toString("utf8"));

  console.log("  ✅ Decryption successful!\n");
  console.log("  📋 Decrypted response:");
  console.log("  ─────────────────────────────────────────");
  console.log(JSON.stringify(responseData, null, 4));
  console.log("  ─────────────────────────────────────────");
}

// Main execution
async function main() {
  console.log("═══════════════════════════════════════════════════════════════");
  console.log("  Session Crypto PoC - Client Demo");
  console.log("═══════════════════════════════════════════════════════════════");
  console.log(`  Server: ${SERVER_URL}`);

  try {
    // Step 1: Initialize session
    const session = await initSession();

    // Step 2: Make encrypted purchase
    await makePurchase(session, {
      schemeCode: "AEF",
      amount: 5000,
    });

    console.log("\n═══════════════════════════════════════════════════════════════");
    console.log("  ✅ Demo completed successfully!");
    console.log("═══════════════════════════════════════════════════════════════\n");
  } catch (error) {
    console.error("\n❌ Error:", error);
    process.exit(1);
  }
}

main();
