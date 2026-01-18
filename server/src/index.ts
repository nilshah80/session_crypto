import Fastify from "fastify";
import crypto from "crypto";
import { Redis } from "ioredis";
import {
  b64,
  unb64,
  createEcdhKeypair,
  hkdf32,
  validateP256PublicKey,
  validateReplayProtection,
  initReplayProtection,
  aesGcmDecrypt,
  aesGcmEncrypt,
  buildAad,
  generateIv,
  generateSessionId,
} from "./crypto-helpers.js";
import { storeSession, getSession, initSessionStore } from "./session-store.js";
import { MetricsCollector } from "./metrics.js";

// Declare module augmentation for Fastify request
declare module "fastify" {
  interface FastifyRequest {
    metrics?: MetricsCollector;
  }
}

const fastify = Fastify({
  logger: true,
});

// Initialize Redis connection
const redis = new Redis({
  host: process.env.REDIS_HOST || "localhost",
  port: parseInt(process.env.REDIS_PORT || "6379", 10),
  retryStrategy: (times) => {
    const delay = Math.min(times * 50, 2000);
    return delay;
  },
});

redis.on("connect", () => {
  console.log("Connected to Redis");
});

redis.on("error", (err) => {
  console.error("Redis connection error:", err);
});

// Initialize stores with Redis
initSessionStore(redis);
initReplayProtection(redis);

// Add content type parser for raw/octet-stream bodies
fastify.addContentTypeParser(
  "application/octet-stream",
  { parseAs: "string" },
  (_req, body, done) => {
    done(null, body);
  }
);

// Metrics hooks - initialize collector on request start
fastify.addHook("onRequest", async (request) => {
  const endpoint = request.routeOptions?.url || request.url;
  request.metrics = new MetricsCollector(endpoint);
});

// Add Server-Timing header on response
fastify.addHook("onSend", async (request, reply) => {
  if (request.metrics) {
    const header = request.metrics.toServerTimingHeader();
    reply.header("Server-Timing", header);

    // Log metrics for debugging
    const metrics = request.metrics.finalize();
    request.log.info({ metrics }, "Request metrics");
  }
});

// Types
interface SessionInitBody {
  keyAgreement: string;
  clientPublicKey: string;
  ttlSec?: number;
}

interface SessionInitResponse {
  sessionId: string;
  serverPublicKey: string;
  encAlg: string;
  expiresInSec: number;
}

// POST /session/init - Session initialization
// Note: Authorization/introspection handled by APIM before reaching this service
fastify.post<{
  Body: SessionInitBody;
  Reply: SessionInitResponse | { error: string };
}>("/session/init", async (request, reply) => {
  const nonce = request.headers["x-nonce"] as string | undefined;
  const timestamp = request.headers["x-timestamp"] as string | undefined;

  // Validate required headers
  if (!nonce || !timestamp) {
    return reply.status(400).send({ error: "CRYPTO_ERROR" });
  }

  // Replay protection
  try {
    await request.metrics!.measureAsync("replay-protection", () =>
      validateReplayProtection(nonce, timestamp)
    );
  } catch (e) {
    request.log.warn({ error: e }, "Replay protection failed");
    return reply.status(400).send({ error: "CRYPTO_ERROR" });
  }

  // Validate request body
  const { keyAgreement, clientPublicKey, ttlSec } = request.body;

  if (keyAgreement !== "ECDH_P256") {
    return reply.status(400).send({ error: "CRYPTO_ERROR" });
  }

  if (!clientPublicKey) {
    return reply.status(400).send({ error: "CRYPTO_ERROR" });
  }

  // Decode and validate client public key
  let clientPub: Buffer;
  try {
    clientPub = request.metrics!.measure("validate-pubkey", () => {
      const pub = unb64(clientPublicKey);
      validateP256PublicKey(pub);
      return pub;
    });
  } catch (e) {
    request.log.warn({ error: e }, "Client public key validation failed");
    return reply.status(400).send({ error: "CRYPTO_ERROR" });
  }

  // Generate server ECDH keypair
  const { ecdh: serverECDH, publicKey: serverPub } = request.metrics!.measure(
    "ecdh-keygen",
    () => createEcdhKeypair()
  );

  // Compute shared secret
  const sharedSecret = request.metrics!.measure("ecdh-compute", () =>
    serverECDH.computeSecret(clientPub)
  );

  // Generate session ID with 128-bit entropy
  const sessionId = generateSessionId("S");

  // Cap TTL between 5 minutes and 1 hour
  const allowedTtl = Math.min(Math.max(ttlSec ?? 1800, 300), 3600);

  // Derive session key using HKDF
  // Using a fixed info string since we don't have token introspection here
  // In production with APIM, you might pass principal info via headers
  const salt = Buffer.from(sessionId, "utf8");
  const info = Buffer.from("SESSION|A256GCM|AUTH", "utf8");
  const sessionKey = request.metrics!.measure("hkdf", () =>
    hkdf32(sharedSecret, salt, info)
  );

  // Store session in Redis
  await request.metrics!.measureAsync("redis-store", () =>
    storeSession(sessionId, sessionKey, "AUTH", allowedTtl)
  );

  request.log.info({ sessionId, ttl: allowedTtl }, "Session created");

  return {
    sessionId,
    serverPublicKey: b64(serverPub),
    encAlg: "A256GCM",
    expiresInSec: allowedTtl,
  };
});

// POST /transaction/purchase - Encrypted business endpoint
fastify.post("/transaction/purchase", async (request, reply) => {
  // Extract encryption headers
  const kid = request.headers["x-kid"] as string | undefined;
  const encAlg = request.headers["x-enc-alg"] as string | undefined;
  const ivB64 = request.headers["x-iv"] as string | undefined;
  const tagB64 = request.headers["x-tag"] as string | undefined;
  const aadB64 = request.headers["x-aad"] as string | undefined;
  const nonce = request.headers["x-nonce"] as string | undefined;
  const timestamp = request.headers["x-timestamp"] as string | undefined;

  // Validate all required headers
  if (!kid || !encAlg || !ivB64 || !tagB64 || !aadB64 || !nonce || !timestamp) {
    return reply.status(400).send({ error: "CRYPTO_ERROR" });
  }

  // Validate encryption algorithm
  if (encAlg !== "A256GCM") {
    return reply.status(400).send({ error: "CRYPTO_ERROR" });
  }

  // Replay protection
  try {
    await request.metrics!.measureAsync("replay-protection", () =>
      validateReplayProtection(nonce, timestamp)
    );
  } catch (e) {
    request.log.warn({ error: e }, "Replay protection failed");
    return reply.status(400).send({ error: "CRYPTO_ERROR" });
  }

  // Extract session ID from kid (format: "session:S-xxxx")
  const sessionId = kid.startsWith("session:") ? kid.slice(8) : null;
  if (!sessionId) {
    return reply.status(400).send({ error: "CRYPTO_ERROR" });
  }

  // Get session from Redis store
  const session = await request.metrics!.measureAsync("redis-get", () =>
    getSession(sessionId)
  );
  if (!session) {
    return reply.status(401).send({ error: "SESSION_EXPIRED" });
  }

  // Decode crypto components
  let iv: Buffer, tag: Buffer, aad: Buffer, ciphertext: Buffer;
  try {
    iv = unb64(ivB64);
    tag = unb64(tagB64);
    aad = unb64(aadB64);

    // Validate IV and tag lengths
    if (iv.length !== 12) throw new Error("INVALID_IV_LENGTH");
    if (tag.length !== 16) throw new Error("INVALID_TAG_LENGTH");

    // Get ciphertext from body (raw buffer)
    const rawBody = request.body as Buffer | string;
    ciphertext =
      typeof rawBody === "string" ? unb64(rawBody) : Buffer.from(rawBody);
  } catch (e) {
    request.log.warn({ error: e }, "Failed to decode crypto components");
    return reply.status(400).send({ error: "CRYPTO_ERROR" });
  }

  // Rebuild expected AAD and verify it matches
  const expectedAad = request.metrics!.measure("aad-validation", () =>
    buildAad("POST", "/transaction/purchase", timestamp, nonce, kid)
  );
  if (!aad.equals(expectedAad)) {
    request.log.warn("AAD mismatch");
    return reply.status(400).send({ error: "CRYPTO_ERROR" });
  }

  // Decrypt request body
  let plaintext: Buffer;
  try {
    plaintext = request.metrics!.measure("aes-gcm-decrypt", () =>
      aesGcmDecrypt(session.key, iv, aad, ciphertext, tag)
    );
  } catch (e) {
    request.log.warn({ error: e }, "Decryption failed");
    return reply.status(400).send({ error: "CRYPTO_ERROR" });
  }

  // Parse decrypted JSON
  let requestData: { schemeCode: string; amount: number };
  try {
    requestData = JSON.parse(plaintext.toString("utf8"));
  } catch (e) {
    request.log.warn({ error: e }, "Failed to parse decrypted JSON");
    return reply.status(400).send({ error: "CRYPTO_ERROR" });
  }

  request.log.info({ requestData }, "Decrypted request received");

  // ===== BUSINESS LOGIC =====
  // Process the transaction (mock implementation)
  const responseData = {
    status: "SUCCESS",
    transactionId: `TXN-${crypto.randomBytes(8).toString("hex").toUpperCase()}`,
    schemeCode: requestData.schemeCode,
    amount: requestData.amount,
    timestamp: new Date().toISOString(),
    message: `Purchase of ${requestData.amount} in scheme ${requestData.schemeCode} completed successfully`,
  };
  // ===== END BUSINESS LOGIC =====

  // Encrypt response
  const responsePlaintext = Buffer.from(JSON.stringify(responseData), "utf8");
  const responseIv = generateIv();
  const responseNonce = crypto.randomUUID();
  const responseTimestamp = Date.now().toString();

  // Build response AAD
  const responseAad = buildAad(
    "200",
    "/transaction/purchase",
    responseTimestamp,
    responseNonce,
    kid
  );

  const { ciphertext: responseCiphertext, tag: responseTag } =
    request.metrics!.measure("aes-gcm-encrypt", () =>
      aesGcmEncrypt(session.key, responseIv, responseAad, responsePlaintext)
    );

  // Set response headers
  reply.header("X-Kid", kid);
  reply.header("X-Enc-Alg", "A256GCM");
  reply.header("X-IV", b64(responseIv));
  reply.header("X-Tag", b64(responseTag));
  reply.header("X-AAD", b64(responseAad));
  reply.header("X-Nonce", responseNonce);
  reply.header("X-Timestamp", responseTimestamp);
  reply.header("Content-Type", "application/octet-stream");

  return reply.send(b64(responseCiphertext));
});

// Health check
fastify.get("/health", async () => {
  // Check Redis connection
  const redisStatus = redis.status === "ready" ? "ok" : "disconnected";
  return {
    status: redisStatus === "ok" ? "ok" : "degraded",
    timestamp: new Date().toISOString(),
    redis: redisStatus,
  };
});

// Graceful shutdown
const shutdown = async () => {
  console.log("Shutting down...");
  await redis.quit();
  await fastify.close();
  process.exit(0);
};

process.on("SIGTERM", shutdown);
process.on("SIGINT", shutdown);

// Start server
const start = async () => {
  try {
    // Wait for Redis to be ready
    await new Promise<void>((resolve, reject) => {
      if (redis.status === "ready") {
        resolve();
        return;
      }
      redis.once("ready", resolve);
      redis.once("error", reject);
      setTimeout(() => reject(new Error("Redis connection timeout")), 10000);
    });

    await fastify.listen({ port: 3000, host: "0.0.0.0" });
    console.log("Server listening on http://localhost:3000");
  } catch (err) {
    fastify.log.error(err);
    process.exit(1);
  }
};

start();
