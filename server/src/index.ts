import Fastify from "fastify";
import cors from "@fastify/cors";
import crypto from "crypto";
import http from "http";
import { Redis } from "ioredis";
import {
  b64,
  unb64,
  createEcdhKeypair,
  hkdf32,
  validateP256PublicKey,
  validateReplayProtection,
  initReplayProtection,
  disposeReplayProtection,
  aesGcmDecrypt,
  aesGcmEncrypt,
  buildAad,
  generateSessionId,
} from "./crypto-helpers.js";
import { storeSession, getSession, initSessionStore, getPool, closeSessionStore } from "./session-store.js";
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

/**
 * Parse integer environment variable with validation
 */
function parseIntEnv(name: string, defaultValue: number, min?: number, max?: number): number {
  const raw = process.env[name];
  if (!raw) return defaultValue;

  const parsed = parseInt(raw, 10);
  if (isNaN(parsed)) {
    throw new Error(`Invalid ${name}: "${raw}" is not a valid integer`);
  }
  if (min !== undefined && parsed < min) {
    throw new Error(`Invalid ${name}: ${parsed} is below minimum ${min}`);
  }
  if (max !== undefined && parsed > max) {
    throw new Error(`Invalid ${name}: ${parsed} exceeds maximum ${max}`);
  }
  return parsed;
}

// Configuration constants (with environment variable overrides and validation)
const REDIS_COMMAND_TIMEOUT_MS = parseIntEnv("REDIS_COMMAND_TIMEOUT_MS", 5000, 100, 60000);
const REDIS_CONNECTION_TIMEOUT_MS = parseIntEnv("REDIS_CONNECTION_TIMEOUT_MS", 10000, 1000, 60000);
const SESSION_TTL_MIN_SEC = parseIntEnv("SESSION_TTL_MIN_SEC", 300, 60);  // 5 minutes default, min 1 minute
const SESSION_TTL_MAX_SEC = parseIntEnv("SESSION_TTL_MAX_SEC", 3600, 60); // 1 hour default, min 1 minute
const SESSION_TTL_DEFAULT_SEC = parseIntEnv("SESSION_TTL_DEFAULT_SEC", 1800, 60); // 30 minutes default, min 1 minute

// Identity Service configuration
const IDENTITY_SERVICE_HOST = process.env.IDENTITY_SERVICE_HOST || "localhost";
const IDENTITY_SERVICE_PORT = parseIntEnv("IDENTITY_SERVICE_PORT", 3001, 1, 65535);
const IDENTITY_SERVICE_TIMEOUT_MS = parseIntEnv("IDENTITY_SERVICE_TIMEOUT_MS", 5000, 100, 30000);

/**
 * Response from identity-service GET /v1/session/:sessionId
 */
interface SessionKeyResponse {
  sessionId: string;
  sessionKey: string;
  expiresAt: number;
}

/**
 * Fetch session key from identity-service-node
 * @param sessionId Session ID
 * @param clientId Client ID for authorization
 * @returns Session key as Buffer
 */
async function fetchSessionKeyFromIdentityService(
  sessionId: string,
  clientId: string
): Promise<{ key: Buffer; expiresAt: number }> {
  return new Promise((resolve, reject) => {
    const options = {
      hostname: IDENTITY_SERVICE_HOST,
      port: IDENTITY_SERVICE_PORT,
      path: `/v1/session/${sessionId}`,
      method: "GET",
      headers: {
        "X-ClientId": clientId,
      },
      timeout: IDENTITY_SERVICE_TIMEOUT_MS,
    };

    const req = http.request(options, (res) => {
      let data = "";
      res.on("data", (chunk) => { data += chunk; });
      res.on("end", () => {
        try {
          if (res.statusCode === 200) {
            const response: SessionKeyResponse = JSON.parse(data);
            const keyBuffer = Buffer.from(response.sessionKey, "base64");
            resolve({ key: keyBuffer, expiresAt: response.expiresAt });
          } else if (res.statusCode === 404) {
            reject(new Error("SESSION_NOT_FOUND"));
          } else if (res.statusCode === 403) {
            reject(new Error("SESSION_UNAUTHORIZED"));
          } else if (res.statusCode === 410) {
            reject(new Error("SESSION_EXPIRED"));
          } else {
            reject(new Error(`IDENTITY_SERVICE_ERROR: ${res.statusCode}`));
          }
        } catch (e) {
          reject(new Error("IDENTITY_SERVICE_PARSE_ERROR"));
        }
      });
    });

    req.on("error", (err) => {
      reject(new Error(`IDENTITY_SERVICE_UNAVAILABLE: ${err.message}`));
    });

    req.on("timeout", () => {
      req.destroy();
      reject(new Error("IDENTITY_SERVICE_TIMEOUT"));
    });

    req.end();
  });
}

// Validate required environment variables
function validateEnvironment(): void {
  const required = [
    "REDIS_HOST",
    "POSTGRES_HOST",
    "POSTGRES_USER",
    "POSTGRES_PASSWORD",
    "POSTGRES_DB",
  ];

  const missing = required.filter((key) => !process.env[key]);

  if (missing.length > 0) {
    throw new Error(
      `Missing required environment variables: ${missing.join(", ")}\n` +
        `Please check your .env file or environment configuration.`
    );
  }

  // Validate port is a valid number
  const port = parseInt(process.env.PORT || "3000", 10);
  if (isNaN(port) || port < 1 || port > 65535) {
    throw new Error(`Invalid PORT: ${process.env.PORT}`);
  }

  const redisPort = parseInt(process.env.REDIS_PORT || "6379", 10);
  if (isNaN(redisPort) || redisPort < 1 || redisPort > 65535) {
    throw new Error(`Invalid REDIS_PORT: ${process.env.REDIS_PORT}`);
  }

  const postgresPort = parseInt(process.env.POSTGRES_PORT || "5432", 10);
  if (isNaN(postgresPort) || postgresPort < 1 || postgresPort > 65535) {
    throw new Error(`Invalid POSTGRES_PORT: ${process.env.POSTGRES_PORT}`);
  }
}

// Initialize Redis connection
const redis = new Redis({
  host: process.env.REDIS_HOST || "localhost",
  port: parseInt(process.env.REDIS_PORT || "6379", 10),
  commandTimeout: REDIS_COMMAND_TIMEOUT_MS,
  retryStrategy: (times) => {
    const delay = Math.min(times * 50, 2000);
    return delay;
  },
});

redis.on("connect", () => {
  fastify.log.info("Connected to Redis");
});

redis.on("error", (err) => {
  fastify.log.error({ err }, "Redis connection error");
});

// Initialize stores with Redis
// Session store initialized in start()
initReplayProtection(redis, fastify.log);

// Enable CORS for browser clients (must be registered before routes)
await fastify.register(cors, {
  origin: true, // Allow all origins in development
  methods: ["GET", "POST", "OPTIONS"],
  allowedHeaders: [
    "Content-Type",
    "X-Idempotency-Key",
    "X-ClientId",
    "X-Kid",
  ],
  exposedHeaders: [
    "Server-Timing",
    "X-Kid",
    "X-Idempotency-Key",
  ],
});

// Add content type parser for raw/octet-stream bodies
fastify.addContentTypeParser(
  "application/octet-stream",
  { parseAs: "buffer" },
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
  const idempotencyKey = request.headers["x-idempotency-key"] as string | undefined;
  const clientId = request.headers["x-clientid"] as string | undefined;

  // Validate required headers
  if (!idempotencyKey || !clientId) {
    return reply.status(400).send({ error: "CRYPTO_ERROR" });
  }

  // Parse X-Idempotency-Key: timestamp.nonce
  const [timestamp, nonce] = idempotencyKey.split(".");
  if (!timestamp || !nonce) {
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
  const { clientPublicKey, ttlSec } = request.body;

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

  // Validate TTL
  if (ttlSec !== undefined && (ttlSec < 0 || !Number.isInteger(ttlSec))) {
    return reply.status(400).send({ error: "CRYPTO_ERROR" });
  }

  // Cap TTL between configured min and max
  const allowedTtl = Math.min(Math.max(ttlSec ?? SESSION_TTL_DEFAULT_SEC, SESSION_TTL_MIN_SEC), SESSION_TTL_MAX_SEC);

  // Derive session key using HKDF
  // Info includes clientId for domain separation
  const salt = Buffer.from(sessionId, "utf8");
  const info = Buffer.from(`SESSION|A256GCM|${clientId}`, "utf8");
  const sessionKey = request.metrics!.measure("hkdf", () =>
    hkdf32(sharedSecret, salt, info)
  );

  // SECURITY: Zeroize shared secret after deriving session key
  sharedSecret.fill(0);

  // Store session in Redis
  await request.metrics!.measureAsync("redis-store", () =>
    storeSession(sessionId, sessionKey, "AUTH", allowedTtl)
  );

  // SECURITY: Zeroize session key after storing
  sessionKey.fill(0);

  request.log.info({ sessionId, ttl: allowedTtl }, "Session created");

  return {
    sessionId,
    serverPublicKey: b64(serverPub),
    encAlg: "A256GCM",
    expiresInSec: allowedTtl,
  };
});

// POST /transaction/purchase - Encrypted business endpoint
// Fetches session key from identity-service-node for decryption/encryption
fastify.post("/transaction/purchase", async (request, reply) => {
  // Extract headers
  const kid = request.headers["x-kid"] as string | undefined;
  const idempotencyKey = request.headers["x-idempotency-key"] as string | undefined;
  const clientId = request.headers["x-clientid"] as string | undefined;

  // Validate all required headers
  if (!kid || !idempotencyKey || !clientId) {
    return reply.status(400).send({ error: "CRYPTO_ERROR" });
  }

  // Parse X-Idempotency-Key: timestamp.nonce
  const [timestamp, nonce] = idempotencyKey.split(".");
  if (!timestamp || !nonce) {
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

  // Fetch session key from identity-service-node
  let sessionKey: Buffer;
  try {
    const session = await request.metrics!.measureAsync("identity-service-get", () =>
      fetchSessionKeyFromIdentityService(sessionId, clientId)
    );
    sessionKey = session.key;
  } catch (e) {
    const error = e as Error;
    request.log.warn({ error: error.message, sessionId }, "Failed to fetch session from identity-service");
    
    if (error.message === "SESSION_NOT_FOUND" || error.message === "SESSION_EXPIRED") {
      return reply.status(401).send({ error: "SESSION_EXPIRED" });
    }
    if (error.message === "SESSION_UNAUTHORIZED") {
      return reply.status(403).send({ error: "SESSION_UNAUTHORIZED" });
    }
    // Identity service unavailable or other errors
    return reply.status(503).send({ error: "SERVICE_UNAVAILABLE" });
  }

  // SECURITY: Wrap all session key usage in try/finally to ensure zeroization on all paths
  try {
    // Build AAD from headers (server reconstructs it)
    // AAD format: TIMESTAMP|NONCE|KID|CLIENTID
    const aad = request.metrics!.measure("aad-build", () =>
      buildAad(timestamp, nonce, kid, clientId)
    );

    // Get encrypted body (IV || ciphertext || tag)
    let encryptedBody: Buffer;
    try {
      const rawBody = request.body as Buffer | string;
      encryptedBody =
        typeof rawBody === "string" ? Buffer.from(rawBody) : Buffer.from(rawBody);

      // Minimum length: IV (12) + tag (16) = 28 bytes
      if (encryptedBody.length < 28) {
        throw new Error("INVALID_BODY_LENGTH");
      }
    } catch (e) {
      request.log.warn({ error: e }, "Failed to read encrypted body");
      return reply.status(400).send({ error: "CRYPTO_ERROR" });
    }

    // Decrypt request body (body contains IV || ciphertext || tag)
    let plaintext: Buffer;
    try {
      plaintext = request.metrics!.measure("aes-gcm-decrypt", () =>
        aesGcmDecrypt(sessionKey, aad, encryptedBody)
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
    const responseNonce = crypto.randomUUID();
    const responseTimestamp = Date.now().toString();
    const responseIdempotencyKey = `${responseTimestamp}.${responseNonce}`;

    // Build response AAD
    // AAD format: TIMESTAMP|NONCE|KID|CLIENTID
    const responseAad = buildAad(
      responseTimestamp,
      responseNonce,
      kid,
      clientId
    );

    // Encrypt - returns IV || ciphertext || tag
    const encryptedResponse = request.metrics!.measure("aes-gcm-encrypt", () =>
      aesGcmEncrypt(sessionKey, responseAad, responsePlaintext)
    );

    // Set response headers
    reply.header("X-Kid", kid);
    reply.header("X-Idempotency-Key", responseIdempotencyKey);
    reply.header("Content-Type", "application/octet-stream");

    return reply.send(encryptedResponse);
  } finally {
    // SECURITY: Always zeroize session key, even on error paths
    sessionKey.fill(0);
  }
});

// Health check
fastify.get("/health", async () => {
  // Check Redis connection
  const redisStatus = redis.status === "ready" ? "ok" : "disconnected";

  // Check Postgres connection
  let postgresStatus = "disconnected";
  const pool = getPool();
  if (pool) {
    try {
      await pool.query("SELECT 1");
      postgresStatus = "ok";
    } catch {
      postgresStatus = "disconnected";
    }
  }

  const status = redisStatus === "ok" && postgresStatus === "ok" ? "ok" : "degraded";

  return {
    status,
    timestamp: new Date().toISOString(),
    redis: redisStatus,
    postgres: postgresStatus,
  };
});

// Graceful shutdown
const shutdown = async () => {
  fastify.log.info("Shutting down...");
  disposeReplayProtection();
  await redis.quit();
  await closeSessionStore();
  await fastify.close();
  process.exit(0);
};

process.on("SIGTERM", shutdown);
process.on("SIGINT", shutdown);

// Start server
const start = async () => {
  try {
    // Validate environment variables first
    validateEnvironment();

    // Try to wait for Redis to be ready (optional - server can run without Redis)
    try {
      await new Promise<void>((resolve, reject) => {
        if (redis.status === "ready") {
          resolve();
          return;
        }
        redis.once("ready", resolve);
        redis.once("error", reject);
        setTimeout(() => reject(new Error("Redis connection timeout")), REDIS_CONNECTION_TIMEOUT_MS);
      });
      fastify.log.info("Redis connected - cache enabled");
    } catch (redisErr) {
      fastify.log.warn({ err: redisErr }, "Redis unavailable - running without cache (PostgreSQL only)");
    }

    // Initialize session store (connects to Postgres)
    await initSessionStore(redis, fastify.log);

    const PORT = parseInt(process.env.PORT || "3000", 10);
    await fastify.listen({ port: PORT, host: "0.0.0.0" });
    fastify.log.info(`Server listening on http://localhost:${PORT}`);
  } catch (err) {
    fastify.log.error(err);
    process.exit(1);
  }
};

start();
