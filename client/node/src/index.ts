import crypto from "crypto";
import { performance } from "perf_hooks";
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

// ===== Metrics Types =====
interface CryptoTiming {
  operation: string;
  durationMs: number;
}

interface EndpointMetrics {
  endpoint: string;
  totalRoundTripMs: number;
  httpRequestMs: number;
  cryptoOperations: CryptoTiming[];
  serverTiming?: string;
}

interface BenchmarkStats {
  count: number;
  totalMs: number;
  minMs: number;
  maxMs: number;
  meanMs: number;
  p50Ms: number;
  p95Ms: number;
  p99Ms: number;
}

// ===== Metrics Helpers =====
function measureSync<T>(
  operation: string,
  timings: CryptoTiming[],
  fn: () => T
): T {
  const start = performance.now();
  const result = fn();
  timings.push({ operation, durationMs: performance.now() - start });
  return result;
}

function parseServerTiming(header: string | null): CryptoTiming[] {
  if (!header) return [];
  return header.split(",").map((part) => {
    const [name, durPart] = part.trim().split(";");
    const dur = durPart?.match(/dur=([\d.]+)/)?.[1];
    return {
      operation: name.trim(),
      durationMs: dur ? parseFloat(dur) : 0,
    };
  });
}

function calculateStats(durations: number[]): BenchmarkStats {
  const sorted = [...durations].sort((a, b) => a - b);
  const sum = sorted.reduce((a, b) => a + b, 0);
  const len = sorted.length;

  return {
    count: len,
    totalMs: sum,
    minMs: sorted[0],
    maxMs: sorted[len - 1],
    meanMs: sum / len,
    p50Ms: sorted[Math.floor(len * 0.5)],
    p95Ms: sorted[Math.floor(len * 0.95)],
    p99Ms: sorted[Math.floor(len * 0.99)],
  };
}

// ===== Response Types =====
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
  clientId: string;
}

// Client ID for this application
const CLIENT_ID = "NODE_CLIENT";

// ===== Step 1: Initialize session with server =====
async function initSession(
  verbose: boolean = true
): Promise<{ session: SessionContext; metrics: EndpointMetrics }> {
  const totalStart = performance.now();
  const cryptoOps: CryptoTiming[] = [];

  if (verbose) {
    console.log("\n📡 Step 1: Initializing session with server...\n");
  }

  // Generate client ECDH keypair
  const { ecdh: clientECDH, publicKey: clientPub } = measureSync(
    "ecdh-keygen",
    cryptoOps,
    () => createEcdhKeypair()
  );

  if (verbose) {
    console.log("  ✅ Generated client ECDH keypair");
    console.log(
      `     Public key (first 32 chars): ${b64(clientPub).slice(0, 32)}...`
    );
  }

  // Prepare request
  const nonce = crypto.randomUUID();
  const timestamp = Date.now().toString();

  const requestBody = {
    clientPublicKey: b64(clientPub),
    ttlSec: 1800,
  };

  if (verbose) {
    console.log("\n  📤 Sending POST /session/init");
    console.log(`     X-Nonce: ${nonce}`);
    console.log(`     X-Timestamp: ${timestamp}`);
    console.log(`     X-ClientId: ${CLIENT_ID}`);
  }

  // Time HTTP request
  const httpStart = performance.now();
  const response = await fetch(`${SERVER_URL}/session/init`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "X-Nonce": nonce,
      "X-Timestamp": timestamp,
      "X-ClientId": CLIENT_ID,
    },
    body: JSON.stringify(requestBody),
  });
  const httpMs = performance.now() - httpStart;

  if (!response.ok) {
    const error = await response.text();
    throw new Error(`Session init failed: ${response.status} - ${error}`);
  }

  // Get Server-Timing header
  const serverTiming = response.headers.get("Server-Timing") ?? undefined;

  const data: SessionInitResponse = await response.json();

  if (verbose) {
    console.log("\n  📥 Received response:");
    console.log(`     Session ID: ${data.sessionId}`);
    console.log(`     Encryption: ${data.encAlg}`);
    console.log(`     Expires in: ${data.expiresInSec} seconds`);
  }

  // Decode server public key
  const serverPub = unb64(data.serverPublicKey);

  if (verbose) {
    console.log(
      `     Server public key (first 32 chars): ${data.serverPublicKey.slice(0, 32)}...`
    );
  }

  // Compute shared secret using ECDH
  const sharedSecret = measureSync("ecdh-compute", cryptoOps, () =>
    clientECDH.computeSecret(serverPub)
  );

  if (verbose) {
    console.log("\n  🔐 Computed ECDH shared secret");
  }

  // Derive session key using HKDF (must match server's derivation)
  // Info includes clientId for domain separation
  const salt = Buffer.from(data.sessionId, "utf8");
  const info = Buffer.from(`SESSION|A256GCM|${CLIENT_ID}`, "utf8");
  const sessionKey = measureSync("hkdf", cryptoOps, () =>
    hkdf32(sharedSecret, salt, info)
  );

  if (verbose) {
    console.log("  🔑 Derived session key using HKDF-SHA256");
    console.log(
      `     Session key (first 16 chars): ${b64(sessionKey).slice(0, 16)}...`
    );
  }

  const kid = `session:${data.sessionId}`;

  const metrics: EndpointMetrics = {
    endpoint: "/session/init",
    totalRoundTripMs: performance.now() - totalStart,
    httpRequestMs: httpMs,
    cryptoOperations: cryptoOps,
    serverTiming,
  };

  return {
    session: {
      sessionId: data.sessionId,
      sessionKey,
      kid,
      clientId: CLIENT_ID,
    },
    metrics,
  };
}

// ===== Step 2: Make encrypted API call =====
async function makePurchase(
  session: SessionContext,
  purchaseData: { schemeCode: string; amount: number },
  verbose: boolean = true
): Promise<EndpointMetrics> {
  const totalStart = performance.now();
  const cryptoOps: CryptoTiming[] = [];

  if (verbose) {
    console.log("\n📡 Step 2: Making encrypted purchase request...\n");
  }

  // Prepare plaintext
  const plaintext = Buffer.from(JSON.stringify(purchaseData), "utf8");

  if (verbose) {
    console.log("  📝 Request payload:");
    console.log(`     ${JSON.stringify(purchaseData)}`);
  }

  // Generate IV for this request
  const iv = generateIv();
  const nonce = crypto.randomUUID();
  const timestamp = Date.now().toString();

  // Build AAD
  // Format: TIMESTAMP|NONCE|KID|CLIENTID
  const aad = buildAad(
    timestamp,
    nonce,
    session.kid,
    session.clientId
  );

  if (verbose) {
    console.log("\n  🔒 Encrypting request...");
    console.log(`     IV (base64): ${b64(iv)}`);
    console.log(
      `     AAD: ${timestamp}|${nonce.slice(0, 8)}...|session:${session.sessionId.slice(0, 8)}...|${session.clientId}`
    );
  }

  // Encrypt
  const { ciphertext, tag } = measureSync("aes-gcm-encrypt", cryptoOps, () =>
    aesGcmEncrypt(session.sessionKey, iv, aad, plaintext)
  );

  if (verbose) {
    console.log(`     Ciphertext length: ${ciphertext.length} bytes`);
    console.log(`     Auth tag (base64): ${b64(tag)}`);
    console.log("\n  📤 Sending encrypted POST /transaction/purchase");
  }

  // Time HTTP request
  const httpStart = performance.now();
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
      "X-ClientId": session.clientId,
    },
    body: b64(ciphertext),
  });
  const httpMs = performance.now() - httpStart;

  if (!response.ok) {
    const error = await response.text();
    throw new Error(`Purchase failed: ${response.status} - ${error}`);
  }

  // Get Server-Timing header
  const serverTiming = response.headers.get("Server-Timing") ?? undefined;

  if (verbose) {
    console.log(`\n  📥 Received encrypted response (status: ${response.status})`);
  }

  // Extract response headers
  const respKid = response.headers.get("X-Kid");
  const respEncAlg = response.headers.get("X-Enc-Alg");
  const respIvB64 = response.headers.get("X-IV");
  const respTagB64 = response.headers.get("X-Tag");
  const respAadB64 = response.headers.get("X-AAD");

  if (verbose) {
    console.log("     Response headers:");
    console.log(`       X-Kid: ${respKid}`);
    console.log(`       X-Enc-Alg: ${respEncAlg}`);
    console.log(`       X-IV: ${respIvB64?.slice(0, 20)}...`);
    console.log(`       X-Tag: ${respTagB64?.slice(0, 20)}...`);
  }

  if (!respIvB64 || !respTagB64 || !respAadB64) {
    throw new Error("Missing encryption headers in response");
  }

  // Decode response crypto components
  const respIv = unb64(respIvB64);
  const respTag = unb64(respTagB64);
  const respAad = unb64(respAadB64);
  const respCiphertext = unb64(await response.text());

  if (verbose) {
    console.log("\n  🔓 Decrypting response...");
  }

  // Decrypt response
  const respPlaintext = measureSync("aes-gcm-decrypt", cryptoOps, () =>
    aesGcmDecrypt(session.sessionKey, respIv, respAad, respCiphertext, respTag)
  );

  // Parse decrypted JSON
  const responseData = JSON.parse(respPlaintext.toString("utf8"));

  if (verbose) {
    console.log("  ✅ Decryption successful!\n");
    console.log("  📋 Decrypted response:");
    console.log("  ─────────────────────────────────────────");
    console.log(JSON.stringify(responseData, null, 4));
    console.log("  ─────────────────────────────────────────");
  }

  return {
    endpoint: "/transaction/purchase",
    totalRoundTripMs: performance.now() - totalStart,
    httpRequestMs: httpMs,
    cryptoOperations: cryptoOps,
    serverTiming,
  };
}

// ===== Metrics Display =====
function printMetricsSummary(
  initMetrics: EndpointMetrics,
  purchaseMetrics: EndpointMetrics
): void {
  console.log(
    "\n================================================================================"
  );
  console.log("  Performance Metrics Summary");
  console.log(
    "================================================================================\n"
  );

  for (const metrics of [initMetrics, purchaseMetrics]) {
    console.log(`Endpoint: ${metrics.endpoint}`);
    console.log("-".repeat(40));
    console.log(
      `  Total Round-Trip:     ${metrics.totalRoundTripMs.toFixed(3)} ms`
    );
    console.log(`  HTTP Request Time:    ${metrics.httpRequestMs.toFixed(3)} ms`);

    console.log("\n  Client Crypto Operations:");
    for (const op of metrics.cryptoOperations) {
      console.log(`    - ${op.operation.padEnd(18)} ${op.durationMs.toFixed(3)} ms`);
    }

    if (metrics.serverTiming) {
      console.log("\n  Server Timing:");
      const serverOps = parseServerTiming(metrics.serverTiming);
      for (const op of serverOps) {
        console.log(`    - ${op.operation.padEnd(18)} ${op.durationMs.toFixed(3)} ms`);
      }
    }
    console.log("");
  }
}

// ===== Benchmark Mode =====
async function runBenchmark(iterations: number): Promise<void> {
  const warmup = 5;
  const initDurations: number[] = [];
  const purchaseDurations: number[] = [];
  const combinedDurations: number[] = [];

  console.log(
    "\n================================================================================"
  );
  console.log(`  Throughput Benchmark (${iterations} iterations, ${warmup} warmup)`);
  console.log(
    "================================================================================\n"
  );

  for (let i = 0; i < iterations + warmup; i++) {
    const flowStart = performance.now();

    const { session, metrics: initMetrics } = await initSession(false);
    const purchaseMetrics = await makePurchase(
      session,
      { schemeCode: "AEF", amount: 5000 },
      false
    );

    const flowDuration = performance.now() - flowStart;

    if (i >= warmup) {
      initDurations.push(initMetrics.totalRoundTripMs);
      purchaseDurations.push(purchaseMetrics.totalRoundTripMs);
      combinedDurations.push(flowDuration);
    }

    // Progress indicator
    if ((i + 1) % 10 === 0 || i === iterations + warmup - 1) {
      const progress = Math.min(i + 1 - warmup, iterations);
      process.stdout.write(
        `\r  Progress: ${progress}/${iterations} iterations completed`
      );
    }
  }

  console.log("\n");

  // Calculate and display statistics
  const initStats = calculateStats(initDurations);
  const purchaseStats = calculateStats(purchaseDurations);
  const combinedStats = calculateStats(combinedDurations);

  const printStats = (label: string, stats: BenchmarkStats): void => {
    console.log(`${label}:`);
    console.log(
      `  Throughput:    ${((1000 / stats.meanMs) * 1).toFixed(1)} req/s`
    );
    console.log(
      `  Latency:       Min: ${stats.minMs.toFixed(1)}ms | Max: ${stats.maxMs.toFixed(1)}ms | Mean: ${stats.meanMs.toFixed(1)}ms`
    );
    console.log(
      `                 P50: ${stats.p50Ms.toFixed(1)}ms | P95: ${stats.p95Ms.toFixed(1)}ms | P99: ${stats.p99Ms.toFixed(1)}ms`
    );
    console.log("");
  };

  printStats("/session/init", initStats);
  printStats("/transaction/purchase", purchaseStats);
  printStats("Combined (init + purchase)", combinedStats);
}

// ===== Main execution =====
async function main() {
  const args = process.argv.slice(2);
  const benchmarkIdx = args.indexOf("--benchmark");
  const isBenchmark = benchmarkIdx !== -1;
  const benchmarkIterations = isBenchmark
    ? parseInt(args[benchmarkIdx + 1] || "100", 10)
    : 0;

  console.log("═══════════════════════════════════════════════════════════════");
  console.log("  Session Crypto PoC - Node.js Client");
  console.log("═══════════════════════════════════════════════════════════════");
  console.log(`  Server: ${SERVER_URL}`);

  if (isBenchmark) {
    console.log(`  Mode: Benchmark (${benchmarkIterations} iterations)`);
  } else {
    console.log("  Mode: Single run with metrics");
  }

  try {
    if (isBenchmark) {
      await runBenchmark(benchmarkIterations);
    } else {
      // Normal single run with metrics
      const { session, metrics: initMetrics } = await initSession();
      const purchaseMetrics = await makePurchase(session, {
        schemeCode: "AEF",
        amount: 5000,
      });

      // Print metrics summary
      printMetricsSummary(initMetrics, purchaseMetrics);
    }

    console.log(
      "═══════════════════════════════════════════════════════════════"
    );
    console.log("  ✅ Completed successfully!");
    console.log(
      "═══════════════════════════════════════════════════════════════\n"
    );
  } catch (error) {
    console.error("\n❌ Error:", error);
    process.exit(1);
  }
}

main();
