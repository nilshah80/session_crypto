package com.example;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.Mac;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.*;
import java.util.*;
import java.util.concurrent.Executors;
import java.util.function.Supplier;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Java Virtual Threads client with performance metrics and benchmark mode.
 */
public class SessionCryptoClient {
    private static final String SERVER_URL = "http://localhost:3000";
    private static final ObjectMapper mapper = new ObjectMapper();

    // HttpClient using virtual threads
    private static final HttpClient httpClient = HttpClient.newBuilder()
        .executor(Executors.newVirtualThreadPerTaskExecutor())
        .build();

    // ===== Metrics Types =====
    record CryptoTiming(String operation, double durationMs) {}

    record EndpointMetrics(
        String endpoint,
        double totalRoundTripMs,
        double httpRequestMs,
        List<CryptoTiming> cryptoOperations,
        String serverTiming
    ) {}

    record BenchmarkStats(
        int count,
        double totalMs,
        double minMs,
        double maxMs,
        double meanMs,
        double p50Ms,
        double p95Ms,
        double p99Ms
    ) {}

    record InitResult(SessionContext session, EndpointMetrics metrics) {}

    // ===== Metrics Helpers =====
    static <T> T measureSync(String operation, List<CryptoTiming> timings, Supplier<T> fn) {
        long start = System.nanoTime();
        T result = fn.get();
        timings.add(new CryptoTiming(operation, (System.nanoTime() - start) / 1_000_000.0));
        return result;
    }

    static List<CryptoTiming> parseServerTiming(String header) {
        if (header == null || header.isEmpty()) return Collections.emptyList();
        List<CryptoTiming> timings = new ArrayList<>();
        Pattern durPattern = Pattern.compile("dur=([\\d.]+)");
        for (String part : header.split(",")) {
            String[] segments = part.trim().split(";");
            String name = segments[0].trim();
            double dur = 0.0;
            if (segments.length > 1) {
                Matcher m = durPattern.matcher(segments[1]);
                if (m.find()) {
                    dur = Double.parseDouble(m.group(1));
                }
            }
            timings.add(new CryptoTiming(name, dur));
        }
        return timings;
    }

    static BenchmarkStats calculateStats(List<Double> durations) {
        List<Double> sorted = new ArrayList<>(durations);
        Collections.sort(sorted);
        double sum = sorted.stream().mapToDouble(Double::doubleValue).sum();
        int len = sorted.size();

        return new BenchmarkStats(
            len,
            sum,
            sorted.get(0),
            sorted.get(len - 1),
            sum / len,
            sorted.get((int) (len * 0.5)),
            sorted.get((int) (len * 0.95)),
            sorted.get((int) (len * 0.99))
        );
    }

    public static void main(String[] args) {
        System.out.println("═══════════════════════════════════════════════════════════════");
        System.out.println("  Session Crypto PoC - Java Virtual Threads Client");
        System.out.println("═══════════════════════════════════════════════════════════════");
        System.out.println("  Server: " + SERVER_URL);

        // Parse benchmark flag
        boolean isBenchmark = false;
        int benchmarkIterations = 100;
        for (int i = 0; i < args.length; i++) {
            if ("--benchmark".equals(args[i]) && i + 1 < args.length) {
                isBenchmark = true;
                benchmarkIterations = Integer.parseInt(args[i + 1]);
            }
        }

        if (isBenchmark) {
            System.out.println("  Mode: Benchmark (" + benchmarkIterations + " iterations)");
        } else {
            System.out.println("  Mode: Single run with metrics");
        }

        final boolean runBenchmark = isBenchmark;
        final int iterations = benchmarkIterations;

        // Run in a virtual thread
        try {
            Thread.startVirtualThread(() -> {
                try {
                    if (runBenchmark) {
                        runBenchmark(iterations);
                    } else {
                        // Single run with metrics
                        InitResult initResult = initSession(true);
                        EndpointMetrics purchaseMetrics = makePurchase(
                            initResult.session(),
                            new PurchaseRequest("AEF", 5000),
                            true
                        );
                        printMetricsSummary(initResult.metrics(), purchaseMetrics);
                    }

                    System.out.println("═══════════════════════════════════════════════════════════════");
                    System.out.println("  ✅ Completed successfully!");
                    System.out.println("═══════════════════════════════════════════════════════════════\n");
                } catch (Exception e) {
                    System.out.println("\n❌ Error: " + e.getMessage());
                    e.printStackTrace();
                    System.exit(1);
                }
            }).join();
        } catch (InterruptedException e) {
            System.out.println("\n❌ Error: Thread interrupted");
            System.exit(1);
        }
    }

    static InitResult initSession(boolean verbose) throws Exception {
        long totalStart = System.nanoTime();
        List<CryptoTiming> cryptoOps = new ArrayList<>();

        if (verbose) {
            System.out.println("\n📡 Step 1: Initializing session with server...\n");
        }

        // Generate client ECDH keypair (P-256)
        KeyPair clientKeyPair = measureSync("ecdh-keygen", cryptoOps, () -> {
            try {
                KeyPairGenerator keyGen = KeyPairGenerator.getInstance("EC");
                keyGen.initialize(new ECGenParameterSpec("secp256r1"));
                return keyGen.generateKeyPair();
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
        });

        byte[] clientPubRaw = extractRawPublicKey(clientKeyPair.getPublic());
        if (verbose) {
            System.out.println("  ✅ Generated client ECDH keypair");
            System.out.println("     Public key (first 32 chars): " +
                Base64.getEncoder().encodeToString(clientPubRaw).substring(0, 32) + "...");
        }

        String nonce = UUID.randomUUID().toString();
        String timestamp = String.valueOf(System.currentTimeMillis());

        if (verbose) {
            System.out.println("\n  📤 Sending POST /session/init");
            System.out.println("     X-Nonce: " + nonce);
            System.out.println("     X-Timestamp: " + timestamp);
        }

        SessionInitRequest requestBody = new SessionInitRequest(
            "ECDH_P256",
            Base64.getEncoder().encodeToString(clientPubRaw),
            1800
        );

        HttpRequest request = HttpRequest.newBuilder()
            .uri(URI.create(SERVER_URL + "/session/init"))
            .header("Content-Type", "application/json")
            .header("X-Nonce", nonce)
            .header("X-Timestamp", timestamp)
            .POST(HttpRequest.BodyPublishers.ofString(mapper.writeValueAsString(requestBody)))
            .build();

        long httpStart = System.nanoTime();
        HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
        double httpMs = (System.nanoTime() - httpStart) / 1_000_000.0;

        if (response.statusCode() != 200) {
            throw new RuntimeException("Session init failed: " + response.statusCode() + " - " + response.body());
        }

        String serverTiming = response.headers().firstValue("Server-Timing").orElse(null);
        SessionInitResponse data = mapper.readValue(response.body(), SessionInitResponse.class);

        if (verbose) {
            System.out.println("\n  📥 Received response:");
            System.out.println("     Session ID: " + data.sessionId);
            System.out.println("     Encryption: " + data.encAlg);
            System.out.println("     Expires in: " + data.expiresInSec + " seconds");
            System.out.println("     Server public key (first 32 chars): " +
                data.serverPublicKey.substring(0, 32) + "...");
        }

        // Import server public key
        byte[] serverPubRaw = Base64.getDecoder().decode(data.serverPublicKey);
        PublicKey serverPubKey = importRawPublicKey(serverPubRaw);

        // Compute shared secret
        byte[] sharedSecret = measureSync("ecdh-compute", cryptoOps, () -> {
            try {
                KeyAgreement keyAgreement = KeyAgreement.getInstance("ECDH");
                keyAgreement.init(clientKeyPair.getPrivate());
                keyAgreement.doPhase(serverPubKey, true);
                return keyAgreement.generateSecret();
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
        });

        if (verbose) {
            System.out.println("\n  🔐 Computed ECDH shared secret");
        }

        // Derive session key using HKDF
        byte[] salt = data.sessionId.getBytes(StandardCharsets.UTF_8);
        byte[] info = "SESSION|A256GCM|AUTH".getBytes(StandardCharsets.UTF_8);
        byte[] sessionKey = measureSync("hkdf", cryptoOps, () -> {
            try {
                return hkdf(sharedSecret, salt, info, 32);
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
        });

        if (verbose) {
            System.out.println("  🔑 Derived session key using HKDF-SHA256");
            System.out.println("     Session key (first 16 chars): " +
                Base64.getEncoder().encodeToString(sessionKey).substring(0, 16) + "...");
        }

        EndpointMetrics metrics = new EndpointMetrics(
            "/session/init",
            (System.nanoTime() - totalStart) / 1_000_000.0,
            httpMs,
            cryptoOps,
            serverTiming
        );

        return new InitResult(
            new SessionContext(data.sessionId, sessionKey, "session:" + data.sessionId),
            metrics
        );
    }

    static EndpointMetrics makePurchase(SessionContext session, PurchaseRequest purchaseData, boolean verbose) throws Exception {
        long totalStart = System.nanoTime();
        List<CryptoTiming> cryptoOps = new ArrayList<>();

        if (verbose) {
            System.out.println("\n📡 Step 2: Making encrypted purchase request...\n");
        }

        byte[] plaintext = mapper.writeValueAsBytes(purchaseData);
        if (verbose) {
            System.out.println("  📝 Request payload:");
            System.out.println("     " + mapper.writeValueAsString(purchaseData));
        }

        // Generate IV and nonce
        byte[] iv = new byte[12];
        SecureRandom.getInstanceStrong().nextBytes(iv);
        String nonce = UUID.randomUUID().toString();
        String timestamp = String.valueOf(System.currentTimeMillis());

        // Build AAD
        String aadStr = "POST|/transaction/purchase|" + timestamp + "|" + nonce + "|" + session.kid;
        byte[] aad = aadStr.getBytes(StandardCharsets.UTF_8);

        if (verbose) {
            System.out.println("\n  🔒 Encrypting request...");
            System.out.println("     IV (base64): " + Base64.getEncoder().encodeToString(iv));
            System.out.println("     AAD: POST|/transaction/purchase|" + timestamp + "|" +
                nonce.substring(0, 8) + "...|session:" + session.sessionId.substring(0, 8) + "...");
        }

        // Encrypt with AES-256-GCM
        byte[][] encResult = measureSync("aes-gcm-encrypt", cryptoOps, () -> {
            try {
                Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
                SecretKeySpec keySpec = new SecretKeySpec(session.sessionKey, "AES");
                GCMParameterSpec gcmSpec = new GCMParameterSpec(128, iv);
                cipher.init(Cipher.ENCRYPT_MODE, keySpec, gcmSpec);
                cipher.updateAAD(aad);
                byte[] ciphertextWithTag = cipher.doFinal(plaintext);

                // Split ciphertext and tag (tag is last 16 bytes)
                byte[] ciphertext = new byte[ciphertextWithTag.length - 16];
                byte[] tag = new byte[16];
                System.arraycopy(ciphertextWithTag, 0, ciphertext, 0, ciphertext.length);
                System.arraycopy(ciphertextWithTag, ciphertext.length, tag, 0, 16);
                return new byte[][] { ciphertext, tag };
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
        });

        byte[] ciphertext = encResult[0];
        byte[] tag = encResult[1];

        if (verbose) {
            System.out.println("     Ciphertext length: " + ciphertext.length + " bytes");
            System.out.println("     Auth tag (base64): " + Base64.getEncoder().encodeToString(tag));
            System.out.println("\n  📤 Sending encrypted POST /transaction/purchase");
        }

        HttpRequest request = HttpRequest.newBuilder()
            .uri(URI.create(SERVER_URL + "/transaction/purchase"))
            .header("Content-Type", "application/octet-stream")
            .header("X-Kid", session.kid)
            .header("X-Enc-Alg", "A256GCM")
            .header("X-IV", Base64.getEncoder().encodeToString(iv))
            .header("X-Tag", Base64.getEncoder().encodeToString(tag))
            .header("X-AAD", Base64.getEncoder().encodeToString(aad))
            .header("X-Nonce", nonce)
            .header("X-Timestamp", timestamp)
            .POST(HttpRequest.BodyPublishers.ofString(Base64.getEncoder().encodeToString(ciphertext)))
            .build();

        long httpStart = System.nanoTime();
        HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
        double httpMs = (System.nanoTime() - httpStart) / 1_000_000.0;

        if (response.statusCode() != 200) {
            throw new RuntimeException("Purchase failed: " + response.statusCode() + " - " + response.body());
        }

        String serverTiming = response.headers().firstValue("Server-Timing").orElse(null);

        if (verbose) {
            System.out.println("\n  📥 Received encrypted response (status: " + response.statusCode() + ")");
        }

        // Extract response headers
        String respIvB64 = response.headers().firstValue("X-IV").orElseThrow();
        String respTagB64 = response.headers().firstValue("X-Tag").orElseThrow();
        String respAadB64 = response.headers().firstValue("X-AAD").orElseThrow();

        if (verbose) {
            System.out.println("     Response headers:");
            System.out.println("       X-Kid: " + response.headers().firstValue("X-Kid").orElse(""));
            System.out.println("       X-Enc-Alg: " + response.headers().firstValue("X-Enc-Alg").orElse(""));
            System.out.println("       X-IV: " + respIvB64.substring(0, 16) + "...");
            System.out.println("       X-Tag: " + respTagB64.substring(0, 20) + "...");
            System.out.println("\n  🔓 Decrypting response...");
        }

        // Decode and decrypt response
        byte[] respIv = Base64.getDecoder().decode(respIvB64);
        byte[] respTag = Base64.getDecoder().decode(respTagB64);
        byte[] respAad = Base64.getDecoder().decode(respAadB64);
        byte[] respCiphertext = Base64.getDecoder().decode(response.body());

        byte[] respPlaintext = measureSync("aes-gcm-decrypt", cryptoOps, () -> {
            try {
                // Combine ciphertext and tag for decryption
                byte[] respCiphertextWithTag = new byte[respCiphertext.length + respTag.length];
                System.arraycopy(respCiphertext, 0, respCiphertextWithTag, 0, respCiphertext.length);
                System.arraycopy(respTag, 0, respCiphertextWithTag, respCiphertext.length, respTag.length);

                Cipher decCipher = Cipher.getInstance("AES/GCM/NoPadding");
                SecretKeySpec decKeySpec = new SecretKeySpec(session.sessionKey, "AES");
                GCMParameterSpec decGcmSpec = new GCMParameterSpec(128, respIv);
                decCipher.init(Cipher.DECRYPT_MODE, decKeySpec, decGcmSpec);
                decCipher.updateAAD(respAad);
                return decCipher.doFinal(respCiphertextWithTag);
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
        });

        if (verbose) {
            JsonNode responseData = mapper.readTree(respPlaintext);
            System.out.println("  ✅ Decryption successful!\n");
            System.out.println("  📋 Decrypted response:");
            System.out.println("  ─────────────────────────────────────────");
            System.out.println(mapper.writerWithDefaultPrettyPrinter().writeValueAsString(responseData));
            System.out.println("  ─────────────────────────────────────────");
        }

        return new EndpointMetrics(
            "/transaction/purchase",
            (System.nanoTime() - totalStart) / 1_000_000.0,
            httpMs,
            cryptoOps,
            serverTiming
        );
    }

    // ===== Metrics Display =====
    static void printMetricsSummary(EndpointMetrics initMetrics, EndpointMetrics purchaseMetrics) {
        System.out.println("\n================================================================================");
        System.out.println("  Performance Metrics Summary");
        System.out.println("================================================================================\n");

        for (EndpointMetrics metrics : List.of(initMetrics, purchaseMetrics)) {
            System.out.println("Endpoint: " + metrics.endpoint);
            System.out.println("-".repeat(40));
            System.out.printf("  Total Round-Trip:     %.3f ms%n", metrics.totalRoundTripMs);
            System.out.printf("  HTTP Request Time:    %.3f ms%n", metrics.httpRequestMs);

            System.out.println("\n  Client Crypto Operations:");
            for (CryptoTiming op : metrics.cryptoOperations) {
                System.out.printf("    - %-18s %.3f ms%n", op.operation, op.durationMs);
            }

            if (metrics.serverTiming != null && !metrics.serverTiming.isEmpty()) {
                System.out.println("\n  Server Timing:");
                for (CryptoTiming op : parseServerTiming(metrics.serverTiming)) {
                    System.out.printf("    - %-18s %.3f ms%n", op.operation, op.durationMs);
                }
            }
            System.out.println();
        }
    }

    // ===== Benchmark Mode =====
    static void runBenchmark(int iterations) throws Exception {
        int warmup = 5;
        List<Double> initDurations = new ArrayList<>();
        List<Double> purchaseDurations = new ArrayList<>();
        List<Double> combinedDurations = new ArrayList<>();

        System.out.println("\n================================================================================");
        System.out.printf("  Throughput Benchmark (%d iterations, %d warmup)%n", iterations, warmup);
        System.out.println("================================================================================\n");

        for (int i = 0; i < iterations + warmup; i++) {
            long flowStart = System.nanoTime();

            InitResult initResult = initSession(false);
            EndpointMetrics purchaseMetrics = makePurchase(
                initResult.session(),
                new PurchaseRequest("AEF", 5000),
                false
            );

            double flowDuration = (System.nanoTime() - flowStart) / 1_000_000.0;

            if (i >= warmup) {
                initDurations.add(initResult.metrics().totalRoundTripMs);
                purchaseDurations.add(purchaseMetrics.totalRoundTripMs);
                combinedDurations.add(flowDuration);
            }

            // Progress indicator
            if ((i + 1) % 10 == 0 || i == iterations + warmup - 1) {
                int progress = Math.min(i + 1 - warmup, iterations);
                System.out.printf("\r  Progress: %d/%d iterations completed", progress, iterations);
            }
        }

        System.out.println("\n");

        // Calculate and display statistics
        BenchmarkStats initStats = calculateStats(initDurations);
        BenchmarkStats purchaseStats = calculateStats(purchaseDurations);
        BenchmarkStats combinedStats = calculateStats(combinedDurations);

        printStats("/session/init", initStats);
        printStats("/transaction/purchase", purchaseStats);
        printStats("Combined (init + purchase)", combinedStats);
    }

    static void printStats(String label, BenchmarkStats stats) {
        System.out.println(label + ":");
        System.out.printf("  Throughput:    %.1f req/s%n", 1000.0 / stats.meanMs);
        System.out.printf("  Latency:       Min: %.1fms | Max: %.1fms | Mean: %.1fms%n",
            stats.minMs, stats.maxMs, stats.meanMs);
        System.out.printf("                 P50: %.1fms | P95: %.1fms | P99: %.1fms%n",
            stats.p50Ms, stats.p95Ms, stats.p99Ms);
        System.out.println();
    }

    // Extract raw 65-byte uncompressed public key from ECPublicKey
    static byte[] extractRawPublicKey(PublicKey publicKey) {
        if (publicKey instanceof java.security.interfaces.ECPublicKey ecPub) {
            var point = ecPub.getW();
            byte[] x = point.getAffineX().toByteArray();
            byte[] y = point.getAffineY().toByteArray();

            byte[] xBytes = new byte[32];
            byte[] yBytes = new byte[32];

            if (x.length > 32) {
                System.arraycopy(x, x.length - 32, xBytes, 0, 32);
            } else {
                System.arraycopy(x, 0, xBytes, 32 - x.length, x.length);
            }

            if (y.length > 32) {
                System.arraycopy(y, y.length - 32, yBytes, 0, 32);
            } else {
                System.arraycopy(y, 0, yBytes, 32 - y.length, y.length);
            }

            byte[] result = new byte[65];
            result[0] = 0x04;
            System.arraycopy(xBytes, 0, result, 1, 32);
            System.arraycopy(yBytes, 0, result, 33, 32);
            return result;
        }
        throw new IllegalArgumentException("Not an EC public key");
    }

    // Import raw 65-byte public key
    static PublicKey importRawPublicKey(byte[] rawKey) throws Exception {
        if (rawKey.length != 65 || rawKey[0] != 0x04) {
            throw new IllegalArgumentException("Invalid raw public key format");
        }

        byte[] x = new byte[32];
        byte[] y = new byte[32];
        System.arraycopy(rawKey, 1, x, 0, 32);
        System.arraycopy(rawKey, 33, y, 0, 32);

        ECPoint point = new ECPoint(
            new java.math.BigInteger(1, x),
            new java.math.BigInteger(1, y)
        );

        AlgorithmParameters params = AlgorithmParameters.getInstance("EC");
        params.init(new ECGenParameterSpec("secp256r1"));
        ECParameterSpec ecSpec = params.getParameterSpec(ECParameterSpec.class);

        ECPublicKeySpec pubKeySpec = new ECPublicKeySpec(point, ecSpec);
        KeyFactory keyFactory = KeyFactory.getInstance("EC");
        return keyFactory.generatePublic(pubKeySpec);
    }

    // HKDF implementation
    static byte[] hkdf(byte[] ikm, byte[] salt, byte[] info, int length) throws Exception {
        // Extract
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(new SecretKeySpec(salt.length > 0 ? salt : new byte[32], "HmacSHA256"));
        byte[] prk = mac.doFinal(ikm);

        // Expand
        byte[] result = new byte[length];
        byte[] t = new byte[0];
        int offset = 0;
        int counter = 1;

        while (offset < length) {
            mac.init(new SecretKeySpec(prk, "HmacSHA256"));
            mac.update(t);
            mac.update(info);
            mac.update((byte) counter);
            t = mac.doFinal();

            int toCopy = Math.min(t.length, length - offset);
            System.arraycopy(t, 0, result, offset, toCopy);
            offset += toCopy;
            counter++;
        }

        return result;
    }

    // Records for request/response
    record SessionInitRequest(
        @JsonProperty("keyAgreement") String keyAgreement,
        @JsonProperty("clientPublicKey") String clientPublicKey,
        @JsonProperty("ttlSec") int ttlSec
    ) {}

    record SessionInitResponse(
        @JsonProperty("sessionId") String sessionId,
        @JsonProperty("serverPublicKey") String serverPublicKey,
        @JsonProperty("encAlg") String encAlg,
        @JsonProperty("expiresInSec") int expiresInSec
    ) {}

    record PurchaseRequest(
        @JsonProperty("schemeCode") String schemeCode,
        @JsonProperty("amount") int amount
    ) {}

    record SessionContext(String sessionId, byte[] sessionKey, String kid) {}
}
