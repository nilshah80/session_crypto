package com.example;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.Mac;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.*;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import com.amazon.corretto.crypto.provider.AmazonCorrettoCryptoProvider;

import reactor.core.publisher.Mono;
import reactor.core.scheduler.Schedulers;
import reactor.netty.http.client.HttpClient;
import reactor.netty.http.client.HttpClientResponse;
import io.netty.handler.codec.http.HttpHeaderNames;
import io.netty.handler.codec.http.HttpHeaderValues;
import io.netty.handler.codec.http.HttpMethod;

/**
 * Java WebFlux-style client with PROPER reactive programming using Project Reactor.
 * Uses Mono/Flux reactive streams with reactor-netty for truly reactive HTTP.
 * Optimized with cipher reuse, buffer pooling, and ACCP native crypto.
 */
public class SessionCryptoClient {
    // Install ACCP as the highest priority security provider (with fallback)
    static {
        try {
            AmazonCorrettoCryptoProvider.install();
            System.out.println("✓ Amazon Corretto Crypto Provider (ACCP) installed");
        } catch (Exception | NoClassDefFoundError e) {
            System.out.println("⚠ Amazon Corretto Crypto Provider (ACCP) not available, using default JCA");
            System.out.println("  Install ACCP for 10-50x better crypto performance");
        }

        // OPTIMIZATION: Pre-warm crypto operations to avoid first-call JIT penalty
        try {
            KeyPairGenerator warmupGen = KeyPairGenerator.getInstance("EC");
            warmupGen.initialize(new ECGenParameterSpec("secp256r1"));
            KeyPair warmupPair = warmupGen.generateKeyPair();

            Cipher warmupCipher = Cipher.getInstance("AES/GCM/NoPadding");
            SecretKeySpec warmupKey = new SecretKeySpec(new byte[32], "AES");
            GCMParameterSpec warmupSpec = new GCMParameterSpec(128, new byte[12]);
            warmupCipher.init(Cipher.ENCRYPT_MODE, warmupKey, warmupSpec);
            warmupCipher.doFinal(new byte[16]);

            System.out.println("✓ Crypto operations pre-warmed");
        } catch (Exception e) {
            System.err.println("Warning: Crypto pre-warming failed: " + e.getMessage());
        }
    }

    private static final String SERVER_URL = "http://localhost:3000";
    private static final String CLIENT_ID = "JAVA_REACTIVE_CLIENT_ACCP";
    private static final ObjectMapper mapper = new ObjectMapper();

    // Shared SecureRandom instance (thread-safe)
    private static final SecureRandom secureRandom = new SecureRandom();

    // OPTIMIZATION: ThreadLocal buffer pools to reduce GC pressure
    private static final ThreadLocal<byte[]> IV_POOL = ThreadLocal.withInitial(() -> new byte[12]);
    private static final ThreadLocal<byte[]> TEMP_BUFFER = ThreadLocal.withInitial(() -> new byte[8192]);

    // REACTIVE: reactor-netty HTTP client with timeouts
    private static final HttpClient httpClient = HttpClient.create()
        .compress(true)
        .responseTimeout(java.time.Duration.ofSeconds(30))
        .option(io.netty.channel.ChannelOption.CONNECT_TIMEOUT_MILLIS, 15000);

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

    // Helper classes for passing data through reactive chains
    static class InitData {
        KeyPair clientKeyPair;
        byte[] clientPubRaw;
        String nonce;
        String timestamp;
        String requestId;
        List<CryptoTiming> cryptoOps = new ArrayList<>();
        long totalStart = System.nanoTime();
    }

    static class InitResponseData {
        InitData initData;
        String responseBody;
        double httpMs;
        String serverTiming;

        InitResponseData(InitData initData, String responseBody, double httpMs, String serverTiming) {
            this.initData = initData;
            this.responseBody = responseBody;
            this.httpMs = httpMs;
            this.serverTiming = serverTiming;
        }
    }

    static class EncryptData {
        byte[] plaintext;
        String nonce;
        String timestamp;
        String requestId;
        byte[] aad;
        byte[] encryptedBody;
        List<CryptoTiming> cryptoOps = new ArrayList<>();
        long totalStart = System.nanoTime();
    }

    static class PurchaseResponseData {
        EncryptData encryptData;
        byte[] responseBody;
        double httpMs;
        String serverTiming;
        String respKid;
        String respRequestId;

        PurchaseResponseData(EncryptData encryptData, byte[] responseBody, double httpMs,
                           String serverTiming, String respKid, String respRequestId) {
            this.encryptData = encryptData;
            this.responseBody = responseBody;
            this.httpMs = httpMs;
            this.serverTiming = serverTiming;
            this.respKid = respKid;
            this.respRequestId = respRequestId;
        }
    }

    // OPTIMIZATION: Session context with cached Cipher instances for reuse
    static class SessionContext implements AutoCloseable {
        final String sessionId;
        final byte[] sessionKey;
        final String kid;
        final String clientId;
        final Cipher encryptCipher;
        final Cipher decryptCipher;
        final SecretKeySpec keySpec;

        SessionContext(String sessionId, byte[] sessionKey, String kid, String clientId) throws Exception {
            this.sessionId = sessionId;
            this.sessionKey = sessionKey;
            this.kid = kid;
            this.clientId = clientId;
            this.keySpec = new SecretKeySpec(sessionKey, "AES");

            // OPTIMIZATION: Pre-create and cache Cipher instances per session
            this.encryptCipher = Cipher.getInstance("AES/GCM/NoPadding");
            this.decryptCipher = Cipher.getInstance("AES/GCM/NoPadding");
        }

        @Override
        public void close() {
            // Clear sensitive data
            Arrays.fill(sessionKey, (byte) 0);
        }
    }

    // ===== Metrics Helpers =====
    static <T> T measureSync(String operation, List<CryptoTiming> timings, ThrowingSupplier<T> fn) throws Exception {
        long start = System.nanoTime();
        T result = fn.get();
        timings.add(new CryptoTiming(operation, (System.nanoTime() - start) / 1_000_000.0));
        return result;
    }

    @FunctionalInterface
    interface ThrowingSupplier<T> {
        T get() throws Exception;
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
        System.out.println("  Session Crypto PoC - Java Reactive WebFlux Client");
        System.out.println("═══════════════════════════════════════════════════════════════");
        System.out.println("  Server: " + SERVER_URL);
        System.out.println("  Using: Project Reactor (Mono/Flux) + reactor-netty");

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

        // REACTIVE: Chain operations using Mono
        if (runBenchmark) {
            runBenchmarkReactive(iterations)
                .doOnSuccess(v -> {
                    System.out.println("═══════════════════════════════════════════════════════════════");
                    System.out.println("  ✅ Benchmark completed successfully!");
                    System.out.println("═══════════════════════════════════════════════════════════════\n");
                })
                .doOnError(e -> {
                    System.out.println("\n❌ Error: " + e.getMessage());
                    e.printStackTrace();
                })
                .block();  // Block to wait for completion
        } else {
            initSessionReactive(true)
                .flatMap(initResult -> {
                    // SECURITY: Ensure session is closed after use
                    return makePurchaseReactive(initResult.session(), new PurchaseRequest("AEF", 5000), true)
                        .map(purchaseMetrics -> new EndpointMetrics[] { initResult.metrics(), purchaseMetrics })
                        .doFinally(signal -> initResult.session().close());
                })
                .doOnSuccess(metrics -> {
                    printMetricsSummary(metrics[0], metrics[1]);
                    System.out.println("═══════════════════════════════════════════════════════════════");
                    System.out.println("  ✅ Completed successfully!");
                    System.out.println("═══════════════════════════════════════════════════════════════\n");
                })
                .doOnError(e -> {
                    System.out.println("\n❌ Error: " + e.getMessage());
                    e.printStackTrace();
                })
                .block();  // Block to wait for completion
        }
    }

    // REACTIVE: Initialize session using Mono reactive streams
    static Mono<InitResult> initSessionReactive(boolean verbose) {
        // REACTIVE CHAIN: Generate keypair -> Build request -> HTTP call -> Process response
        return Mono.fromCallable(() -> {
            InitData data = new InitData();

            if (verbose) {
                System.out.println("\n📡 Step 1: Initializing session with server...\n");
            }

            // Generate client ECDH keypair (P-256)
            data.clientKeyPair = measureSync("ecdh-keygen", data.cryptoOps, () -> {
                KeyPairGenerator keyGen = KeyPairGenerator.getInstance("EC");
                keyGen.initialize(new ECGenParameterSpec("secp256r1"));
                return keyGen.generateKeyPair();
            });

            data.clientPubRaw = extractRawPublicKey(data.clientKeyPair.getPublic());

            if (verbose) {
                System.out.println("  ✅ Generated client ECDH keypair");
                System.out.println("     Public key (first 32 chars): " +
                    Base64.getEncoder().encodeToString(data.clientPubRaw).substring(0, 32) + "...");
            }

            data.nonce = UUID.randomUUID().toString();
            data.timestamp = String.valueOf(System.currentTimeMillis());
            data.requestId = data.timestamp + "." + data.nonce;

            if (verbose) {
                System.out.println("\n  📤 Sending POST /session/init (reactive)");
                System.out.println("     X-Idempotency-Key: " + data.requestId);
                System.out.println("     X-ClientId: " + CLIENT_ID);
            }

            return data;
        })
        .subscribeOn(Schedulers.parallel())  // Run crypto on parallel scheduler
        .flatMap(data -> {
            // REACTIVE HTTP CALL using reactor-netty
            try {
                SessionInitRequest requestBody = new SessionInitRequest(
                    Base64.getEncoder().encodeToString(data.clientPubRaw),
                    1800
                );

                String jsonBody = mapper.writeValueAsString(requestBody);
                byte[] bodyBytes = jsonBody.getBytes(StandardCharsets.UTF_8);

                long httpStart = System.nanoTime();

                return httpClient
                    .headers(h -> {
                        h.set(HttpHeaderNames.CONTENT_TYPE, HttpHeaderValues.APPLICATION_JSON);
                        h.set("X-Idempotency-Key", data.requestId);
                        h.set("X-ClientId", CLIENT_ID);
                    })
                    .request(HttpMethod.POST)
                    .uri(SERVER_URL + "/session/init")
                    .send((req, out) -> out.sendByteArray(Mono.just(bodyBytes)))
                    .responseSingle((response, body) -> {
                        double httpMs = (System.nanoTime() - httpStart) / 1_000_000.0;

                        if (response.status().code() != 200) {
                            return body.asString().flatMap(err ->
                                Mono.error(new RuntimeException("Session init failed: " + response.status() + " - " + err))
                            );
                        }

                        String serverTiming = response.responseHeaders().get("Server-Timing");

                        return body.asString().map(responseBody -> {
                            return new InitResponseData(data, responseBody, httpMs, serverTiming);
                        });
                    });
            } catch (Exception e) {
                return Mono.error(e);
            }
        })
        .flatMap(responseData -> Mono.fromCallable(() -> {
            // Process response and compute shared secret (CPU-bound)
            InitData data = responseData.initData;

            SessionInitResponse sessionData = mapper.readValue(responseData.responseBody, SessionInitResponse.class);

            if (verbose) {
                System.out.println("\n  📥 Received response:");
                System.out.println("     Session ID: " + sessionData.sessionId);
                System.out.println("     Encryption: " + sessionData.encAlg);
                System.out.println("     Expires in: " + sessionData.expiresInSec + " seconds");
                System.out.println("     Server public key (first 32 chars): " +
                    sessionData.serverPublicKey.substring(0, 32) + "...");
            }

            // Import server public key
            byte[] serverPubRaw = Base64.getDecoder().decode(sessionData.serverPublicKey);
            PublicKey serverPubKey = importRawPublicKey(serverPubRaw);

            // Compute shared secret
            byte[] sharedSecret = measureSync("ecdh-compute", data.cryptoOps, () -> {
                KeyAgreement keyAgreement = KeyAgreement.getInstance("ECDH");
                keyAgreement.init(data.clientKeyPair.getPrivate());
                keyAgreement.doPhase(serverPubKey, true);
                return keyAgreement.generateSecret();
            });

            if (verbose) {
                System.out.println("\n  🔐 Computed ECDH shared secret");
            }

            // Derive session key using HKDF
            byte[] salt = sessionData.sessionId.getBytes(StandardCharsets.UTF_8);
            byte[] info = ("SESSION|A256GCM|" + CLIENT_ID).getBytes(StandardCharsets.UTF_8);
            byte[] sessionKey = measureSync("hkdf", data.cryptoOps, () -> {
                return hkdf(sharedSecret, salt, info, 32);
            });

            if (verbose) {
                System.out.println("  🔑 Derived session key using HKDF-SHA256");
                System.out.println("     Session key (first 16 chars): " +
                    Base64.getEncoder().encodeToString(sessionKey).substring(0, 16) + "...");
            }

            EndpointMetrics metrics = new EndpointMetrics(
                "/session/init",
                (System.nanoTime() - data.totalStart) / 1_000_000.0,
                responseData.httpMs,
                data.cryptoOps,
                responseData.serverTiming
            );

            return new InitResult(
                new SessionContext(sessionData.sessionId, sessionKey, "session:" + sessionData.sessionId, CLIENT_ID),
                metrics
            );
        }).subscribeOn(Schedulers.parallel()));  // Run crypto on parallel scheduler
    }

    // REACTIVE: Make purchase using Mono reactive streams
    static Mono<EndpointMetrics> makePurchaseReactive(SessionContext session, PurchaseRequest purchaseData, boolean verbose) {
        return Mono.fromCallable(() -> {
            EncryptData data = new EncryptData();

            if (verbose) {
                System.out.println("\n📡 Step 2: Making encrypted purchase request...\n");
            }

            data.plaintext = mapper.writeValueAsBytes(purchaseData);
            if (verbose) {
                System.out.println("  📝 Request payload:");
                System.out.println("     " + mapper.writeValueAsString(purchaseData));
            }

            // Generate nonce and timestamp for replay protection
            data.nonce = UUID.randomUUID().toString();
            data.timestamp = String.valueOf(System.currentTimeMillis());
            data.requestId = data.timestamp + "." + data.nonce;

            // Build AAD: TIMESTAMP|NONCE|KID|CLIENTID
            String aadStr = data.timestamp + "|" + data.nonce + "|" + session.kid + "|" + session.clientId;
            data.aad = aadStr.getBytes(StandardCharsets.UTF_8);

            if (verbose) {
                System.out.println("\n  🔒 Encrypting request...");
                System.out.println("     AAD: " + data.timestamp + "|" +
                    data.nonce.substring(0, 8) + "...|session:" + session.sessionId.substring(0, 8) + "...|" + session.clientId);
            }

            // OPTIMIZATION: Encrypt with reused Cipher instance (synchronized for thread safety)
            data.encryptedBody = measureSync("aes-gcm-encrypt", data.cryptoOps, () -> {
                byte[] iv = IV_POOL.get();
                try {
                    secureRandom.nextBytes(iv);

                    synchronized (session.encryptCipher) {
                        GCMParameterSpec gcmSpec = new GCMParameterSpec(128, iv);
                        session.encryptCipher.init(Cipher.ENCRYPT_MODE, session.keySpec, gcmSpec);
                        session.encryptCipher.updateAAD(data.aad);
                        byte[] ciphertextWithTag = session.encryptCipher.doFinal(data.plaintext);

                        // Concatenate: IV (12) || ciphertext || tag
                        byte[] result = new byte[12 + ciphertextWithTag.length];
                        System.arraycopy(iv, 0, result, 0, 12);
                        System.arraycopy(ciphertextWithTag, 0, result, 12, ciphertextWithTag.length);
                        return result;
                    }
                } finally {
                    // SECURITY: Clear IV from ThreadLocal buffer
                    Arrays.fill(iv, (byte) 0);
                }
            });

            if (verbose) {
                System.out.println("     Encrypted body length: " + data.encryptedBody.length + " bytes (IV + ciphertext + tag)");
                System.out.println("\n  📤 Sending encrypted POST /transaction/purchase (reactive)");
            }

            return data;
        })
        .subscribeOn(Schedulers.parallel())  // Run crypto on parallel scheduler
        .flatMap(data -> {
            // REACTIVE HTTP CALL
            byte[] bodyBytes = data.encryptedBody;
            long httpStart = System.nanoTime();

            return httpClient
                .headers(h -> {
                    h.set(HttpHeaderNames.CONTENT_TYPE, "application/octet-stream");
                    h.set("X-Kid", session.kid);
                    h.set("X-Idempotency-Key", data.requestId);
                    h.set("X-ClientId", session.clientId);
                })
                .request(HttpMethod.POST)
                .uri(SERVER_URL + "/transaction/purchase")
                .send((req, out) -> out.sendByteArray(Mono.just(bodyBytes)))
                .responseSingle((response, body) -> {
                    double httpMs = (System.nanoTime() - httpStart) / 1_000_000.0;

                    if (response.status().code() != 200) {
                        return body.asString().flatMap(err ->
                            Mono.error(new RuntimeException("Purchase failed: " + response.status() + " - " + err))
                        );
                    }

                    String serverTiming = response.responseHeaders().get("Server-Timing");
                    String respKid = Optional.ofNullable(response.responseHeaders().get("X-Kid"))
                        .orElseThrow(() -> new RuntimeException("Missing required X-Kid header in response"));
                    String respRequestId = Optional.ofNullable(response.responseHeaders().get("X-Idempotency-Key"))
                        .orElseThrow(() -> new RuntimeException("Missing required X-Idempotency-Key header in response"));

                    return body.asByteArray().map(responseBody -> {
                        return new PurchaseResponseData(data, responseBody, httpMs, serverTiming, respKid, respRequestId);
                    });
                });
        })
        .flatMap(responseData -> Mono.fromCallable(() -> {
            // Decrypt response (CPU-bound)
            EncryptData data = responseData.encryptData;

            if (verbose) {
                System.out.println("\n  📥 Received encrypted response (status: 200)");
                System.out.println("     Response headers:");
                System.out.println("       X-Kid: " + responseData.respKid);
                System.out.println("       X-Idempotency-Key: " + responseData.respRequestId.substring(0, Math.min(30, responseData.respRequestId.length())) + "...");
            }

            // Parse response request ID to get timestamp and nonce for AAD reconstruction
            String[] respParts = responseData.respRequestId.split("\\.");
            if (respParts.length != 2) {
                throw new RuntimeException("Invalid X-Idempotency-Key format in response");
            }
            String respTimestamp = respParts[0];
            String respNonce = respParts[1];

            // Reconstruct AAD from response headers
            byte[] respAad = (respTimestamp + "|" + respNonce + "|" + responseData.respKid + "|" + session.clientId)
                .getBytes(StandardCharsets.UTF_8);

            byte[] respEncryptedBody = responseData.responseBody;

            if (verbose) {
                System.out.println("     Encrypted body length: " + respEncryptedBody.length + " bytes");
                System.out.println("\n  🔓 Decrypting response...");
            }

            // OPTIMIZATION: Decrypt with reused Cipher instance (synchronized for thread safety)
            byte[] respPlaintext = measureSync("aes-gcm-decrypt", data.cryptoOps, () -> {
                // Extract IV (first 12 bytes) and ciphertext+tag (rest)
                byte[] respIv = new byte[12];
                System.arraycopy(respEncryptedBody, 0, respIv, 0, 12);
                byte[] respCiphertextWithTag = new byte[respEncryptedBody.length - 12];
                System.arraycopy(respEncryptedBody, 12, respCiphertextWithTag, 0, respCiphertextWithTag.length);

                synchronized (session.decryptCipher) {
                    GCMParameterSpec decGcmSpec = new GCMParameterSpec(128, respIv);
                    session.decryptCipher.init(Cipher.DECRYPT_MODE, session.keySpec, decGcmSpec);
                    session.decryptCipher.updateAAD(respAad);
                    return session.decryptCipher.doFinal(respCiphertextWithTag);
                }
            });

            if (verbose) {
                JsonNode responseJson = mapper.readTree(respPlaintext);
                System.out.println("  ✅ Decryption successful!\n");
                System.out.println("  📋 Decrypted response:");
                System.out.println("  ─────────────────────────────────────────");
                System.out.println(mapper.writerWithDefaultPrettyPrinter().writeValueAsString(responseJson));
                System.out.println("  ─────────────────────────────────────────");
            }

            return new EndpointMetrics(
                "/transaction/purchase",
                (System.nanoTime() - data.totalStart) / 1_000_000.0,
                responseData.httpMs,
                data.cryptoOps,
                responseData.serverTiming
            );
        }).subscribeOn(Schedulers.parallel()));  // Run crypto on parallel scheduler
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
    static Mono<Void> runBenchmarkReactive(int iterations) {
        return Mono.fromCallable(() -> {
            int warmup = 5;
            List<Double> initDurations = new ArrayList<>();
            List<Double> purchaseDurations = new ArrayList<>();
            List<Double> combinedDurations = new ArrayList<>();

            System.out.println("\n================================================================================");
            System.out.printf("  Throughput Benchmark (%d iterations, %d warmup)%n", iterations, warmup);
            System.out.println("================================================================================\n");

            for (int i = 0; i < iterations + warmup; i++) {
                long flowStart = System.nanoTime();

                // Execute reactive chain and block for result
                InitResult initResult = initSessionReactive(false).block();

                // SECURITY: Use try-with-resources to ensure session key is wiped
                try (SessionContext session = initResult.session()) {
                    EndpointMetrics purchaseMetrics = makePurchaseReactive(
                        session,
                        new PurchaseRequest("AEF", 5000),
                        false
                    ).block();

                    double flowDuration = (System.nanoTime() - flowStart) / 1_000_000.0;

                    if (i >= warmup) {
                        initDurations.add(initResult.metrics().totalRoundTripMs);
                        purchaseDurations.add(purchaseMetrics.totalRoundTripMs);
                        combinedDurations.add(flowDuration);
                    }
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

            return null;
        }).subscribeOn(Schedulers.boundedElastic()).then();
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
}
