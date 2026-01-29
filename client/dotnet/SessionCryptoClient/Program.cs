using System.Buffers;
using System.Diagnostics;
using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;

// ===== Environment Config =====
var SessionUrl = Environment.GetEnvironmentVariable("SESSION_URL") ?? "http://localhost:3001";
var ServerUrl = Environment.GetEnvironmentVariable("SERVER_URL") ?? "http://localhost:3000";
var BenchmarkConcurrency = int.TryParse(Environment.GetEnvironmentVariable("BENCHMARK_CONCURRENCY"), out var bc) ? bc : 1;
const string ClientId = "DOTNET_CLIENT_OPT";

// Optimized HttpClient with SocketsHttpHandler for better connection pooling
using var socketsHandler = new SocketsHttpHandler
{
    PooledConnectionLifetime = TimeSpan.FromMinutes(2),
    PooledConnectionIdleTimeout = TimeSpan.FromMinutes(1),
    MaxConnectionsPerServer = 100,
    EnableMultipleHttp2Connections = true
};
using var httpClient = new HttpClient(socketsHandler);

// Pre-warm crypto providers on startup
Console.WriteLine("🔥 Pre-warming crypto providers...");
PrewarmCrypto();

// Parse command line arguments
var cliArgs = Environment.GetCommandLineArgs();
var benchmarkIdx = Array.IndexOf(cliArgs, "--benchmark");
var isBenchmark = benchmarkIdx != -1;
var benchmarkIterations = isBenchmark && cliArgs.Length > benchmarkIdx + 1
    ? int.Parse(cliArgs[benchmarkIdx + 1])
    : 100;

Console.WriteLine("═══════════════════════════════════════════════════════════════");
Console.WriteLine("  Session Crypto PoC - .NET 10 Client (OPTIMIZED)");
Console.WriteLine("═══════════════════════════════════════════════════════════════");
Console.WriteLine($"  Session Server:  {SessionUrl}");
Console.WriteLine($"  API Server:      {ServerUrl}");
Console.WriteLine($"  Optimizations:   AesGcm Reuse, ArrayPool, Span<T>, SocketsHttpHandler");

if (isBenchmark)
{
    Console.WriteLine($"  Mode:            Benchmark ({benchmarkIterations} iterations)");
    Console.WriteLine($"  Concurrency:     {BenchmarkConcurrency} parallel workers");
    Console.WriteLine($"  HTTP Keep-Alive: Enabled (max {socketsHandler.MaxConnectionsPerServer} connections)");
}
else
{
    Console.WriteLine("  Mode:            Single run with metrics");
}

try
{
    if (isBenchmark)
    {
        await RunBenchmark(benchmarkIterations);
    }
    else
    {
        // Step 1: Initialize session
        var (session, initMetrics) = await InitSession(verbose: true);

        try
        {
            // Step 2: Make encrypted purchase
            var purchaseMetrics = await MakePurchase(session, new PurchaseRequest("AEF", 5000), verbose: true);

            // Print metrics summary
            PrintMetricsSummary(initMetrics, purchaseMetrics);
        }
        finally
        {
            // SECURITY: Ensure session keys are always zeroed, even on exception
            session.Dispose();
        }
    }

    Console.WriteLine("═══════════════════════════════════════════════════════════════");
    Console.WriteLine("  ✅ Completed successfully!");
    Console.WriteLine("═══════════════════════════════════════════════════════════════\n");
}
catch (Exception ex)
{
    Console.WriteLine($"\n❌ Error: {ex.Message}");
    Environment.Exit(1);
}
// HttpClient and SocketsHttpHandler are automatically disposed here via using declarations

// Pre-warm crypto providers to avoid JIT overhead
void PrewarmCrypto()
{
    using var ecdh = ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256);
    var pubKey = ecdh.PublicKey.ExportSubjectPublicKeyInfo();
    var sharedSecret = new byte[32];
    RandomNumberGenerator.Fill(sharedSecret);
    var sessionKey = HKDF.DeriveKey(HashAlgorithmName.SHA256, sharedSecret, 32,
        Encoding.UTF8.GetBytes("warmup-salt"), Encoding.UTF8.GetBytes("warmup-info"));

    using var aesGcm = new AesGcm(sessionKey, 16);
    var iv = new byte[12];
    var plaintext = new byte[100];
    var ciphertext = new byte[100];
    var tag = new byte[16];
    RandomNumberGenerator.Fill(iv);
    RandomNumberGenerator.Fill(plaintext);
    aesGcm.Encrypt(iv, plaintext, ciphertext, tag);
    aesGcm.Decrypt(iv, ciphertext, tag, plaintext);

    Console.WriteLine("✓ Crypto providers warmed up\n");
}

// ===== Benchmark Mode =====
async Task RunBenchmark(int iterations)
{
    const int warmup = 5;
    var concurrency = BenchmarkConcurrency;

    Console.WriteLine($"\n================================================================================");
    Console.WriteLine($"  Throughput Benchmark ({iterations} iterations, {warmup} warmup, concurrency: {concurrency})");
    Console.WriteLine($"================================================================================\n");

    // Thread-safe collection of results
    var totalIterations = iterations + warmup;
    var requestsPerWorker = (int)Math.Ceiling((double)totalIterations / concurrency);

    long completedCount = 0;
    var resultLock = new object();
    var initDurations = new List<double>();
    var purchaseDurations = new List<double>();
    var combinedDurations = new List<double>();
    Exception? firstError = null;

    var startTime = Stopwatch.StartNew();

    // Create concurrent workers
    var workers = new List<Task>();
    for (int w = 0; w < concurrency; w++)
    {
        var workerStart = w * requestsPerWorker;
        var workerEnd = Math.Min(workerStart + requestsPerWorker, totalIterations);
        if (workerStart >= totalIterations) break;

        workers.Add(Task.Run(async () =>
        {
            for (int i = workerStart; i < workerEnd; i++)
            {
                // Check if another worker errored
                lock (resultLock)
                {
                    if (firstError != null) return;
                }

                var flowSw = Stopwatch.StartNew();

                OptimizedSessionContext? session = null;
                try
                {
                    var (sess, initMetrics) = await InitSession(verbose: false);
                    session = sess;

                    var purchaseMetrics = await MakePurchase(session, new PurchaseRequest("AEF", 5000), verbose: false);

                    flowSw.Stop();

                    // Skip warmup iterations
                    if (i >= warmup)
                    {
                        lock (resultLock)
                        {
                            initDurations.Add(initMetrics.TotalRoundTripMs);
                            purchaseDurations.Add(purchaseMetrics.TotalRoundTripMs);
                            combinedDurations.Add(flowSw.Elapsed.TotalMilliseconds);
                        }
                    }
                }
                catch (Exception ex)
                {
                    lock (resultLock)
                    {
                        firstError ??= ex;
                    }
                    return;
                }
                finally
                {
                    // SECURITY: Ensure session keys are always zeroed
                    session?.Dispose();
                }

                // Progress update
                var completed = Interlocked.Increment(ref completedCount);
                if (completed % 100 == 0 || completed == totalIterations)
                {
                    var progress = Math.Max(0, completed - warmup);
                    var elapsed = startTime.Elapsed.TotalSeconds;
                    var currentRps = elapsed > 0 ? completed / elapsed : 0;
                    Console.Write($"\r  Progress: {progress}/{iterations} | Current RPS: {currentRps:F0} | Concurrency: {concurrency}          ");
                }
            }
        }));
    }

    // Wait for all workers to complete
    await Task.WhenAll(workers);

    startTime.Stop();
    var totalTime = startTime.Elapsed.TotalSeconds;
    // ⬆️ Timer stops here - all printing below does NOT affect measurements

    if (firstError != null)
        throw new Exception($"Benchmark failed: {firstError.Message}", firstError);

    Console.WriteLine("\n");

    // Display test summary
    Console.WriteLine("================================================================================");
    Console.WriteLine($"  Test Duration: {totalTime:F2}s ({totalTime / 60:F2} minutes)");
    Console.WriteLine("================================================================================\n");

    // Calculate and display statistics
    PrintBenchmarkStats("/session/init", CalculateStats(initDurations), iterations, concurrency, totalTime);
    PrintBenchmarkStats("/transaction/purchase", CalculateStats(purchaseDurations), iterations, concurrency, totalTime);
    PrintBenchmarkStats("Combined (init + purchase)", CalculateStats(combinedDurations), iterations, concurrency, totalTime);
}

BenchmarkStats CalculateStats(List<double> durations)
{
    var sorted = durations.OrderBy(x => x).ToList();
    var sum = sorted.Sum();
    var count = sorted.Count;

    return new BenchmarkStats(
        count,
        sum,
        sorted.First(),
        sorted.Last(),
        sum / count,
        sorted[count / 2],
        sorted[(int)(count * 0.95)],
        sorted[(int)(count * 0.99)]
    );
}

void PrintBenchmarkStats(string name, BenchmarkStats stats, int iterations, int concurrency, double totalTime)
{
    Console.WriteLine($"{name}:");

    // Calculate actual throughput based on concurrency and total time
    var actualThroughput = iterations / totalTime;
    var theoreticalMaxThroughput = (1000.0 / stats.MeanMs) * concurrency;
    var efficiency = (actualThroughput / theoreticalMaxThroughput) * 100.0;

    Console.WriteLine($"  Throughput:    {actualThroughput:F1} req/s (actual) | {theoreticalMaxThroughput:F1} req/s (theoretical max)");
    Console.WriteLine($"    Calculation: {iterations} iterations / {totalTime:F2}s = {actualThroughput:F1} req/s (actual)");
    Console.WriteLine($"                 (1000ms / {stats.MeanMs:F1}ms) × {concurrency} workers = {theoreticalMaxThroughput:F1} req/s (theoretical)");
    Console.WriteLine($"    Efficiency:  {efficiency:F1}% (actual/theoretical)");
    Console.WriteLine($"  Latency:       Min: {stats.MinMs:F1}ms | Max: {stats.MaxMs:F1}ms | Mean: {stats.MeanMs:F1}ms");
    Console.WriteLine($"                 P50: {stats.P50Ms:F1}ms | P95: {stats.P95Ms:F1}ms | P99: {stats.P99Ms:F1}ms\n");
}

void PrintMetricsSummary(EndpointMetrics init, EndpointMetrics purchase)
{
    Console.WriteLine("\n================================================================================");
    Console.WriteLine("  Performance Metrics Summary");
    Console.WriteLine("================================================================================\n");

    foreach (var metrics in new[] { init, purchase })
    {
        Console.WriteLine($"Endpoint: {metrics.Endpoint}");
        Console.WriteLine("----------------------------------------");
        Console.WriteLine($"  Total Round-Trip:     {metrics.TotalRoundTripMs:F3} ms");
        Console.WriteLine($"  HTTP Request Time:    {metrics.HttpRequestMs:F3} ms\n");

        if (metrics.CryptoOperations.Any())
        {
            Console.WriteLine("  Client Crypto Operations:");
            foreach (var op in metrics.CryptoOperations)
            {
                Console.WriteLine($"    - {op.Operation,-18} {op.DurationMs:F3} ms");
            }
        }

        if (!string.IsNullOrEmpty(metrics.ServerTiming))
        {
            Console.WriteLine("\n  Server Timing:");
            var serverOps = ParseServerTiming(metrics.ServerTiming);
            foreach (var op in serverOps)
            {
                Console.WriteLine($"    - {op.Operation,-18} {op.DurationMs:F3} ms");
            }
        }
        Console.WriteLine();
    }
}

List<CryptoTiming> ParseServerTiming(string header)
{
    return header.Split(',')
        .Select(part =>
        {
            var parts = part.Trim().Split(';');
            var name = parts[0].Trim();
            var dur = parts.Length > 1 && parts[1].StartsWith("dur=")
                ? double.Parse(parts[1][4..])
                : 0;
            return new CryptoTiming(name, dur);
        })
        .ToList();
}

// ===== Session Initialization =====
async Task<(OptimizedSessionContext Session, EndpointMetrics Metrics)> InitSession(bool verbose)
{
    var totalSw = Stopwatch.StartNew();
    var cryptoOps = new List<CryptoTiming>();

    if (verbose)
        Console.WriteLine("\n📡 Step 1: Initializing session with server...\n");

    // Generate client ECDH keypair (P-256)
    ECDiffieHellman clientEcdh = null!;
    byte[] clientPubRaw = null!;
    MeasureSync("ecdh-keygen", cryptoOps, () =>
    {
        clientEcdh = ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256);
        var clientPubBytes = clientEcdh.PublicKey.ExportSubjectPublicKeyInfo();
        clientPubRaw = ExtractRawPublicKey(clientPubBytes);
    });

    if (verbose)
    {
        Console.WriteLine("  ✅ Generated client ECDH keypair");
        Console.WriteLine($"     Public key (first 32 chars): {Convert.ToBase64String(clientPubRaw)[..32]}...");
    }

    // Prepare request
    var nonce = Guid.NewGuid().ToString();
    var timestamp = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds().ToString();
    var requestId = $"{timestamp}.{nonce}";

    var requestBody = new SessionInitRequest(Convert.ToBase64String(clientPubRaw), 1800);

    if (verbose)
    {
        Console.WriteLine("\n  📤 Sending POST /session/init");
        Console.WriteLine($"     X-Idempotency-Key: {requestId}");
        Console.WriteLine($"     X-ClientId: {ClientId}");
    }

    // Time HTTP request
    var request = new HttpRequestMessage(HttpMethod.Post, $"{SessionUrl}/v1/session/init")
    {
        Content = new StringContent(JsonSerializer.Serialize(requestBody), Encoding.UTF8, "application/json")
    };
    request.Headers.Add("X-Idempotency-Key", requestId);
    request.Headers.Add("X-ClientId", ClientId);

    var httpSw = Stopwatch.StartNew();
    using var response = await httpClient.SendAsync(request);
    httpSw.Stop();
    var httpMs = httpSw.Elapsed.TotalMilliseconds;

    if (!response.IsSuccessStatusCode)
    {
        var error = await response.Content.ReadAsStringAsync();
        throw new Exception($"Session init failed: {response.StatusCode} - {error}");
    }

    // Get Server-Timing header
    string? serverTiming = response.Headers.TryGetValues("Server-Timing", out var values)
        ? values.First()
        : null;

    var data = JsonSerializer.Deserialize<SessionInitResponse>(await response.Content.ReadAsStringAsync())!;

    if (verbose)
    {
        Console.WriteLine("\n  📥 Received response:");
        Console.WriteLine($"     Session ID: {data.SessionId}");
        Console.WriteLine($"     Encryption: {data.EncAlg}");
        Console.WriteLine($"     Expires in: {data.ExpiresInSec} seconds");
        Console.WriteLine($"     Server public key (first 32 chars): {data.ServerPublicKey[..32]}...");
    }

    // Decode server public key and import
    var serverPubRaw = Convert.FromBase64String(data.ServerPublicKey);
    using var serverEcdh = ImportRawPublicKey(serverPubRaw);

    // Compute shared secret
    byte[] sharedSecret = null!;
    MeasureSync("ecdh-compute", cryptoOps, () =>
    {
        sharedSecret = clientEcdh.DeriveRawSecretAgreement(serverEcdh.PublicKey);
    });

    if (verbose)
        Console.WriteLine("\n  🔐 Computed ECDH shared secret");

    // Derive session key using HKDF
    var salt = Encoding.UTF8.GetBytes(data.SessionId);
    var info = Encoding.UTF8.GetBytes($"SESSION|A256GCM|{ClientId}");
    byte[] sessionKey = null!;
    MeasureSync("hkdf", cryptoOps, () =>
    {
        sessionKey = HKDF.DeriveKey(HashAlgorithmName.SHA256, sharedSecret, 32, salt, info);
    });

    if (verbose)
    {
        Console.WriteLine("  🔑 Derived session key using HKDF-SHA256");
        Console.WriteLine($"     Session key (first 16 chars): {Convert.ToBase64String(sessionKey)[..16]}...");
    }

    totalSw.Stop();

    clientEcdh.Dispose();

    var metrics = new EndpointMetrics(
        "/session/init",
        totalSw.Elapsed.TotalMilliseconds,
        httpMs,
        cryptoOps,
        serverTiming
    );

    // OPTIMIZATION: Create AesGcm instance once and reuse for all transactions
    var aesGcm = new AesGcm(sessionKey, 16);

    return (new OptimizedSessionContext(data.SessionId, sessionKey, $"session:{data.SessionId}", ClientId, aesGcm), metrics);
}

// ===== Make Purchase =====
async Task<EndpointMetrics> MakePurchase(OptimizedSessionContext session, PurchaseRequest purchaseData, bool verbose)
{
    var totalSw = Stopwatch.StartNew();
    var cryptoOps = new List<CryptoTiming>();

    if (verbose)
        Console.WriteLine("\n📡 Step 2: Making encrypted purchase request...\n");

    var plaintext = Encoding.UTF8.GetBytes(JsonSerializer.Serialize(purchaseData));

    if (verbose)
    {
        Console.WriteLine("  📝 Request payload:");
        Console.WriteLine($"     {JsonSerializer.Serialize(purchaseData)}");
    }

    // Generate nonce and timestamp for replay protection
    var nonce = Guid.NewGuid().ToString();
    var timestamp = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds().ToString();
    var requestId = $"{timestamp}.{nonce}";

    // OPTIMIZATION: Build AAD efficiently
    var aadBytes = BuildAadBytes(timestamp, nonce, session.Kid, session.ClientId);

    if (verbose)
    {
        Console.WriteLine("\n  🔒 Encrypting request...");
        Console.WriteLine($"     AAD: {timestamp}|{nonce[..8]}...|session:{session.SessionId[..8]}...|{session.ClientId}");
    }

    // OPTIMIZATION: Use ArrayPool for buffers
    var iv = ArrayPool<byte>.Shared.Rent(12);
    var ciphertext = ArrayPool<byte>.Shared.Rent(plaintext.Length);
    var tag = ArrayPool<byte>.Shared.Rent(16);

    try
    {
        RandomNumberGenerator.Fill(iv.AsSpan(0, 12));

        byte[] encryptedBody = null!;
        MeasureSync("aes-gcm-encrypt", cryptoOps, () =>
        {
            // OPTIMIZATION: Reuse AesGcm instance from session
            session.AesGcm.Encrypt(iv.AsSpan(0, 12), plaintext, ciphertext.AsSpan(0, plaintext.Length),
                tag.AsSpan(0, 16), aadBytes);

            // Concatenate: IV (12) || ciphertext || tag (16)
            encryptedBody = new byte[12 + plaintext.Length + 16];
            iv.AsSpan(0, 12).CopyTo(encryptedBody);
            ciphertext.AsSpan(0, plaintext.Length).CopyTo(encryptedBody.AsSpan(12));
            tag.AsSpan(0, 16).CopyTo(encryptedBody.AsSpan(12 + plaintext.Length));
        });

        if (verbose)
        {
            Console.WriteLine($"     Encrypted body length: {encryptedBody.Length} bytes (IV + ciphertext + tag)");
            Console.WriteLine("\n  📤 Sending encrypted POST /transaction/purchase");
        }

        // Time HTTP request
        var request = new HttpRequestMessage(HttpMethod.Post, $"{ServerUrl}/transaction/purchase")
        {
            Content = new ByteArrayContent(encryptedBody)
        };
        request.Content.Headers.ContentType = new System.Net.Http.Headers.MediaTypeHeaderValue("application/octet-stream");
        request.Headers.Add("X-Kid", session.Kid);
        request.Headers.Add("X-Idempotency-Key", requestId);
        request.Headers.Add("X-ClientId", session.ClientId);

        var httpSw = Stopwatch.StartNew();
        using var response = await httpClient.SendAsync(request);
        httpSw.Stop();
        var httpMs = httpSw.Elapsed.TotalMilliseconds;

        if (!response.IsSuccessStatusCode)
        {
            var error = await response.Content.ReadAsStringAsync();
            throw new Exception($"Purchase failed: {response.StatusCode} - {error}");
        }

        // Get Server-Timing header
        string? serverTiming = response.Headers.TryGetValues("Server-Timing", out var values)
            ? values.First()
            : null;

        // Extract response headers
        var respKid = response.Headers.GetValues("X-Kid").First();
        var respRequestId = response.Headers.GetValues("X-Idempotency-Key").First();

        if (verbose)
        {
            Console.WriteLine($"\n  📥 Received encrypted response (status: {(int)response.StatusCode})");
            Console.WriteLine("     Response headers:");
            Console.WriteLine($"       X-Kid: {respKid}");
            Console.WriteLine($"       X-Idempotency-Key: {respRequestId[..Math.Min(30, respRequestId.Length)]}...");
        }

        // Parse response request ID
        var respParts = respRequestId.Split('.');
        if (respParts.Length != 2)
            throw new Exception("Invalid X-Idempotency-Key format in response");
        var respTimestamp = respParts[0];
        var respNonce = respParts[1];

        // OPTIMIZATION: Build response AAD efficiently
        var respAadBytes = BuildAadBytes(respTimestamp, respNonce, respKid, session.ClientId);

        // Get encrypted body
        var respEncryptedBody = await response.Content.ReadAsByteArrayAsync();

        if (verbose)
        {
            Console.WriteLine($"     Encrypted body length: {respEncryptedBody.Length} bytes");
            Console.WriteLine("\n  🔓 Decrypting response...");
        }

        // Extract IV, ciphertext, and tag
        var respIv = respEncryptedBody[..12];
        var respTag = respEncryptedBody[^16..];
        var respCiphertext = respEncryptedBody[12..^16];

        var respPlaintext = new byte[respCiphertext.Length];
        MeasureSync("aes-gcm-decrypt", cryptoOps, () =>
        {
            // OPTIMIZATION: Reuse AesGcm instance from session
            session.AesGcm.Decrypt(respIv, respCiphertext, respTag, respPlaintext, respAadBytes);
        });

        var responseData = JsonSerializer.Deserialize<JsonElement>(respPlaintext);

        if (verbose)
        {
            Console.WriteLine("  ✅ Decryption successful!\n");
            Console.WriteLine("  📋 Decrypted response:");
            Console.WriteLine("  ─────────────────────────────────────────");
            Console.WriteLine(JsonSerializer.Serialize(responseData, new JsonSerializerOptions { WriteIndented = true }));
            Console.WriteLine("  ─────────────────────────────────────────");
        }

        totalSw.Stop();

        return new EndpointMetrics(
            "/transaction/purchase",
            totalSw.Elapsed.TotalMilliseconds,
            httpMs,
            cryptoOps,
            serverTiming
        );
    }
    finally
    {
        // SECURITY: Clear entire rented buffers before returning to pool
        // Using clearArray: true ensures entire buffer is zeroed, not just used portion
        ArrayPool<byte>.Shared.Return(iv, clearArray: true);
        ArrayPool<byte>.Shared.Return(ciphertext, clearArray: true);
        ArrayPool<byte>.Shared.Return(tag, clearArray: true);
    }
}

// OPTIMIZATION: Build AAD efficiently with minimal allocations
byte[] BuildAadBytes(string timestamp, string nonce, string kid, string clientId)
{
    // Pre-calculate size to avoid resizing
    var size = Encoding.UTF8.GetByteCount(timestamp) + 1 +
               Encoding.UTF8.GetByteCount(nonce) + 1 +
               Encoding.UTF8.GetByteCount(kid) + 1 +
               Encoding.UTF8.GetByteCount(clientId);

    var buffer = new byte[size];
    int offset = 0;

    offset += Encoding.UTF8.GetBytes(timestamp, buffer.AsSpan(offset));
    buffer[offset++] = (byte)'|';
    offset += Encoding.UTF8.GetBytes(nonce, buffer.AsSpan(offset));
    buffer[offset++] = (byte)'|';
    offset += Encoding.UTF8.GetBytes(kid, buffer.AsSpan(offset));
    buffer[offset++] = (byte)'|';
    Encoding.UTF8.GetBytes(clientId, buffer.AsSpan(offset));

    return buffer;
}

// ===== Timing Helper =====
void MeasureSync(string operation, List<CryptoTiming> timings, Action fn)
{
    var sw = Stopwatch.StartNew();
    fn();
    sw.Stop();
    timings.Add(new CryptoTiming(operation, sw.Elapsed.TotalMilliseconds));
}

// Helper to extract raw 65-byte uncompressed public key from SPKI format
byte[] ExtractRawPublicKey(byte[] spki)
{
    return spki[^65..];
}

// Helper to import raw 65-byte public key
ECDiffieHellman ImportRawPublicKey(byte[] rawKey)
{
    var spkiHeader = Convert.FromHexString("3059301306072a8648ce3d020106082a8648ce3d030107034200");
    var spki = new byte[spkiHeader.Length + rawKey.Length];
    spkiHeader.CopyTo(spki, 0);
    rawKey.CopyTo(spki, spkiHeader.Length);

    var ecdh = ECDiffieHellman.Create();
    ecdh.ImportSubjectPublicKeyInfo(spki, out _);
    return ecdh;
}

// ===== Records =====
record CryptoTiming(string Operation, double DurationMs);

record EndpointMetrics(
    string Endpoint,
    double TotalRoundTripMs,
    double HttpRequestMs,
    List<CryptoTiming> CryptoOperations,
    string? ServerTiming);

record BenchmarkStats(
    int Count,
    double TotalMs,
    double MinMs,
    double MaxMs,
    double MeanMs,
    double P50Ms,
    double P95Ms,
    double P99Ms);

record SessionInitRequest(
    [property: JsonPropertyName("clientPublicKey")] string ClientPublicKey,
    [property: JsonPropertyName("ttlSec")] int TtlSec);

record SessionInitResponse(
    [property: JsonPropertyName("sessionId")] string SessionId,
    [property: JsonPropertyName("serverPublicKey")] string ServerPublicKey,
    [property: JsonPropertyName("encAlg")] string EncAlg,
    [property: JsonPropertyName("expiresInSec")] int ExpiresInSec);

// OPTIMIZATION: Session context now includes reusable AesGcm instance
class OptimizedSessionContext : IDisposable
{
    public string SessionId { get; }
    public byte[] SessionKey { get; }
    public string Kid { get; }
    public string ClientId { get; }
    public AesGcm AesGcm { get; }

    public OptimizedSessionContext(string sessionId, byte[] sessionKey, string kid, string clientId, AesGcm aesGcm)
    {
        SessionId = sessionId;
        SessionKey = sessionKey;
        Kid = kid;
        ClientId = clientId;
        AesGcm = aesGcm;
    }

    public void Dispose()
    {
        // SECURITY: Clear sensitive data
        Array.Fill(SessionKey, (byte)0);
        AesGcm.Dispose();
    }
}

record PurchaseRequest(
    [property: JsonPropertyName("schemeCode")] string SchemeCode,
    [property: JsonPropertyName("amount")] int Amount);
