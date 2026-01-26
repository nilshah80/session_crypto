using System.Buffers;
using System.Collections.Concurrent;
using System.Diagnostics;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using Npgsql;
using StackExchange.Redis;

var builder = WebApplication.CreateBuilder(args);

// Add CORS
builder.Services.AddCors(options =>
{
    options.AddDefaultPolicy(policy =>
    {
        policy.AllowAnyOrigin()
              .AllowAnyMethod()
              .AllowAnyHeader()
              .WithExposedHeaders("Server-Timing", "X-Kid", "X-Idempotency-Key");
    });
});

// Configure Kestrel
builder.WebHost.ConfigureKestrel(options =>
{
    options.Limits.MaxRequestBodySize = 1 * 1024 * 1024; // 1MB max request body
    options.Limits.RequestHeadersTimeout = TimeSpan.FromSeconds(30);
    options.Limits.KeepAliveTimeout = TimeSpan.FromSeconds(120);
});

// Add logging
builder.Logging.ClearProviders();
builder.Logging.AddConsole();

var app = builder.Build();
var logger = app.Services.GetRequiredService<ILoggerFactory>().CreateLogger("SessionCryptoServer");

// Configuration
var redisHost = Environment.GetEnvironmentVariable("REDIS_HOST") ?? "127.0.0.1";
var redisPort = Environment.GetEnvironmentVariable("REDIS_PORT") ?? "6379";
var pgHost = Environment.GetEnvironmentVariable("POSTGRES_HOST") ?? "127.0.0.1";
var pgPort = Environment.GetEnvironmentVariable("POSTGRES_PORT") ?? "5432";
var pgUser = Environment.GetEnvironmentVariable("POSTGRES_USER") ?? "postgres";
var pgPass = Environment.GetEnvironmentVariable("POSTGRES_PASSWORD") ?? "postgres";
var pgDb = Environment.GetEnvironmentVariable("POSTGRES_DB") ?? "session_crypto";

// Initialize Redis with proper configuration
ConnectionMultiplexer? redis = null;
IDatabase? redisDb = null;

var redisConfig = new ConfigurationOptions
{
    EndPoints = { $"{redisHost}:{redisPort}" },
    ConnectTimeout = 5000,
    SyncTimeout = 3000,
    AsyncTimeout = 3000,
    AbortOnConnectFail = false,
    ConnectRetry = 3,
    KeepAlive = 60,
    ReconnectRetryPolicy = new ExponentialRetry(1000)
};

for (int i = 0; i < 10; i++)
{
    try
    {
        redis = await ConnectionMultiplexer.ConnectAsync(redisConfig);
        redisDb = redis.GetDatabase();
        logger.LogInformation("Connected to Redis");
        break;
    }
    catch (Exception ex)
    {
        logger.LogWarning("Waiting for Redis... (attempt {Attempt}/10): {Error}", i + 1, ex.Message);
        await Task.Delay(1000);
    }
}

if (redisDb == null)
{
    logger.LogWarning("Redis not connected - running without cache");
}

// Initialize PostgreSQL with connection pooling
var connStringBuilder = new NpgsqlConnectionStringBuilder
{
    Host = pgHost,
    Port = int.Parse(pgPort),
    Username = pgUser,
    Password = pgPass,
    Database = pgDb,
    // Connection pooling configuration (optimized for standard workloads)
    MinPoolSize = 5,
    MaxPoolSize = 20,
    ConnectionIdleLifetime = 300,
    ConnectionPruningInterval = 10,
    // Timeouts
    CommandTimeout = 30,
    Timeout = 15
};

var dataSourceBuilder = new NpgsqlDataSourceBuilder(connStringBuilder.ConnectionString);
NpgsqlDataSource? dataSource = null;

for (int i = 0; i < 10; i++)
{
    try
    {
        dataSource = dataSourceBuilder.Build();
        await using var cmd = dataSource.CreateCommand("SELECT 1");
        await cmd.ExecuteScalarAsync();
        logger.LogInformation("Connected to Postgres (pool: min={MinPool}, max={MaxPool})",
            connStringBuilder.MinPoolSize, connStringBuilder.MaxPoolSize);
        break;
    }
    catch (Exception ex)
    {
        logger.LogWarning("Waiting for Postgres... (attempt {Attempt}/10): {Error}", i + 1, ex.Message);
        await Task.Delay(1000);
    }
}

if (dataSource == null)
{
    throw new Exception("Failed to connect to Postgres");
}

// Ensure table exists
await using (var cmd = dataSource.CreateCommand(@"
    CREATE TABLE IF NOT EXISTS sessions (
        session_id VARCHAR(255) PRIMARY KEY,
        data JSONB NOT NULL,
        expires_at BIGINT NOT NULL
    );
    CREATE INDEX IF NOT EXISTS idx_sessions_expires_at ON sessions(expires_at);
"))
{
    await cmd.ExecuteNonQueryAsync();
}

// Constants
const int TimestampWindowMs = 5 * 60 * 1000;
const int NonceTtlSec = 300;
const string NoncePrefix = "nonce:";
const string SessionPrefix = "sess:";

// Graceful shutdown handling
app.Lifetime.ApplicationStopping.Register(() =>
{
    logger.LogInformation("Application stopping - closing connections");
    redis?.Close();
    dataSource?.Dispose();
});

app.UseCors();

// Health endpoint
app.MapGet("/health", async () =>
{
    var redisStatus = "ok";
    var postgresStatus = "ok";

    try
    {
        if (redisDb != null)
            await redisDb.PingAsync();
        else
            redisStatus = "disconnected";
    }
    catch { redisStatus = "disconnected"; }

    try
    {
        using var cmd = dataSource!.CreateCommand("SELECT 1");
        await cmd.ExecuteScalarAsync();
    }
    catch { postgresStatus = "disconnected"; }

    var status = (redisStatus == "ok" && postgresStatus == "ok") ? "ok" : "degraded";

    return Results.Json(new
    {
        status,
        timestamp = DateTime.UtcNow.ToString("o"),
        redis = redisStatus,
        postgres = postgresStatus
    });
});

// Session init endpoint
app.MapPost("/session/init", async (HttpContext context) =>
{
    var metrics = new MetricsCollector();

    try
    {
        var idempotencyKey = context.Request.Headers["X-Idempotency-Key"].FirstOrDefault();
        var clientId = context.Request.Headers["X-ClientId"].FirstOrDefault();

        if (string.IsNullOrEmpty(idempotencyKey) || string.IsNullOrEmpty(clientId))
        {
            return SendError(context, metrics, 400, "CRYPTO_ERROR");
        }

        var parts = idempotencyKey.Split('.');
        if (parts.Length != 2)
        {
            return SendError(context, metrics, 400, "CRYPTO_ERROR");
        }

        var timestamp = parts[0];
        var nonce = parts[1];

        // Replay protection
        var replayResult = await metrics.MeasureAsync("replay-protection", async () =>
        {
            return await ValidateReplayProtection(redisDb, nonce, timestamp);
        });

        if (!replayResult)
        {
            return SendError(context, metrics, 400, "CRYPTO_ERROR");
        }

        // Parse request body
        var requestBody = await JsonSerializer.DeserializeAsync<SessionInitRequest>(context.Request.Body);
        if (requestBody == null || string.IsNullOrEmpty(requestBody.ClientPublicKey))
        {
            return SendError(context, metrics, 400, "CRYPTO_ERROR");
        }

        // Decode and validate client public key
        byte[] clientPubBytes;
        try
        {
            clientPubBytes = metrics.Measure("validate-pubkey", () =>
            {
                var bytes = Convert.FromBase64String(requestBody.ClientPublicKey);
                if (bytes.Length != 65 || bytes[0] != 0x04)
                {
                    throw new Exception("Invalid key format");
                }
                return bytes;
            });
        }
        catch
        {
            return SendError(context, metrics, 400, "CRYPTO_ERROR");
        }

        // Generate server ECDH keypair
        using var serverEcdh = ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256);
        byte[] serverPubBytes = null!;

        metrics.Measure("ecdh-keygen", () =>
        {
            // Extract uncompressed point from SubjectPublicKeyInfo
            serverPubBytes = ExportUncompressedPublicKey(serverEcdh);
        });

        // Compute shared secret
        byte[] sharedSecret = null!;

        metrics.Measure("ecdh-compute", () =>
        {
            using var clientEcdh = ECDiffieHellman.Create();
            clientEcdh.ImportSubjectPublicKeyInfo(CreateSubjectPublicKeyInfo(clientPubBytes), out _);
            sharedSecret = serverEcdh.DeriveRawSecretAgreement(clientEcdh.PublicKey);
        });

        // Generate session ID
        var sessionId = $"S-{GenerateRandomHex(16)}";

        // TTL
        var ttlSec = requestBody.TtlSec ?? 1800;
        ttlSec = Math.Max(300, Math.Min(3600, ttlSec));

        // Derive session key using HKDF
        byte[] sessionKey = null!;
        var salt = Encoding.UTF8.GetBytes(sessionId);
        var info = Encoding.UTF8.GetBytes($"SESSION|A256GCM|{clientId}");

        metrics.Measure("hkdf", () =>
        {
            sessionKey = HKDF.DeriveKey(HashAlgorithmName.SHA256, sharedSecret, 32, salt, info);
        });

        // Store session
        var storeResult = await metrics.MeasureAsync("db-store", async () =>
        {
            return await StoreSession(dataSource!, redisDb, sessionId, sessionKey, "AUTH", ttlSec);
        });

        if (!storeResult)
        {
            return SendError(context, metrics, 500, "INTERNAL_ERROR");
        }

        logger.LogInformation("Session created: {SessionId}, ttl: {TtlSec}", sessionId, ttlSec);

        context.Response.Headers["Server-Timing"] = metrics.ToServerTimingHeader();
        return Results.Json(new SessionInitResponse
        {
            SessionId = sessionId,
            ServerPublicKey = Convert.ToBase64String(serverPubBytes),
            EncAlg = "A256GCM",
            ExpiresInSec = ttlSec
        });
    }
    catch (Exception ex)
    {
        logger.LogError(ex, "Error in session/init");
        return SendError(context, metrics, 500, "INTERNAL_ERROR");
    }
});

// Transaction purchase endpoint
app.MapPost("/transaction/purchase", async (HttpContext context) =>
{
    var metrics = new MetricsCollector();

    try
    {
        var kid = context.Request.Headers["X-Kid"].FirstOrDefault();
        var idempotencyKey = context.Request.Headers["X-Idempotency-Key"].FirstOrDefault();
        var clientId = context.Request.Headers["X-ClientId"].FirstOrDefault();

        if (string.IsNullOrEmpty(kid) || string.IsNullOrEmpty(idempotencyKey) || string.IsNullOrEmpty(clientId))
        {
            return SendError(context, metrics, 400, "CRYPTO_ERROR");
        }

        var parts = idempotencyKey.Split('.');
        if (parts.Length != 2)
        {
            return SendError(context, metrics, 400, "CRYPTO_ERROR");
        }

        var timestamp = parts[0];
        var nonce = parts[1];

        // Replay protection
        var replayResult = await metrics.MeasureAsync("replay-protection", async () =>
        {
            return await ValidateReplayProtection(redisDb, nonce, timestamp);
        });

        if (!replayResult)
        {
            return SendError(context, metrics, 400, "CRYPTO_ERROR");
        }

        // Extract session ID
        if (!kid.StartsWith("session:"))
        {
            return SendError(context, metrics, 400, "CRYPTO_ERROR");
        }
        var sessionId = kid[8..];

        // Get session
        SessionData? session = null;
        session = await metrics.MeasureAsync("db-get", async () =>
        {
            return await GetSession(dataSource!, redisDb, sessionId);
        });

        if (session == null)
        {
            return SendError(context, metrics, 401, "SESSION_EXPIRED");
        }

        // Build AAD
        byte[] aad = null!;
        metrics.Measure("aad-build", () =>
        {
            aad = Encoding.UTF8.GetBytes($"{timestamp}|{nonce}|{kid}|{clientId}");
        });

        // Read encrypted body using ArrayPool
        var buffer = ArrayPool<byte>.Shared.Rent(8192);
        var encryptedBody = Array.Empty<byte>();
        try
        {
            using var ms = new MemoryStream();
            int bytesRead;
            while ((bytesRead = await context.Request.Body.ReadAsync(buffer)) > 0)
            {
                ms.Write(buffer, 0, bytesRead);
            }
            encryptedBody = ms.ToArray();
        }
        finally
        {
            // SECURITY: Clear sensitive data before returning to pool
            buffer.AsSpan().Clear();
            ArrayPool<byte>.Shared.Return(buffer);
        }

        if (encryptedBody.Length < 28)
        {
            return SendError(context, metrics, 400, "CRYPTO_ERROR");
        }

        // Decrypt
        var sessionKey = Convert.FromBase64String(session.Key);
        byte[] plaintext = null!;

        try
        {
            metrics.Measure("aes-gcm-decrypt", () =>
            {
                plaintext = AesGcmDecrypt(sessionKey, aad, encryptedBody);
            });
        }
        catch (Exception ex)
        {
            logger.LogWarning("Decryption failed: {Error}", ex.Message);
            return SendError(context, metrics, 400, "CRYPTO_ERROR");
        }

        // Parse request
        var requestData = JsonSerializer.Deserialize<TransactionRequest>(plaintext);
        if (requestData == null)
        {
            return SendError(context, metrics, 400, "CRYPTO_ERROR");
        }

        logger.LogDebug("Decrypted request: SchemeCode={SchemeCode}, Amount={Amount}", requestData.SchemeCode, requestData.Amount);

        // Business logic
        var responseData = new TransactionResponse
        {
            Status = "SUCCESS",
            TransactionId = $"TXN-{GenerateRandomHex(8).ToUpper()}",
            SchemeCode = requestData.SchemeCode,
            Amount = requestData.Amount,
            Timestamp = DateTime.UtcNow.ToString("o"),
            Message = $"Purchase of {requestData.Amount} in scheme {requestData.SchemeCode} completed successfully"
        };

        // Encrypt response
        var responsePlaintext = JsonSerializer.SerializeToUtf8Bytes(responseData);
        var responseNonce = Guid.NewGuid().ToString();
        var responseTimestamp = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds().ToString();
        var responseIdempotencyKey = $"{responseTimestamp}.{responseNonce}";
        var responseAad = Encoding.UTF8.GetBytes($"{responseTimestamp}|{responseNonce}|{kid}|{clientId}");

        byte[] encryptedResponse = null!;
        metrics.Measure("aes-gcm-encrypt", () =>
        {
            encryptedResponse = AesGcmEncrypt(sessionKey, responseAad, responsePlaintext);
        });

        context.Response.Headers["X-Kid"] = kid;
        context.Response.Headers["X-Idempotency-Key"] = responseIdempotencyKey;
        context.Response.Headers["Server-Timing"] = metrics.ToServerTimingHeader();
        context.Response.ContentType = "application/octet-stream";

        return Results.Bytes(encryptedResponse);
    }
    catch (Exception ex)
    {
        logger.LogError(ex, "Error in transaction/purchase");
        return SendError(context, metrics, 500, "INTERNAL_ERROR");
    }
});

logger.LogInformation("Server listening on http://localhost:3000");
app.Run("http://0.0.0.0:3000");

// Helper methods
static IResult SendError(HttpContext context, MetricsCollector metrics, int statusCode, string error)
{
    context.Response.Headers["Server-Timing"] = metrics.ToServerTimingHeader();
    context.Response.StatusCode = statusCode;
    return Results.Json(new { error });
}

static string GenerateRandomHex(int byteCount)
{
    var bytes = RandomNumberGenerator.GetBytes(byteCount);
    return Convert.ToHexString(bytes).ToLower();
}

static byte[] ExportUncompressedPublicKey(ECDiffieHellman ecdh)
{
    var parameters = ecdh.ExportParameters(false);
    var result = new byte[65];
    result[0] = 0x04;
    Buffer.BlockCopy(parameters.Q.X!, 0, result, 1, 32);
    Buffer.BlockCopy(parameters.Q.Y!, 0, result, 33, 32);
    return result;
}

static byte[] CreateSubjectPublicKeyInfo(byte[] uncompressedPoint)
{
    // P-256 OID: 1.2.840.10045.3.1.7
    // EC public key OID: 1.2.840.10045.2.1
    var header = new byte[]
    {
        0x30, 0x59, // SEQUENCE, length 89
        0x30, 0x13, // SEQUENCE, length 19
        0x06, 0x07, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01, // OID ecPublicKey
        0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07, // OID prime256v1
        0x03, 0x42, 0x00 // BIT STRING, length 66, no unused bits
    };

    var result = new byte[header.Length + uncompressedPoint.Length];
    Buffer.BlockCopy(header, 0, result, 0, header.Length);
    Buffer.BlockCopy(uncompressedPoint, 0, result, header.Length, uncompressedPoint.Length);
    return result;
}

static byte[] AesGcmEncrypt(byte[] key, byte[] aad, byte[] plaintext)
{
    // Use ArrayPool for temporary buffers
    var iv = ArrayPool<byte>.Shared.Rent(12);
    var tag = ArrayPool<byte>.Shared.Rent(16);
    var ciphertext = ArrayPool<byte>.Shared.Rent(plaintext.Length);

    try
    {
        RandomNumberGenerator.Fill(iv.AsSpan(0, 12));

        // Create new AesGcm instance per request (AesGcm is NOT thread-safe)
        using var aes = new AesGcm(key, 16);
        aes.Encrypt(iv.AsSpan(0, 12), plaintext, ciphertext.AsSpan(0, plaintext.Length), tag.AsSpan(0, 16), aad);

        // Return IV || ciphertext || tag
        var result = new byte[12 + plaintext.Length + 16];
        Buffer.BlockCopy(iv, 0, result, 0, 12);
        Buffer.BlockCopy(ciphertext, 0, result, 12, plaintext.Length);
        Buffer.BlockCopy(tag, 0, result, 12 + plaintext.Length, 16);
        return result;
    }
    finally
    {
        // SECURITY: Clear entire rented buffers before returning to pool
        // Using clearArray: true ensures entire buffer is zeroed, not just used portion
        ArrayPool<byte>.Shared.Return(iv, clearArray: true);
        ArrayPool<byte>.Shared.Return(tag, clearArray: true);
        ArrayPool<byte>.Shared.Return(ciphertext, clearArray: true);
    }
}

static byte[] AesGcmDecrypt(byte[] key, byte[] aad, byte[] data)
{
    if (data.Length < 28)
        throw new ArgumentException("Invalid data length");

    var iv = data[..12];
    var ciphertext = data[12..^16];
    var tag = data[^16..];
    var plaintext = new byte[ciphertext.Length];

    // Create new AesGcm instance per request (AesGcm is NOT thread-safe)
    using var aes = new AesGcm(key, 16);
    aes.Decrypt(iv, ciphertext, tag, plaintext, aad);
    return plaintext;
}

static async Task<bool> ValidateReplayProtection(IDatabase? redisDb, string nonce, string timestamp)
{
    if (!long.TryParse(timestamp, out var ts))
        return false;

    var now = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
    if (Math.Abs(now - ts) > TimestampWindowMs)
        return false;

    if (redisDb == null)
        return true; // Skip nonce check if Redis not available

    var key = NoncePrefix + nonce;
    var wasSet = await redisDb.StringSetAsync(key, "1", TimeSpan.FromSeconds(NonceTtlSec), When.NotExists);
    return wasSet;
}

static async Task<bool> StoreSession(NpgsqlDataSource dataSource, IDatabase? redisDb, string sessionId, byte[] key, string type, int ttlSec)
{
    var expiresAt = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds() + (ttlSec * 1000L);
    var data = new SessionData
    {
        Key = Convert.ToBase64String(key),
        Type = type,
        ExpiresAt = expiresAt
    };
    var jsonData = JsonSerializer.Serialize(data);

    // Store in PostgreSQL
    await using var cmd = dataSource.CreateCommand(@"
        INSERT INTO sessions (session_id, data, expires_at)
        VALUES ($1, $2::jsonb, $3)
        ON CONFLICT (session_id) DO UPDATE
        SET data = EXCLUDED.data, expires_at = EXCLUDED.expires_at
    ");
    cmd.Parameters.AddWithValue(sessionId);
    cmd.Parameters.AddWithValue(jsonData);
    cmd.Parameters.AddWithValue(expiresAt);
    await cmd.ExecuteNonQueryAsync();

    // Store in Redis cache
    if (redisDb != null)
    {
        await redisDb.StringSetAsync(SessionPrefix + sessionId, jsonData, TimeSpan.FromSeconds(ttlSec));
    }

    return true;
}

static async Task<SessionData?> GetSession(NpgsqlDataSource dataSource, IDatabase? redisDb, string sessionId)
{
    // Try Redis first
    if (redisDb != null)
    {
        var value = await redisDb.StringGetAsync(SessionPrefix + sessionId);
        if (value.HasValue)
        {
            var data = JsonSerializer.Deserialize<SessionData>(value.ToString());
            if (data != null && DateTimeOffset.UtcNow.ToUnixTimeMilliseconds() <= data.ExpiresAt)
            {
                return data;
            }
        }
    }

    // Fallback to PostgreSQL
    await using var cmd = dataSource.CreateCommand("SELECT data FROM sessions WHERE session_id = $1");
    cmd.Parameters.AddWithValue(sessionId);
    var result = await cmd.ExecuteScalarAsync();
    if (result == null)
        return null;

    var sessionData = JsonSerializer.Deserialize<SessionData>(result.ToString()!);
    if (sessionData == null || DateTimeOffset.UtcNow.ToUnixTimeMilliseconds() > sessionData.ExpiresAt)
        return null;

    // Populate Redis cache
    if (redisDb != null)
    {
        var ttl = TimeSpan.FromMilliseconds(sessionData.ExpiresAt - DateTimeOffset.UtcNow.ToUnixTimeMilliseconds());
        if (ttl > TimeSpan.Zero)
        {
            await redisDb.StringSetAsync(SessionPrefix + sessionId, result.ToString(), ttl);
        }
    }

    return sessionData;
}

// Types
class SessionInitRequest
{
    [JsonPropertyName("clientPublicKey")]
    public string ClientPublicKey { get; set; } = "";

    [JsonPropertyName("ttlSec")]
    public int? TtlSec { get; set; }
}

class SessionInitResponse
{
    [JsonPropertyName("sessionId")]
    public string SessionId { get; set; } = "";

    [JsonPropertyName("serverPublicKey")]
    public string ServerPublicKey { get; set; } = "";

    [JsonPropertyName("encAlg")]
    public string EncAlg { get; set; } = "";

    [JsonPropertyName("expiresInSec")]
    public int ExpiresInSec { get; set; }
}

class SessionData
{
    [JsonPropertyName("key")]
    public string Key { get; set; } = "";

    [JsonPropertyName("type")]
    public string Type { get; set; } = "";

    [JsonPropertyName("expiresAt")]
    public long ExpiresAt { get; set; }
}

class TransactionRequest
{
    [JsonPropertyName("schemeCode")]
    public string SchemeCode { get; set; } = "";

    [JsonPropertyName("amount")]
    public decimal Amount { get; set; }
}

class TransactionResponse
{
    [JsonPropertyName("status")]
    public string Status { get; set; } = "";

    [JsonPropertyName("transactionId")]
    public string TransactionId { get; set; } = "";

    [JsonPropertyName("schemeCode")]
    public string SchemeCode { get; set; } = "";

    [JsonPropertyName("amount")]
    public decimal Amount { get; set; }

    [JsonPropertyName("timestamp")]
    public string Timestamp { get; set; } = "";

    [JsonPropertyName("message")]
    public string Message { get; set; } = "";
}

class MetricsCollector
{
    private readonly Stopwatch _stopwatch = Stopwatch.StartNew();
    private readonly List<(string Name, double DurationMs)> _operations = new();

    public void Measure(string name, Action action)
    {
        var sw = Stopwatch.StartNew();
        action();
        sw.Stop();
        _operations.Add((name, sw.Elapsed.TotalMilliseconds));
    }

    public T Measure<T>(string name, Func<T> func)
    {
        var sw = Stopwatch.StartNew();
        var result = func();
        sw.Stop();
        _operations.Add((name, sw.Elapsed.TotalMilliseconds));
        return result;
    }

    public async Task<T> MeasureAsync<T>(string name, Func<Task<T>> func)
    {
        var sw = Stopwatch.StartNew();
        var result = await func();
        sw.Stop();
        _operations.Add((name, sw.Elapsed.TotalMilliseconds));
        return result;
    }

    public string ToServerTimingHeader()
    {
        var parts = _operations.Select(op => $"{op.Name.Replace(" ", "-")};dur={op.DurationMs:F3}").ToList();
        parts.Add($"total;dur={_stopwatch.Elapsed.TotalMilliseconds:F3}");
        return string.Join(", ", parts);
    }
}
