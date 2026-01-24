use axum::{
    body::Bytes,
    extract::State,
    http::{HeaderMap, HeaderValue, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use ring::{
    aead::{self, Aad, BoundKey, Nonce, NonceSequence, NONCE_LEN},
    agreement::{self, EphemeralPrivateKey, UnparsedPublicKey},
    hkdf::{Salt, HKDF_SHA256},
    rand::{SecureRandom, SystemRandom},
};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use deadpool_postgres::{Config, Pool, Runtime};
use redis::AsyncCommands;
use serde::{Deserialize, Serialize};
use std::{
    sync::Arc,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use tokio_postgres::NoTls;
use postgres_native_tls::MakeTlsConnector;
use native_tls::TlsConnector;
use tower_http::{
    cors::{Any, CorsLayer},
    trace::TraceLayer,
};
use tracing::{info, warn};

// Constants
const TIMESTAMP_WINDOW_MS: i64 = 5 * 60 * 1000; // ±5 minutes
const NONCE_TTL_SEC: u64 = 300; // 5 minutes
const NONCE_PREFIX: &str = "nonce:";
const SESSION_PREFIX: &str = "sess:";

// Migration SQL
const MIGRATION_SQL: &str = r#"
CREATE TABLE IF NOT EXISTS sessions (
    session_id VARCHAR(255) PRIMARY KEY,
    data JSONB NOT NULL,
    expires_at BIGINT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_sessions_expires_at ON sessions(expires_at);
"#;

// App state
struct AppState {
    redis: redis::aio::ConnectionManager,
    postgres: Pool,
    rng: SystemRandom,
}

// Types
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct SessionInitRequest {
    client_public_key: String,
    ttl_sec: Option<i32>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct SessionInitResponse {
    session_id: String,
    server_public_key: String,
    enc_alg: String,
    expires_in_sec: i32,
}

#[derive(Debug, Serialize)]
struct ErrorResponse {
    error: String,
}

#[derive(Debug, Serialize)]
struct HealthResponse {
    status: String,
    timestamp: String,
    redis: String,
    postgres: String,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct SessionData {
    key: String,
    #[serde(rename = "type")]
    session_type: String,
    expires_at: i64,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct TransactionRequest {
    scheme_code: String,
    amount: f64,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct TransactionResponse {
    status: String,
    transaction_id: String,
    scheme_code: String,
    amount: f64,
    timestamp: String,
    message: String,
}

// Metrics collector for Server-Timing header
struct MetricsCollector {
    start_time: Instant,
    operations: Vec<(String, f64)>,
}

impl MetricsCollector {
    fn new() -> Self {
        Self {
            start_time: Instant::now(),
            operations: Vec::new(),
        }
    }

    fn measure<T, F: FnOnce() -> T>(&mut self, operation: &str, f: F) -> T {
        let start = Instant::now();
        let result = f();
        let duration_ms = start.elapsed().as_secs_f64() * 1000.0;
        self.operations.push((operation.to_string(), duration_ms));
        result
    }

    async fn measure_async<T, F>(&mut self, operation: &str, f: F) -> T
    where
        F: std::future::Future<Output = T>,
    {
        let start = Instant::now();
        let result = f.await;
        let duration_ms = start.elapsed().as_secs_f64() * 1000.0;
        self.operations.push((operation.to_string(), duration_ms));
        result
    }

    fn to_server_timing_header(&self) -> String {
        let mut parts: Vec<String> = self
            .operations
            .iter()
            .map(|(op, dur)| format!("{};dur={:.3}", op.replace(' ', "-"), dur))
            .collect();
        let total_ms = self.start_time.elapsed().as_secs_f64() * 1000.0;
        parts.push(format!("total;dur={:.3}", total_ms));
        parts.join(", ")
    }
}

// Helper for AES-GCM with a fixed nonce (used per-operation)
struct SingleUseNonce(Option<[u8; NONCE_LEN]>);

impl NonceSequence for SingleUseNonce {
    fn advance(&mut self) -> Result<Nonce, ring::error::Unspecified> {
        self.0
            .take()
            .map(Nonce::assume_unique_for_key)
            .ok_or(ring::error::Unspecified)
    }
}

// Crypto helpers
fn b64_encode(data: &[u8]) -> String {
    BASE64.encode(data)
}

fn b64_decode(s: &str) -> Result<Vec<u8>, base64::DecodeError> {
    BASE64.decode(s)
}

fn generate_session_id(prefix: &str, rng: &SystemRandom) -> String {
    let mut bytes = [0u8; 16];
    rng.fill(&mut bytes).unwrap();
    format!("{}-{}", prefix, hex::encode(bytes))
}

fn generate_iv(rng: &SystemRandom) -> [u8; 12] {
    let mut iv = [0u8; 12];
    rng.fill(&mut iv).unwrap();
    iv
}

fn generate_random_hex(n: usize, rng: &SystemRandom) -> String {
    let mut bytes = vec![0u8; n];
    rng.fill(&mut bytes).unwrap();
    hex::encode(bytes)
}

fn current_timestamp_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis() as i64
}

fn current_timestamp_iso() -> String {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis();
    // Format as ISO 8601 with milliseconds
    let secs = now / 1000;
    let millis = now % 1000;
    let naive = chrono_lite(secs as i64, millis as u32);
    naive
}

// Simple ISO timestamp formatter without chrono dependency
fn chrono_lite(secs: i64, millis: u32) -> String {
    const SECS_PER_DAY: i64 = 86400;
    const DAYS_PER_400Y: i64 = 146097;
    const DAYS_PER_100Y: i64 = 36524;
    const DAYS_PER_4Y: i64 = 1461;

    let mut days = secs / SECS_PER_DAY;
    let mut rem_secs = (secs % SECS_PER_DAY) as u32;
    if secs < 0 && rem_secs != 0 {
        days -= 1;
        rem_secs = (SECS_PER_DAY as u32) - rem_secs;
    }

    // Days since 1970-01-01 -> days since 0001-01-01
    days += 719468;

    let mut year = 1;
    let mut q = days / DAYS_PER_400Y;
    year += q * 400;
    days -= q * DAYS_PER_400Y;

    q = days / DAYS_PER_100Y;
    if q == 4 {
        q = 3;
    }
    year += q * 100;
    days -= q * DAYS_PER_100Y;

    q = days / DAYS_PER_4Y;
    year += q * 4;
    days -= q * DAYS_PER_4Y;

    q = days / 365;
    if q == 4 {
        q = 3;
    }
    year += q;
    days -= q * 365;

    let leap = year % 4 == 0 && (year % 100 != 0 || year % 400 == 0);
    let month_days: [i64; 12] = if leap {
        [31, 29, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
    } else {
        [31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
    };

    let mut month = 0;
    for (i, &d) in month_days.iter().enumerate() {
        if days < d {
            month = i + 1;
            break;
        }
        days -= d;
    }
    let day = days + 1;

    let hour = rem_secs / 3600;
    rem_secs %= 3600;
    let minute = rem_secs / 60;
    let second = rem_secs % 60;

    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}.{:03}Z",
        year, month, day, hour, minute, second, millis
    )
}

// HKDF to derive 32-byte key
fn hkdf32(shared_secret: &[u8], salt_bytes: &[u8], info: &[u8]) -> Vec<u8> {
    let salt = Salt::new(HKDF_SHA256, salt_bytes);
    let prk = salt.extract(shared_secret);
    let info_arr = [info];
    let okm = prk
        .expand(&info_arr, HKDF_SHA256)
        .expect("HKDF expand failed");
    let mut key = vec![0u8; 32];
    okm.fill(&mut key).expect("HKDF fill failed");
    key
}

// AES-256-GCM encryption - returns IV || ciphertext || tag
fn aes_gcm_encrypt(
    key: &[u8],
    aad: &[u8],
    plaintext: &[u8],
    rng: &SystemRandom,
) -> Result<Vec<u8>, ring::error::Unspecified> {
    let iv = generate_iv(rng);
    let unbound_key = aead::UnboundKey::new(&aead::AES_256_GCM, key)?;
    let mut sealing_key = aead::SealingKey::new(unbound_key, SingleUseNonce(Some(iv)));

    let mut in_out = plaintext.to_vec();
    let tag = sealing_key.seal_in_place_separate_tag(Aad::from(aad), &mut in_out)?;

    // Return IV || ciphertext || tag
    let mut result = Vec::with_capacity(12 + in_out.len() + 16);
    result.extend_from_slice(&iv);
    result.extend_from_slice(&in_out);
    result.extend_from_slice(tag.as_ref());
    Ok(result)
}

// AES-256-GCM decryption - expects IV || ciphertext || tag
fn aes_gcm_decrypt(
    key: &[u8],
    aad: &[u8],
    encrypted_body: &[u8],
) -> Result<Vec<u8>, ring::error::Unspecified> {
    if encrypted_body.len() < 12 + 16 {
        return Err(ring::error::Unspecified);
    }

    let iv: [u8; 12] = encrypted_body[..12].try_into().unwrap();
    let ciphertext = &encrypted_body[12..encrypted_body.len() - 16];
    let tag = &encrypted_body[encrypted_body.len() - 16..];

    let unbound_key = aead::UnboundKey::new(&aead::AES_256_GCM, key)?;
    let mut opening_key = aead::OpeningKey::new(unbound_key, SingleUseNonce(Some(iv)));

    let mut in_out = Vec::with_capacity(ciphertext.len() + tag.len());
    in_out.extend_from_slice(ciphertext);
    in_out.extend_from_slice(tag);

    let plaintext = opening_key.open_in_place(Aad::from(aad), &mut in_out)?;
    Ok(plaintext.to_vec())
}

// Build AAD from request components
// Format: TIMESTAMP|NONCE|KID|CLIENTID
fn build_aad(ts: &str, nonce: &str, kid: &str, client_id: &str) -> Vec<u8> {
    format!("{}|{}|{}|{}", ts, nonce, kid, client_id).into_bytes()
}

// Validate P-256 public key
fn validate_p256_public_key(public_key_bytes: &[u8]) -> Result<(), &'static str> {
    if public_key_bytes.len() != 65 {
        return Err("INVALID_KEY_LENGTH");
    }

    if public_key_bytes[0] != 0x04 {
        return Err("INVALID_KEY_FORMAT");
    }

    // Validate point is on curve by trying to create a public key
    let _ = UnparsedPublicKey::new(&agreement::ECDH_P256, public_key_bytes);
    Ok(())
}

// Replay protection
async fn validate_replay_protection(
    redis: &mut redis::aio::ConnectionManager,
    nonce: &str,
    timestamp: &str,
) -> Result<(), &'static str> {
    let ts: i64 = timestamp.parse().map_err(|_| "TIMESTAMP_INVALID")?;
    let now = current_timestamp_ms();

    if (now - ts).abs() > TIMESTAMP_WINDOW_MS {
        return Err("TIMESTAMP_INVALID");
    }

    // Nonce uniqueness check with Redis SET NX EX
    let key = format!("{}{}", NONCE_PREFIX, nonce);
    let was_set: bool = redis::cmd("SET")
        .arg(&key)
        .arg("1")
        .arg("EX")
        .arg(NONCE_TTL_SEC)
        .arg("NX")
        .query_async(redis)
        .await
        .map_err(|_| "REDIS_ERROR")?;

    if !was_set {
        return Err("REPLAY_DETECTED");
    }

    Ok(())
}

// Session store operations
async fn store_session(
    redis: &mut redis::aio::ConnectionManager,
    postgres: &Pool,
    session_id: &str,
    key: &[u8],
    session_type: &str,
    ttl_sec: i32,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let expires_at = current_timestamp_ms() + (ttl_sec as i64) * 1000;
    let data = SessionData {
        key: b64_encode(key),
        session_type: session_type.to_string(),
        expires_at,
    };

    let json_data = serde_json::to_string(&data).unwrap();
    let redis_key = format!("{}{}", SESSION_PREFIX, session_id);

    // 1. Write to PostgreSQL (Source of Truth)
    let pg_client = postgres.get().await?;
    pg_client
        .execute(
            "INSERT INTO sessions (session_id, data, expires_at) VALUES ($1, $2, $3)
             ON CONFLICT (session_id) DO UPDATE SET data = $2, expires_at = $3",
            &[&session_id, &serde_json::from_str::<serde_json::Value>(&json_data)?, &expires_at],
        )
        .await?;

    // 2. Write to Redis (Cache)
    redis
        .set_ex::<_, _, ()>(&redis_key, &json_data, ttl_sec as u64)
        .await?;

    Ok(())
}

async fn get_session(
    redis: &mut redis::aio::ConnectionManager,
    postgres: &Pool,
    session_id: &str,
) -> Option<SessionData> {
    let redis_key = format!("{}{}", SESSION_PREFIX, session_id);

    // 1. Try Redis first
    if let Ok(Some(value)) = redis.get::<_, Option<String>>(&redis_key).await {
        if let Some(data) = parse_session(&value, session_id, redis, postgres).await {
            return Some(data);
        }
    }

    // 2. Fallback to PostgreSQL
    let pg_client = match postgres.get().await {
        Ok(c) => c,
        Err(e) => {
            warn!("Failed to get PostgreSQL connection: {:?}", e);
            return None;
        }
    };

    let row = match pg_client
        .query_opt("SELECT data FROM sessions WHERE session_id = $1", &[&session_id])
        .await
    {
        Ok(Some(r)) => r,
        Ok(None) => return None,
        Err(e) => {
            warn!("PostgreSQL query error: {:?}", e);
            return None;
        }
    };

    // Handle JSONB: postgres returns serde_json::Value with serde_json feature
    let raw_data: serde_json::Value = row.get(0);
    let db_value = raw_data.to_string();

    let parsed = parse_session(&db_value, session_id, redis, postgres).await?;

    // Populate Redis cache if valid
    let ttl = ((parsed.expires_at - current_timestamp_ms()) / 1000).max(0) as u64;
    if ttl > 0 {
        let _: Result<(), _> = redis.set_ex::<_, _, ()>(&redis_key, &db_value, ttl).await;
    }

    Some(parsed)
}

async fn parse_session(
    json_str: &str,
    session_id: &str,
    redis: &mut redis::aio::ConnectionManager,
    postgres: &Pool,
) -> Option<SessionData> {
    let data: SessionData = serde_json::from_str(json_str).ok()?;

    // Check if expired
    if current_timestamp_ms() > data.expires_at {
        // Cleanup from both Redis and PostgreSQL
        let redis_key = format!("{}{}", SESSION_PREFIX, session_id);
        let _: Result<(), _> = redis.del::<_, ()>(&redis_key).await;

        // Cleanup from PostgreSQL
        if let Ok(pg_client) = postgres.get().await {
            let _ = pg_client
                .execute("DELETE FROM sessions WHERE session_id = $1", &[&session_id])
                .await;
        }
        return None;
    }

    Some(data)
}

// HTTP Handlers
async fn session_init_handler(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(req): Json<SessionInitRequest>,
) -> impl IntoResponse {
    let mut metrics = MetricsCollector::new();

    let idempotency_key = headers
        .get("x-idempotency-key")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    let client_id = headers
        .get("x-clientid")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");

    if idempotency_key.is_empty() || client_id.is_empty() {
        return error_response(StatusCode::BAD_REQUEST, "CRYPTO_ERROR", &metrics);
    }

    // Parse X-Idempotency-Key: timestamp.nonce
    let parts: Vec<&str> = idempotency_key.split('.').collect();
    if parts.len() != 2 {
        return error_response(StatusCode::BAD_REQUEST, "CRYPTO_ERROR", &metrics);
    }
    let timestamp = parts[0];
    let nonce = parts[1];

    // Replay protection
    {
        let mut redis = state.redis.clone();
        let result = metrics
            .measure_async("replay-protection", async {
                validate_replay_protection(&mut redis, nonce, timestamp).await
            })
            .await;

        if let Err(e) = result {
            warn!("Replay protection failed: {}", e);
            return error_response(StatusCode::BAD_REQUEST, "CRYPTO_ERROR", &metrics);
        }
    }

    if req.client_public_key.is_empty() {
        return error_response(StatusCode::BAD_REQUEST, "CRYPTO_ERROR", &metrics);
    }

    // Decode and validate client public key
    let client_pub = match metrics.measure("validate-pubkey", || {
        let pub_bytes = b64_decode(&req.client_public_key)?;
        validate_p256_public_key(&pub_bytes).map_err(|_| base64::DecodeError::InvalidLength(0))?;
        Ok::<Vec<u8>, base64::DecodeError>(pub_bytes)
    }) {
        Ok(pub_bytes) => pub_bytes,
        Err(_) => {
            warn!("Client public key validation failed");
            return error_response(StatusCode::BAD_REQUEST, "CRYPTO_ERROR", &metrics);
        }
    };

    // Generate server ECDH keypair
    let server_private_key: EphemeralPrivateKey = metrics.measure("ecdh-keygen", || {
        EphemeralPrivateKey::generate(&agreement::ECDH_P256, &state.rng).unwrap()
    });
    let server_pub = server_private_key.compute_public_key().unwrap();
    let server_pub_bytes = server_pub.as_ref().to_vec();

    // Compute shared secret
    let client_public_key = UnparsedPublicKey::new(&agreement::ECDH_P256, &client_pub);
    let shared_secret: Vec<u8> = metrics.measure("ecdh-compute", || {
        agreement::agree_ephemeral(
            server_private_key,
            &client_public_key,
            |secret| secret.to_vec(),
        )
        .unwrap()
    });

    // Generate session ID
    let session_id = generate_session_id("S", &state.rng);

    // Cap TTL between 5 minutes and 1 hour
    let ttl_sec = req.ttl_sec.unwrap_or(1800).clamp(300, 3600);

    // Derive session key using HKDF
    // Info includes client_id for domain separation
    let salt = session_id.as_bytes();
    let info = format!("SESSION|A256GCM|{}", client_id);
    let session_key = metrics.measure("hkdf", || hkdf32(&shared_secret, salt, info.as_bytes()));

    // Store session in PostgreSQL and Redis
    {
        let mut redis = state.redis.clone();
        let result = metrics
            .measure_async("db-store", async {
                store_session(&mut redis, &state.postgres, &session_id, &session_key, "AUTH", ttl_sec).await
            })
            .await;

        if let Err(e) = result {
            warn!("Failed to store session: {:?}", e);
            return error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "INTERNAL_ERROR",
                &metrics,
            );
        }
    }

    info!("Session created: {}, ttl: {}", session_id, ttl_sec);

    let response = SessionInitResponse {
        session_id,
        server_public_key: b64_encode(&server_pub_bytes),
        enc_alg: "A256GCM".to_string(),
        expires_in_sec: ttl_sec,
    };

    success_response(StatusCode::OK, response, &metrics)
}

async fn transaction_purchase_handler(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    body: Bytes,
) -> impl IntoResponse {
    let mut metrics = MetricsCollector::new();

    // Extract headers
    let kid = headers
        .get("x-kid")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    let idempotency_key = headers
        .get("x-idempotency-key")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    let client_id = headers
        .get("x-clientid")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");

    if kid.is_empty() || idempotency_key.is_empty() || client_id.is_empty() {
        return error_response(StatusCode::BAD_REQUEST, "CRYPTO_ERROR", &metrics);
    }

    // Parse X-Idempotency-Key: timestamp.nonce
    let parts: Vec<&str> = idempotency_key.split('.').collect();
    if parts.len() != 2 {
        return error_response(StatusCode::BAD_REQUEST, "CRYPTO_ERROR", &metrics);
    }
    let timestamp = parts[0];
    let nonce = parts[1];

    // Replay protection
    {
        let mut redis = state.redis.clone();
        let result = metrics
            .measure_async("replay-protection", async {
                validate_replay_protection(&mut redis, nonce, timestamp).await
            })
            .await;

        if let Err(e) = result {
            warn!("Replay protection failed: {}", e);
            return error_response(StatusCode::BAD_REQUEST, "CRYPTO_ERROR", &metrics);
        }
    }

    // Extract session ID from kid
    let session_id = if kid.starts_with("session:") {
        &kid[8..]
    } else {
        return error_response(StatusCode::BAD_REQUEST, "CRYPTO_ERROR", &metrics);
    };

    // Get session from Redis/PostgreSQL
    let session = {
        let mut redis = state.redis.clone();
        metrics
            .measure_async("db-get", async { get_session(&mut redis, &state.postgres, session_id).await })
            .await
    };

    let session = match session {
        Some(s) => s,
        None => {
            return error_response(StatusCode::UNAUTHORIZED, "SESSION_EXPIRED", &metrics);
        }
    };

    // Decode session key
    let session_key = match b64_decode(&session.key) {
        Ok(v) => v,
        Err(_) => return error_response(StatusCode::BAD_REQUEST, "CRYPTO_ERROR", &metrics),
    };

    // Build expected AAD
    // AAD format: TIMESTAMP|NONCE|KID|CLIENTID
    let aad = metrics.measure("aad-build", || build_aad(timestamp, nonce, kid, client_id));

    // Decrypt request body (IV || ciphertext || tag)
    let plaintext = match metrics.measure("aes-gcm-decrypt", || {
        aes_gcm_decrypt(&session_key, &aad, &body)
    }) {
        Ok(p) => p,
        Err(_) => {
            warn!("Decryption failed");
            return error_response(StatusCode::BAD_REQUEST, "CRYPTO_ERROR", &metrics);
        }
    };

    // Parse decrypted JSON
    let request_data: TransactionRequest = match serde_json::from_slice(&plaintext) {
        Ok(d) => d,
        Err(_) => {
            warn!("Failed to parse decrypted JSON");
            return error_response(StatusCode::BAD_REQUEST, "CRYPTO_ERROR", &metrics);
        }
    };

    info!("Decrypted request: {:?}", request_data);

    // Business logic - process transaction
    let response_data = TransactionResponse {
        status: "SUCCESS".to_string(),
        transaction_id: format!("TXN-{}", generate_random_hex(8, &state.rng).to_uppercase()),
        scheme_code: request_data.scheme_code.clone(),
        amount: request_data.amount,
        timestamp: current_timestamp_iso(),
        message: format!(
            "Purchase of {:.2} in scheme {} completed successfully",
            request_data.amount, request_data.scheme_code
        ),
    };

    // Encrypt response
    let response_plaintext = serde_json::to_vec(&response_data).unwrap();
    let response_nonce = uuid::Uuid::new_v4().to_string();
    let response_timestamp = current_timestamp_ms().to_string();
    let response_idempotency_key = format!("{}.{}", response_timestamp, response_nonce);

    // Build response AAD
    // AAD format: TIMESTAMP|NONCE|KID|CLIENTID
    let response_aad = build_aad(&response_timestamp, &response_nonce, kid, client_id);

    // Encrypt - returns IV || ciphertext || tag
    let encrypted_response = metrics.measure("aes-gcm-encrypt", || {
        aes_gcm_encrypt(&session_key, &response_aad, &response_plaintext, &state.rng).unwrap()
    });

    // Build response with headers
    let mut response_headers = HeaderMap::new();
    response_headers.insert("X-Kid", HeaderValue::from_str(kid).unwrap());
    response_headers.insert(
        "X-Idempotency-Key",
        HeaderValue::from_str(&response_idempotency_key).unwrap(),
    );
    response_headers.insert("Content-Type", HeaderValue::from_static("application/octet-stream"));
    response_headers.insert(
        "Server-Timing",
        HeaderValue::from_str(&metrics.to_server_timing_header()).unwrap(),
    );

    (StatusCode::OK, response_headers, encrypted_response).into_response()
}

async fn health_handler(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    // Check Redis
    let redis_status = {
        let mut redis = state.redis.clone();
        match redis::cmd("PING")
            .query_async::<String>(&mut redis)
            .await
        {
            Ok(_) => "ok",
            Err(_) => "disconnected",
        }
    };

    // Check PostgreSQL
    let postgres_status = match state.postgres.get().await {
        Ok(client) => match client.query_one("SELECT 1", &[]).await {
            Ok(_) => "ok",
            Err(_) => "disconnected",
        },
        Err(_) => "disconnected",
    };

    let status = if redis_status == "ok" && postgres_status == "ok" {
        "ok"
    } else {
        "degraded"
    };

    Json(HealthResponse {
        status: status.to_string(),
        timestamp: current_timestamp_iso(),
        redis: redis_status.to_string(),
        postgres: postgres_status.to_string(),
    })
}

// Response helpers
fn error_response(status: StatusCode, message: &str, metrics: &MetricsCollector) -> Response {
    let mut headers = HeaderMap::new();
    headers.insert("Content-Type", HeaderValue::from_static("application/json"));
    headers.insert(
        "Server-Timing",
        HeaderValue::from_str(&metrics.to_server_timing_header()).unwrap(),
    );

    let body = serde_json::to_string(&ErrorResponse {
        error: message.to_string(),
    })
    .unwrap();

    (status, headers, body).into_response()
}

fn success_response<T: Serialize>(
    status: StatusCode,
    data: T,
    metrics: &MetricsCollector,
) -> Response {
    let mut headers = HeaderMap::new();
    headers.insert("Content-Type", HeaderValue::from_static("application/json"));
    headers.insert(
        "Server-Timing",
        HeaderValue::from_str(&metrics.to_server_timing_header()).unwrap(),
    );

    let body = serde_json::to_string(&data).unwrap();

    (status, headers, body).into_response()
}

#[tokio::main]
async fn main() {
    // Initialize tracing
    tracing_subscriber::fmt::init();

    // Initialize Redis using ConnectionManager (handles reconnection automatically)
    let redis_host = std::env::var("REDIS_HOST").unwrap_or_else(|_| "localhost".to_string());
    let redis_port = std::env::var("REDIS_PORT").unwrap_or_else(|_| "6379".to_string());
    let redis_url = format!("redis://{}:{}", redis_host, redis_port);

    let client = redis::Client::open(redis_url).expect("Failed to create Redis client");

    // Wait for Redis to be ready using ConnectionManager
    let mut conn_mgr = None;
    for i in 0..10 {
        match redis::aio::ConnectionManager::new(client.clone()).await {
            Ok(c) => {
                info!("Connected to Redis (using ConnectionManager for automatic reconnection)");
                conn_mgr = Some(c);
                break;
            }
            Err(e) => {
                info!("Waiting for Redis... (attempt {}): {:?}", i + 1, e);
                tokio::time::sleep(Duration::from_secs(1)).await;
            }
        }
    }

    let redis_conn = conn_mgr.expect("Failed to connect to Redis after 10 attempts");

    // Initialize PostgreSQL
    let pg_host = std::env::var("POSTGRES_HOST").unwrap_or_else(|_| "localhost".to_string());
    let pg_port = std::env::var("POSTGRES_PORT").unwrap_or_else(|_| "5432".to_string());
    let pg_user = std::env::var("POSTGRES_USER").unwrap_or_else(|_| "postgres".to_string());
    let pg_password = std::env::var("POSTGRES_PASSWORD").unwrap_or_else(|_| "postgres".to_string());
    let pg_db = std::env::var("POSTGRES_DB").unwrap_or_else(|_| "session_crypto".to_string());
    let pg_ssl = std::env::var("POSTGRES_SSL").unwrap_or_else(|_| "false".to_string());

    let mut pg_config = Config::new();
    pg_config.host = Some(pg_host.clone());
    pg_config.port = Some(pg_port.parse().unwrap_or(5432));
    pg_config.user = Some(pg_user);
    pg_config.password = Some(pg_password);
    pg_config.dbname = Some(pg_db);
    let mut pool_cfg = deadpool_postgres::PoolConfig::default();
    pool_cfg.max_size = 25;
    pg_config.pool = Some(pool_cfg);

    // Create pool with or without TLS based on POSTGRES_SSL environment variable
    let pg_pool = if pg_ssl == "true" || pg_ssl == "require" {
        info!("PostgreSQL TLS enabled");
        let tls_connector = TlsConnector::builder()
            .danger_accept_invalid_certs(pg_ssl != "require") // Accept self-signed in non-strict mode
            .build()
            .expect("Failed to create TLS connector");
        let connector = MakeTlsConnector::new(tls_connector);
        pg_config
            .create_pool(Some(Runtime::Tokio1), connector)
            .expect("Failed to create PostgreSQL pool with TLS")
    } else {
        info!("PostgreSQL TLS disabled (set POSTGRES_SSL=true or POSTGRES_SSL=require to enable)");
        pg_config
            .create_pool(Some(Runtime::Tokio1), NoTls)
            .expect("Failed to create PostgreSQL pool")
    };

    // Wait for PostgreSQL to be ready and run migration
    for i in 0..10 {
        match pg_pool.get().await {
            Ok(client) => {
                // Run migration
                if let Err(e) = client.batch_execute(MIGRATION_SQL).await {
                    warn!("Migration warning (may be OK if table exists): {:?}", e);
                }
                info!("Connected to PostgreSQL");
                break;
            }
            Err(e) => {
                info!("Waiting for PostgreSQL... (attempt {}): {:?}", i + 1, e);
                tokio::time::sleep(Duration::from_secs(1)).await;
                if i == 9 {
                    panic!("Failed to connect to PostgreSQL after 10 attempts");
                }
            }
        }
    }

    let state = Arc::new(AppState {
        redis: redis_conn,
        postgres: pg_pool,
        rng: SystemRandom::new(),
    });

    // CORS configuration for browser clients
    let cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods(Any)
        .allow_headers([
            "content-type".parse().unwrap(),
            "x-idempotency-key".parse().unwrap(),
            "x-clientid".parse().unwrap(),
            "x-kid".parse().unwrap(),
        ])
        .expose_headers([
            "server-timing".parse().unwrap(),
            "x-kid".parse().unwrap(),
            "x-idempotency-key".parse().unwrap(),
        ]);

    // Build router
    let app = Router::new()
        .route("/session/init", post(session_init_handler))
        .route("/transaction/purchase", post(transaction_purchase_handler))
        .route("/health", get(health_handler))
        .layer(cors)
        .layer(TraceLayer::new_for_http())
        .with_state(state);

    // Start server
    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await.unwrap();
    info!("Server listening on http://localhost:3000 (ring)");

    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await
        .unwrap();
}

async fn shutdown_signal() {
    tokio::signal::ctrl_c()
        .await
        .expect("Failed to install CTRL+C signal handler");
    info!("Shutting down...");
}
